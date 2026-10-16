#!/usr/bin/env python3
"""Regression coverage for the Redis suite-stage/DNAT readiness handshake."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

LIBRARY = Path(__file__).with_name("redis-stage.sh")
MOCK = """#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
r=Path(os.environ['TEST_STATE']);mode=os.environ['TEST_MODE'];args=sys.argv[1:]
with (r/'calls').open('a') as f:f.write(json.dumps(args)+'\\n')
if args[0]=='inspect':
 if '--format' in args:print('false' if mode=='stopped' else 'true')
elif args[0]=='exec':
 if mode=='broken':raise SystemExit(7)
 p=r/'count';n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
 print('ready' if mode=='delayed' and n>=3 else 'waiting')
else:raise SystemExit(8)
"""


class RedisStageTest(unittest.TestCase):
    def run_stage(self, mode, seconds):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(MOCK)
            docker.chmod(0o755)
            env = os.environ | {
                "DOCKER": str(docker),
                "CONTAINER": "suite",
                "REDIS_CONTAINER": "redis",
                "REDIS_READY_KEY": "suite:dnat:ready",
                "TEST_STATE": str(root),
                "TEST_MODE": mode,
                "E2E_REDIS_STAGE_TIMEOUT_SECONDS": str(seconds),
            }
            result = subprocess.run(
                [
                    "bash",
                    "-ec",
                    "source "
                    + shlex.quote(str(LIBRARY))
                    + "; wait_for_redis_soak_stage",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            calls = [
                json.loads(line) for line in (root / "calls").read_text().splitlines()
            ]
            return result, calls

    def test_delayed_stage_must_signal_before_readiness_starts(self):
        result, calls = self.run_stage("delayed", 5)
        self.assertEqual(result.returncode, 0, result.stderr)
        gets = [call for call in calls if call[0] == "exec"]
        self.assertEqual(len(gets), 3)
        self.assertTrue(all(call[-2:] == ["GET", "suite:dnat:ready"] for call in gets))

    def test_failed_suite_exits_before_waiting_for_redis(self):
        result, calls = self.run_stage("stopped", 5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == "exec" for call in calls))

    def test_missing_stage_is_bounded(self):
        result, _ = self.run_stage("waiting", 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not reach the Redis stage", result.stderr)

    def test_registry_command_failure_is_not_ready(self):
        result, _ = self.run_stage("broken", 5)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
