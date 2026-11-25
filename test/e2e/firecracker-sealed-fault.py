# SPDX-License-Identifier: Apache-2.0
"""Test-only sealed_checkpoint_helper wrapper for the RPC recovery case."""
import errno
import os
from pathlib import Path
import runpy

runtime = runpy.run_path(os.environ["SEALED_REAL_HELPER"])
globals().update({key: value for key, value in runtime.items() if not key.startswith("__")})
real_merge = merge


def fail_one_merge(*args):
    marker = Path(os.environ["SEALED_FAIL_MERGE_MARKER"])
    if marker.exists():
        marker.unlink()
        raise OSError(errno.ENOSPC, "injected sealed XFS merge failure")
    return real_merge(*args)


finish.__globals__["merge"] = fail_one_merge
