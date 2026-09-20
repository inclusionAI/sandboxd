"""Archive contract tests; no gVisor execution or network access required."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


MEMBERS = (
    "runsc",
    "containerd-shim-runsc-v1",
    "gvisor-bin/checkpointgofer",
    "gvisor-bin/gvisor_sentry",
    "gvisor-bin/gvisor-sentry-prewarmer",
    "gvisor-bin/runsc-metric-server",
)
INSTALLER = Path(__file__).with_name("install-gvisor.sh")


class InstallTest(unittest.TestCase):
    def check_archive(self, members=MEMBERS, extra=None, bad_hash=False, success=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "gvisor.tar.bz2"
            destination = root / "bin"
            with tarfile.open(archive, "w:bz2") as output:
                for name in members:
                    info = tarfile.TarInfo("./" + name)
                    data = b"test payload\n"
                    info.size = len(data)
                    output.addfile(info, io.BytesIO(data))
                if extra:
                    output.addfile(extra)
            digest = hashlib.sha512(archive.read_bytes()).hexdigest()
            result = subprocess.run(
                ["bash", str(INSTALLER), str(archive), "0" * 128 if bad_hash else digest,
                 str(destination)], capture_output=True, text=True,
            )
            self.assertEqual(result.returncode == 0, success, result.stderr)
            if success:
                for name in MEMBERS:
                    self.assertTrue(os.access(destination / name, os.X_OK))
                    self.assertEqual((destination / name).read_bytes(), b"test payload\n")
            else:
                self.assertFalse(destination.exists())

    def test_complete_bundle(self):
        self.check_archive(success=True)

    def test_bad_checksum(self):
        self.check_archive(bad_hash=True)

    def test_missing_sidecar(self):
        self.check_archive(members=MEMBERS[:-1])

    def test_duplicate(self):
        self.check_archive(members=MEMBERS + ("runsc",))

    def test_unexpected_file(self):
        self.check_archive(members=MEMBERS + ("extra",))

    def test_traversal(self):
        self.check_archive(members=MEMBERS + ("../escape",))

    def test_symlink(self):
        info = tarfile.TarInfo("./runsc")
        info.type = tarfile.SYMTYPE
        info.linkname = "/bin/sh"
        self.check_archive(members=MEMBERS[1:], extra=info)

    def test_hardlink(self):
        info = tarfile.TarInfo("./runsc")
        info.type = tarfile.LNKTYPE
        info.linkname = "./gvisor-bin/gvisor_sentry"
        self.check_archive(members=MEMBERS[1:], extra=info)

    def test_unexpected_directory(self):
        info = tarfile.TarInfo("../escape/")
        info.type = tarfile.DIRTYPE
        self.check_archive(extra=info)


class LocalBundleTest(unittest.TestCase):
    def stage(self, missing=None, same_directory=False, nonexecutable=None):
        helper = INSTALLER.parent.parent / "test/e2e/gvisor-bundle.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source with spaces"
            destination = source if same_directory else root / "output"
            for name in MEMBERS:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name != missing:
                    path.write_text(name)
                    path.chmod(0o644 if name == nonexecutable else 0o755)
            result = subprocess.run(
                ["bash", "-ec", '. "$1"; copy_gvisor_bundle "$2" "$3"',
                 "test", str(helper), str(source / "runsc"), str(destination)],
                capture_output=True, text=True,
            )
            failed = missing is not None or nonexecutable is not None
            self.assertEqual(result.returncode == 0, not failed, result.stderr)
            if failed:
                self.assertFalse(destination.exists())
            else:
                for name in MEMBERS:
                    self.assertEqual((destination / name).read_text(), name)
                    self.assertTrue(os.access(destination / name, os.X_OK))

    def test_complete_local_bundle(self):
        self.stage()

    def test_already_staged_bundle(self):
        self.stage(same_directory=True)

    def test_each_missing_member(self):
        for member in MEMBERS:
            with self.subTest(member=member):
                self.stage(missing=member)

    def test_nonexecutable_helper(self):
        self.stage(nonexecutable="gvisor-bin/checkpointgofer")


if __name__ == "__main__":
    unittest.main()
