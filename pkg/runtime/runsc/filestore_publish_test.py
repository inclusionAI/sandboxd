import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from filestore_publish import fingerprint, punch, publish

PAGE = 4096


class Generations(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.images = self.root / "images"
        self.images.mkdir()
        (self.images / "checkpoint.img").write_bytes(b"process-memory")
        self.want = bytearray(os.urandom(64 * PAGE))

    def capture(self, idx, previous=None):
        current = self.cache / f"frozen-{idx}"
        current.mkdir()
        target = current / "filestore-0"
        if previous:
            subprocess.run(
                ["cp", "--reflink=always", previous / "filestore-0", target], check=True
            )
            with target.open("r+b", buffering=0) as f:
                f.seek(PAGE)
                f.write(bytes([idx]) * PAGE)
                self.want[PAGE : 2 * PAGE] = bytes([idx]) * PAGE
                punch(f.fileno(), 3 * PAGE, PAGE)
                self.want[3 * PAGE : 4 * PAGE] = bytes(PAGE)
        else:
            target.write_bytes(self.want)
        entry = dict(
            file="filestore-0",
            size_bytes=len(self.want),
            fingerprint=fingerprint(target),
        )
        (current / "filestores.json").write_text(json.dumps({"filestores": [entry]}))
        remote = self.root / f"output-{idx}"
        remote.mkdir()
        receipt = publish(self.cache, current, self.images, remote)
        self.assertEqual((remote / "filestores/filestore-0").read_bytes(), self.want)
        self.assertEqual((remote / "checkpoint.img").read_bytes(), b"process-memory")
        return current, remote, receipt

    def test_adjacent_and_deleted_parent(self):
        a, parent, _ = self.capture(1)
        b, remote, receipt = self.capture(2, a)
        self.assertTrue(receipt["fromPrevious"])
        self.assertEqual(receipt["rwfsUploadBytes"], PAGE)
        self.assertEqual(
            (parent / "filestores/filestore-0").stat().st_size, len(self.want)
        )
        shutil.rmtree(remote)
        _, _, third = self.capture(3, b)
        self.assertFalse(third["fromPrevious"])
        self.assertGreater(third["rwfsUploadBytes"], PAGE)

    def test_lazy_origin_and_hole(self):
        origin = self.root / "base"
        origin.mkdir()
        base = origin / "filestore-0"
        base.write_bytes(self.want)
        (self.cache / "origin").write_text(str(origin))
        local = self.cache / "frozen-a"
        local.mkdir()
        backing = local / "filestore-0"
        with backing.open("wb") as f:
            f.truncate(len(self.want))
            f.seek(4 * PAGE)
            f.write(b"W" * PAGE)
        self.want[4 * PAGE : 5 * PAGE] = b"W" * PAGE
        self.want[5 * PAGE : 6 * PAGE] = bytes(PAGE)
        complete = self.root / "expected"
        complete.write_bytes(self.want)
        layer = dict(
            snapshot_id="capture-a",
            base_inode=base.stat().st_ino,
            base_size=len(self.want),
            base_fingerprint=fingerprint(base),
            local_ranges=[dict(offset=4 * PAGE, length=2 * PAGE)],
        )
        entry = dict(
            file="filestore-0",
            size_bytes=len(self.want),
            fingerprint=fingerprint(complete),
            delta={"frozen": layer},
        )
        (local / "filestores.json").write_text(json.dumps({"filestores": [entry]}))
        digest = hashlib.sha256(
            (self.images / "checkpoint.img").read_bytes()
        ).hexdigest()
        (local / "capture.json").write_text(
            json.dumps(
                {"snapshot_id": "capture-a", "images": {"checkpoint.img": digest}}
            )
        )
        target = self.root / "restorable"
        target.mkdir()
        result = publish(self.cache, local, self.images, target)
        self.assertEqual((target / "filestores/filestore-0").read_bytes(), self.want)
        self.assertEqual(result["rwfsUploadBytes"], PAGE)


if __name__ == "__main__":
    unittest.main()
