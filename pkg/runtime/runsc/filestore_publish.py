# FIEMAP planning and runsc capture verification adapted from akernel-dev/gvisor
# tools/filestore-poc, licensed under the Apache License, Version 2.0.
"""Compose a complete runsc checkpoint in an ADX-owned private capture directory."""

import bisect
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import uuid

PAGE = 4096


def fingerprint(path):
    result = hashlib.sha256()
    size = path.stat().st_size
    with path.open("rb", buffering=0) as source:
        result.update(source.read(PAGE))
        if size > PAGE:
            source.seek(size - PAGE)
            result.update(source.read(PAGE))
    return result.hexdigest()


def range_copy(source, dest, length, source_offset, dest_offset):
    while length:
        copied = os.copy_file_range(
            source, dest, min(length, 1 << 30), source_offset, dest_offset
        )
        if copied <= 0:
            raise RuntimeError(f"short copy_file_range at offset {source_offset}")
        length -= copied
        source_offset += copied
        dest_offset += copied


def punch(fd, offset, length):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fallocate.argtypes = (
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_longlong,
        ctypes.c_longlong,
    )
    if libc.fallocate(fd, 3, offset, length):  # PUNCH_HOLE | KEEP_SIZE
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def fsync_path(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_images(image, expected, destination=None):
    """Verify the bytes being published; reject missing and unexpected artifacts."""
    if {path.name for path in image.iterdir()} != set(expected):
        raise ValueError("process image file set differs from the capture")
    if destination is not None:
        destination.mkdir()
    total = 0
    for name, digest in expected.items():
        path = image / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid process image artifact {name}")
        hasher = hashlib.sha256()
        with contextlib.ExitStack() as stack:
            src = stack.enter_context(path.open("rb"))
            dst = (
                stack.enter_context((destination / name).open("xb"))
                if destination is not None
                else None
            )
            for block in iter(lambda: src.read(1 << 20), b""):
                hasher.update(block)
                total += len(block)
                if dst is not None:
                    dst.write(block)
            if hasher.hexdigest() != digest:
                raise ValueError(f"process image digest mismatch for {name}")
            if dst is not None:
                dst.flush()
                os.fsync(dst.fileno())
    return total


FIEMAP = 0xC020660B
HEADER = struct.Struct("=QQIIII")
EXTENT = struct.Struct("=QQQQQIIII")
LAST, UNWRITTEN, SHARED = 1, 0x800, 0x2000
KNOWN = LAST | UNWRITTEN | SHARED
MAX_OFFSET = (1 << 64) - 1


def mappings(file):
    """Enumerate allocated ranges. Unknown flags force a file read for that range."""
    start = 0
    batch = 512
    while True:
        buf = bytearray(HEADER.size + batch * EXTENT.size)
        HEADER.pack_into(buf, 0, start, MAX_OFFSET - start, 1, 0, batch, 0)
        fcntl.ioctl(file.fileno(), FIEMAP, buf, True)
        count = HEADER.unpack_from(buf)[3]
        if not count:
            return
        for index in range(count):
            off, phys, length, _, _, flags, _, _, _ = EXTENT.unpack_from(
                buf, HEADER.size + index * EXTENT.size
            )
            if off < start or not length:
                raise ValueError("invalid FIEMAP extent")
            yield off, off + length, phys, flags
            start = off + length
        if flags & LAST:
            return


class LocalSnapshot:
    def __init__(self, directory, origin, stack):
        (entry,) = json.loads((directory / "filestores.json").read_text())["filestores"]
        if entry["file"] != "filestore-0":
            raise ValueError("expected one root filestore")
        self.entry = entry
        self.layer = (entry.get("delta") or {}).get("frozen")
        if not self.layer:
            raise ValueError("expected a frozen layer from --filestore-extent-snapshot")
        self.size = entry["size_bytes"]
        self.file = stack.enter_context(
            (directory / entry["file"]).open("rb", buffering=0)
        )
        st = os.fstat(self.file.fileno())
        if st.st_size != self.size:
            raise ValueError("truncated local snapshot")
        origin_stat = origin.stat()
        if (
            self.layer["base_inode"],
            self.layer["base_size"],
            self.layer["base_fingerprint"],
        ) != (origin_stat.st_ino, origin_stat.st_size, fingerprint(origin)):
            raise ValueError("snapshot does not belong to this immutable origin")
        self.identity = dict(
            id=self.layer["snapshot_id"],
            manifest=hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest(),
            inode=st.st_ino,
            device=st.st_dev,
        )
        if not self.identity["id"]:
            raise ValueError("missing snapshot ID")
        self.local = []
        for r in self.layer["local_ranges"] or []:
            lo, end = r["offset"], r["offset"] + r["length"]
            if (
                not (0 <= lo < end <= self.size)
                or self.local
                and lo < self.local[-1][1]
            ):
                raise ValueError("invalid frozen ownership ranges")
            self.local.append((lo, end))
        self.index_extents()

    def index_extents(self):
        self.map = []
        self.mapped = False
        if (
            subprocess.check_output(
                ["stat", "-f", "-L", "-c", "%t", f"/proc/self/fd/{self.file.fileno()}"],
                pass_fds=(self.file.fileno(),),
                text=True,
            ).strip()
            == "58465342"
        ):
            try:
                self.map = list(mappings(self.file))
                self.mapped = True
            except OSError as e:
                # EBADR is FIEMAP's response to an unsupported input flag.
                # A partial extent list also has to be discarded on fallback.
                if e.errno not in (
                    errno.ENOTTY,
                    errno.EOPNOTSUPP,
                    errno.ENOSYS,
                    errno.EBADR,
                ):
                    raise
        self.local_starts = [r[0] for r in self.local]
        self.map_starts = [r[0] for r in self.map]

    def boundaries(self):
        yield self.size
        yield self.layer["base_size"]
        for ranges in (self.local, self.map):
            for r in ranges:
                yield r[0]
                yield r[1]

    def at(self, pos):
        if pos >= self.size:
            return "zero", None
        i = bisect.bisect_right(self.local_starts, pos) - 1
        if pos < self.layer["base_size"] and (i < 0 or self.local[i][1] <= pos):
            return "origin", None
        if not self.mapped:
            return "data", None
        i = bisect.bisect_right(self.map_starts, pos) - 1
        if i < 0 or self.map[i][1] <= pos:
            return "zero", None
        lo, _, phys, flags = self.map[i]
        if flags & ~KNOWN:
            return "data", None
        if flags & UNWRITTEN:
            return "zero", None
        address = (
            (self.identity["device"], phys + pos - lo)
            if phys and flags & SHARED
            else None
        )
        return "data", address


def plan(origin_size, previous, current):
    bounds = {0, current.size, origin_size, *current.boundaries()}
    if previous:
        bounds.update(previous.boundaries())
    points = sorted(x for x in bounds if 0 <= x <= current.size)
    changes = []
    shared = 0
    for start, end in zip(points, points[1:]):
        old = (
            previous.at(start)
            if previous
            else ("origin" if start < origin_size else "zero", None)
        )
        new = current.at(start)
        if new == old and (new[0] != "data" or new[1] is not None):
            if new[0] == "data":
                shared += end - start
            continue
        kind = new[0]
        if (
            changes
            and changes[-1]["kind"] == kind
            and changes[-1]["offset"] + changes[-1]["length"] == start
        ):
            changes[-1]["length"] += end - start
        else:
            changes.append(dict(offset=start, length=end - start, kind=kind))
    return changes, shared


def capture_digests(snapshot, snapshot_id):
    capture = json.loads((snapshot / "capture.json").read_text())
    if capture["snapshot_id"] != snapshot_id:
        raise ValueError("wrong process image capture ID")
    images = capture["images"]
    if set(images) not in (
        {"checkpoint.img"},
        {"checkpoint.img", "pages_meta.img", "pages.img"},
    ):
        raise ValueError("unknown capture image set")
    return images


class FullSnapshot(LocalSnapshot):
    """A fresh sandbox's frozen file is a complete XFS inode, with no origin."""

    def __init__(self, directory, stack):
        (self.entry,) = json.loads((directory / "filestores.json").read_text())[
            "filestores"
        ]
        if self.entry["file"] != "filestore-0" or "delta" in self.entry:
            raise ValueError("expected one complete root filestore")
        self.file = stack.enter_context(
            (directory / "filestore-0").open("rb", buffering=0)
        )
        st = os.fstat(self.file.fileno())
        self.size = self.entry["size_bytes"]
        if st.st_size != self.size:
            raise ValueError("truncated complete filestore")
        self.layer = {"base_size": 0}
        self.local = self.local_starts = []
        self.index_extents()
        self.identity = {"device": st.st_dev, "inode": st.st_ino}


def copy_extent(src, dst, offset, length):
    src.seek(offset)
    dst.seek(offset)
    while length:
        data = src.read(min(4 << 20, length))
        if not data:
            raise OSError("short frozen filestore")
        dst.write(data)
        length -= len(data)


def publish(cache, frozen, image, output):
    """The runtime serializes checkpoint and delete per sandbox; ADX owns output GC."""
    origin_marker = cache / "origin"
    origin = (
        Path(origin_marker.read_text()) / "filestore-0"
        if origin_marker.exists()
        else None
    )
    latest = cache / "latest.json"
    prior = json.loads(latest.read_text()) if latest.exists() else None
    with contextlib.ExitStack() as stack:

        def load(directory):
            return (
                LocalSnapshot(directory, origin, stack)
                if origin
                else FullSnapshot(directory, stack)
            )

        current = load(frozen)
        previous = parent = None
        if prior:
            remote = Path(prior["remote"])
            try:
                receipt = json.loads((remote / "incremental.json").read_text())
                if receipt["generation"] != prior["generation"]:
                    raise ValueError("parent generation does not match local freeze")
                previous = load(cache / prior["frozen"])
                if previous.identity != receipt["local"]:
                    raise ValueError("parent filestore identity mismatch")
                parent = stack.enter_context(
                    (remote / "filestores/filestore-0").open("rb", buffering=0)
                )
            except FileNotFoundError:
                # Public snapshot deletion can race a subsequent checkpoint. The
                # open parent FD pins any selected inode through the composition.
                previous = parent = None
        base = stack.enter_context(origin.open("rb", buffering=0)) if origin else None
        base_size = os.fstat(base.fileno()).st_size if base else 0
        changes, shared = plan(base_size, previous, current)
        directory = output / "filestores"
        directory.mkdir()
        target = directory / "filestore-0"
        with target.open("xb") as dst:
            inherited = parent or base
            if inherited:
                range_copy(
                    inherited.fileno(),
                    dst.fileno(),
                    min(current.size, os.fstat(inherited.fileno()).st_size),
                    0,
                    0,
                )
            dst.truncate(current.size)
            for r in changes:
                off, size = r["offset"], r["length"]
                if r["kind"] == "data":
                    copy_extent(current.file, dst, off, size)
                    dst.flush()
                elif r["kind"] == "zero":
                    punch(dst.fileno(), off, size)
                elif r["kind"] == "origin" and base:
                    range_copy(base.fileno(), dst.fileno(), size, off, off)
                else:
                    raise ValueError("unsupported frozen range")
            dst.flush()
            os.fsync(dst.fileno())
        if fingerprint(target) != current.entry["fingerprint"]:
            raise ValueError("composed filestore differs from frozen capture")
        entry = {k: v for k, v in current.entry.items() if k != "delta"}
        (directory / "filestores.json").write_text(json.dumps({"filestores": [entry]}))
        if origin:
            hashes = capture_digests(frozen, current.identity["id"])
        else:
            names = {p.name for p in image.iterdir()}
            if names not in (
                {"checkpoint.img"},
                {"checkpoint.img", "pages.img", "pages_meta.img"},
            ):
                raise ValueError("unexpected process image set")
            hashes = {}
            for name in names:
                with (image / name).open("rb") as f:
                    digest = hashlib.sha256()
                    for block in iter(lambda: f.read(1 << 20), b""):
                        digest.update(block)
                    hashes[name] = digest.hexdigest()
        image_dest = output / ".process-images"
        verify_images(image, hashes, image_dest)
        for name in hashes:
            (image_dest / name).rename(output / name)
        image_dest.rmdir()
        generation = str(uuid.uuid4())
        receipt = {
            "generation": generation,
            "local": current.identity,
            "sharedLocalBytes": shared,
            "rwfsUploadBytes": sum(r["length"] for r in changes if r["kind"] == "data"),
            "parentGeneration": prior["generation"] if previous else None,
            "fromPrevious": previous is not None,
            "images": hashes,
        }
        receipt["zeroBytes"] = sum(r["length"] for r in changes if r["kind"] == "zero")
        (output / "incremental.json").write_text(json.dumps(receipt))
        for path in [
            directory / "filestores.json",
            directory,
            output / "incremental.json",
            output,
        ]:
            fsync_path(path)
        next_meta = cache / "latest.tmp"
        next_meta.write_text(
            json.dumps(
                {"generation": generation, "frozen": frozen.name, "remote": str(output)}
            )
        )
        fsync_path(next_meta)
        next_meta.replace(latest)
        fsync_path(cache)
        if prior:
            shutil.rmtree(cache / prior["frozen"], ignore_errors=True)
        return receipt


if __name__ == "__main__":
    cache, frozen, image, output = map(Path, sys.argv[1:])
    publish(cache, frozen, image, output)
