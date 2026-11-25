# SPDX-License-Identifier: Apache-2.0
"""Host-side adapter to the matching Firecracker sealed-block coordinator."""
import fcntl
import json
import mmap
import os
from pathlib import Path
import runpy
import shutil
import sys
from types import SimpleNamespace
import uuid

cp = SimpleNamespace(**{k: v for k, v in runpy.run_path(sys.argv[1]).items() if not k.startswith("__")})
action, work, scratch, directory = sys.argv[2], *map(Path, sys.argv[3:6])
disk = "overlay.ext4"
# Serialized in Go while the daemon is alive. Also fence any old child
# exiting after daemon restart before reusing a generation or a file slot.
lock = (work.parent / "sealed.lock").open("a+b")
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
if action == "init":
    scratch.mkdir(mode=0o700)
    base = scratch / "base"
    base.mkdir()
    # Pin the caller's immutable v2 components without reading their contents.
    for name in (disk, "memory", "vmstate"):
        os.link(directory / name, base / name)
    cp.init(work, base / disk, base)
    # Discover unsupported local filesystems before the first guest write.
    with (work / "merged.0").open("rb") as src, (work / "merged.1").open("r+b") as dst:
        fcntl.ioctl(dst.fileno(), cp.FICLONE, src.fileno())

elif action == "prepare":
    # Test that the output and publisher permit a same-mount range copy
    # before pausing. The server owns the output directory.
    import tempfile

    with tempfile.TemporaryFile(dir=scratch) as src, tempfile.TemporaryFile(dir=directory) as dst:
        src.write(b"x")
        src.flush()
        cp.clone_range(src, dst, 0, 0, 1)
    with (work / "epochs").open("r+b") as f, mmap.mmap(f.fileno(), 0) as mm:
        words = cp.Words(mm)
        state = json.loads((work / "state.json").read_text())
        if "pending" in state:
            # A resumed, sealed job can be retried after loss of its RPC/output.
            # A pre-cut pending job may have consumed RAM dirty bits; fail closed.
            cp.finish(work, words, state)
            state = json.loads((work / "state.json").read_text())
        g = state["generation"] + 1
        if g >= 2**32 - 1 or (words.get(0), words.get(4), words.get(8)) != (g, g - 1, 0):
            raise RuntimeError("invalid sealed generation or previous device failure")
        if g > 2:
            retired = scratch / str(g - 2)
            if retired.exists():
                shutil.rmtree(retired)
        size = (work / "lower").stat().st_size
        sectors = size // cp.SECTOR
        cp.resize(work / cp.UPPERS[g % 3], size)
        bank = 4096 + (g % 2) * sectors
        for off in range(0, sectors, 1 << 20):
            length = min(sectors - off, 1 << 20)
            mm[bank + off:bank + off + length] = bytes(length)
        capture = work / f"capture-{g}"
        # A terminated prepare may leave its empty directory before its
        # journal rename. Reuse only that empty, uncommitted directory.
        capture.mkdir(exist_ok=True)
        if any(capture.iterdir()):
            raise RuntimeError("unexpected contents in uncommitted capture")
        state["pending"] = {"generation": g, "target": str(scratch / str(g)), "id": str(uuid.uuid4())}
        cp.save_state(work, state)
        print(g)
elif action == "finish":
    with (work / "epochs").open("r+b") as f, mmap.mmap(f.fileno(), 0) as mm:
        state = json.loads((work / "state.json").read_text())
        cp.finish(work, cp.Words(mm), state)
        parent = Path(state["pending"]["target"])
    # Distinct inodes keep cleanup and writes to exported generations isolated
    # from B's private publishing parent. The Go caller writes the v2 manifest last.
    for name in (disk, "memory", "vmstate"):
        with (parent / name).open("rb") as src, (directory / name).open("xb") as dst:
            cp.clone_range(src, dst, 0, 0, os.fstat(src.fileno()).st_size)
else:
    raise ValueError(action)
