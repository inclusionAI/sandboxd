#!/usr/bin/env python3
"""Verify a separately pinned PVM bundle and stage its original build archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 512 * 1024 * 1024


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_pin(path: Path) -> dict:
    pin = json.loads(path.read_text())
    require(
        pin["schema"] == 1 and pin["repository"] == "akernel-dev/firecracker",
        "invalid PVM candidate",
    )
    require(
        re.fullmatch(r"v\d+\.\d+\.\d+-akernel\.\d+", pin["release_tag"]),
        "invalid PVM candidate",
    )
    for key, length in [
        ("commit", 40),
        ("archive_sha256", 64),
        ("guest_commit", 40),
        ("guest_source_sha256", 64),
    ]:
        require(re.fullmatch(r"[0-9a-f]{" + str(length) + "}", pin[key]), key)
    require(
        re.fullmatch(r"sha256:[0-9a-f]{64}", pin["artifact_digest"]),
        "invalid PVM candidate",
    )
    require(
        isinstance(pin["run_id"], int) and pin["run_id"] > 0, "invalid PVM candidate"
    )
    require(
        isinstance(pin["artifact_id"], int) and pin["artifact_id"] > 0,
        "invalid PVM candidate",
    )
    require(
        pin["archive_name"] == f"firecracker-{pin['release_tag']}-x86_64.tgz",
        "invalid PVM candidate",
    )
    require(
        pin.get("distribution", "actions") in ("actions", "release"),
        "invalid distribution",
    )
    if pin.get("distribution") == "release":
        require(
            pin["archive_url"]
            == f"https://github.com/{pin['repository']}/releases/download/"
            f"{pin['release_tag']}/{pin['archive_name']}",
            "release URL does not match the pinned repository, tag and archive",
        )
    return pin


def verify_archive(path: Path, pin: dict) -> dict:
    require(
        path.stat().st_size <= MAX_BYTES and sha256(path) == pin["archive_sha256"],
        "candidate archive checksum mismatch",
    )
    prefix = f"release-{pin['release_tag']}-x86_64/"
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        require(
            sum(m.size for m in members) <= MAX_BYTES, "candidate exceeds size limit"
        )
        for member in members:
            parts = PurePosixPath(member.name).parts
            require(
                not member.name.startswith("/") and ".." not in parts,
                "invalid PVM candidate",
            )
            require(
                member.isdir() or member.isfile(),
                "candidate contains links or special files",
            )
            require(
                member.name == prefix.rstrip("/") or member.name.startswith(prefix),
                "invalid PVM candidate",
            )

        def read(name: str) -> bytes:
            stream = archive.extractfile(prefix + name)
            require(stream is not None, name)
            return stream.read()

        manifest = json.loads(read("manifest.json"))
        for key, value in {
            "component": "akernel-firecracker-runtime",
            "repository": pin["repository"],
            "commit": pin["commit"],
            "workflow_run_id": str(pin["run_id"]),
            "release_tag": pin["release_tag"],
            "architecture": "x86_64",
            "kernel_profile": "pvm",
        }.items():
            require(manifest[key] == value, f"candidate provenance mismatch: {key}")
        require(
            manifest["vmm"]["source"] == "fork-source-build", "invalid PVM candidate"
        )
        require(
            manifest["guest_kernel"]["source_tag"] == pin["guest_commit"],
            "invalid PVM candidate",
        )
        require(
            manifest["guest_kernel"]["source_sha256"] == pin["guest_source_sha256"],
            "invalid PVM candidate",
        )
        for line in read("SHA256SUMS").decode().splitlines():
            digest, name = line.split(None, 1)
            name = name.removeprefix("*").removeprefix("./")
            require(
                not name.startswith("/") and ".." not in PurePosixPath(name).parts,
                "invalid PVM candidate",
            )
            require(hashlib.sha256(read(name)).hexdigest() == digest, name)
        for name, section, digest_key in [
            ("firecracker", "vmm", "binary_sha256"),
            ("vmlinux", "guest_kernel", "image_sha256"),
        ]:
            data = read(name)
            require(
                data[:6] == b"\x7fELF\x02\x01" and data[18:20] == b"\x3e\x00",
                f"{name} is not x86-64 ELF",
            )
            require(
                hashlib.sha256(data).hexdigest() == manifest[section][digest_key],
                "invalid PVM candidate",
            )
        require(
            hashlib.sha256(read("kernel.config")).hexdigest()
            == manifest["guest_kernel"]["config_sha256"],
            "kernel config checksum mismatch",
        )
        config = read("kernel.config").decode().splitlines()
        for option in (
            "KVM_GUEST",
            "PVM_GUEST",
            "X86_PIE",
            "X86_INTEL_MEMORY_PROTECTION_KEYS",
        ):
            require(f"CONFIG_{option}=y" in config, option)
        return manifest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(path: str, token: str) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def download_actions(pin: dict, destination: Path, token: str) -> None:
    require(token, "GH_TOKEN is required to download an Actions candidate")
    root = "repos/" + pin["repository"]
    run = api(f"{root}/actions/runs/{pin['run_id']}", token)
    require(
        run["conclusion"] == "success" and run["head_sha"] == pin["commit"],
        "invalid PVM candidate",
    )
    require(
        run["path"] == ".github/workflows/akernel-candidate.yml",
        "invalid PVM candidate",
    )
    artifact = api(f"{root}/actions/artifacts/{pin['artifact_id']}", token)
    require(
        not artifact["expired"] and artifact["digest"] == pin["artifact_digest"],
        "invalid PVM candidate",
    )
    require(artifact["workflow_run"]["id"] == pin["run_id"], "invalid PVM candidate")
    request = urllib.request.Request(
        f"https://api.github.com/{root}/actions/artifacts/{pin['artifact_id']}/zip",
        headers={"Authorization": "Bearer " + token},
    )
    try:
        urllib.request.build_opener(NoRedirect).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        require(error.code == 302, "candidate artifact download failed")
        url = error.headers["Location"]
    else:
        raise AssertionError("expected a signed artifact redirect")
    parsed = urllib.parse.urlsplit(url)
    require(
        parsed.scheme == "https" and not parsed.username and not parsed.password,
        "invalid PVM candidate",
    )
    # Never forward the GitHub Authorization header to blob storage.
    with tempfile.TemporaryDirectory() as directory:
        zip_path = Path(directory) / "artifact.zip"
        with (
            urllib.request.urlopen(url, timeout=60) as response,
            zip_path.open("wb") as stream,
        ):
            total = 0
            for block in iter(lambda: response.read(1024 * 1024), b""):
                total += len(block)
                require(total <= MAX_BYTES, "invalid PVM candidate")
                stream.write(block)
        require(
            "sha256:" + sha256(zip_path) == pin["artifact_digest"],
            "Actions artifact digest mismatch",
        )
        with zipfile.ZipFile(zip_path) as artifact_zip:
            info = artifact_zip.getinfo(pin["archive_name"])
            require(info.file_size <= MAX_BYTES, "invalid PVM candidate")
            with artifact_zip.open(info) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)


def download(pin: dict, destination: Path, token: str) -> None:
    if pin.get("distribution", "actions") == "actions":
        download_actions(pin, destination, token)
        return
    # Public promoted assets do not require Actions access or its expiring ZIP.
    # No token is attached to either GitHub or the signed storage redirect.
    with (
        urllib.request.urlopen(pin["archive_url"], timeout=60) as response,
        destination.open("wb") as stream,
    ):
        require(
            urllib.parse.urlsplit(response.url).scheme == "https",
            "insecure release redirect",
        )
        total = 0
        for block in iter(lambda: response.read(1024 * 1024), b""):
            total += len(block)
            require(total <= MAX_BYTES, "release archive exceeds size limit")
            stream.write(block)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pin", type=Path, default=ROOT / "firecracker-pvm.json"
    )
    parser.add_argument(
        "--archive",
        type=Path,
        help="use the same pinned candidate bytes already downloaded locally",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=ROOT / "firecracker-candidate/firecracker.tgz",
    )
    parser.add_argument(
        "--fields",
        action="store_true",
        help="print the release, archive checksum and pinned download source",
    )
    args = parser.parse_args()
    pin = load_pin(args.pin)
    if args.fields:
        print(pin["release_tag"])
        print(pin["archive_sha256"])
        print(
            pin["archive_url"]
            if pin.get("distribution") == "release"
            else f"github-actions://{pin['repository']}/{pin['artifact_id']}/{pin['archive_name']}"
        )
        return
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    if args.destination.exists():
        verify_archive(args.destination, pin)
    else:
        temporary = args.destination.with_suffix(".pending")
        try:
            if args.archive:
                shutil.copyfile(args.archive, temporary)
            else:
                download(pin, temporary, os.environ.get("GH_TOKEN", ""))
            verify_archive(temporary, pin)
            os.replace(temporary, args.destination)
        finally:
            temporary.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "archive": str(args.destination),
                "sha256": pin["archive_sha256"],
                "release": pin["release_tag"],
                "profile": "pvm",
            }
        )
    )


if __name__ == "__main__":
    main()
