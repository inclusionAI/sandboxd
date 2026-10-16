#!/usr/bin/env python3
"""Verify the disposable PVM L1 boundary before any privileged CI operations."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--marker", type=Path, default=Path("/etc/akernel-pvm-ci.json"))
parser.add_argument("--probe", action="store_true")
args = parser.parse_args()


def require(ok, message):
    if not ok:
        raise SystemExit(message)


marker = json.loads(args.marker.read_text())
require(
    marker["schema"] == 1 and marker["isolation"] == "disposable-l1",
    "requires a disposable L1 runner",
)
require(
    platform.machine() == "x86_64" and platform.release() == marker["kernel_release"],
    "unqualified L1 kernel",
)
require(
    "init=/root/l1-init.sh" in Path("/proc/cmdline").read_text().split(),
    "refusing module operations outside the owned L1",
)
flags = (
    Path("/proc/cpuinfo")
    .read_text()
    .split("flags", 1)[1]
    .splitlines()[0]
    .split(":", 1)[1]
    .split()
)
require("vmx" not in flags and "svm" not in flags, "PVM CI must hide VMX/SVM")
require(
    all(x in flags for x in ["fsgsbase", "rdtscp", "cx16"]),
    "PVM CPU prerequisites missing",
)
require(
    marker["outer_network"] == "none"
    and marker["cpu_quota"] == 2
    and marker["memory_gib"] == 10,
    "unbounded L1 runner",
)
require(not marker["debugctl_applied"], "default PVM CI must leave DEBUGCTL unapplied")
for name, digest in marker["modules"].items():
    path = Path("/opt/akernel-pvm-ci/modules") / name
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == digest,
        "host module checksum mismatch",
    )
proof = {
    "kernel": platform.release(),
    "vmx": False,
    "svm": False,
    "host_source": marker["host_source"],
    "debugctl_applied": False,
    "lab_id": marker["lab_id"],
}
if args.probe:
    with open("/dev/kvm", "rb", buffering=0) as kvm:
        require(fcntl.ioctl(kvm, 0xAE00, 0) == 12, "KVM API mismatch")
        msrs = bytearray(4004)
        struct.pack_into("I", msrs, 0, 1000)
        fcntl.ioctl(kvm, 0xC004AE02, msrs, True)
        count = struct.unpack_from("I", msrs)[0]
        require(count <= 1000, "MSR list overflow")
        require(
            0x4B564DF1 in struct.unpack_from(str(count) + "I", msrs, 4),
            "the running KVM backend is not PVM",
        )
        control = fcntl.ioctl(kvm, 0xAE03, 60)
        require(control == 0, "unexpected PVM TSC scaling")
        vm = fcntl.ioctl(kvm, 0xAE01, 0)
        try:
            vcpu = fcntl.ioctl(vm, 0xAE41, 0)
            try:
                frequency = fcntl.ioctl(vcpu, 0xAEA3, 0)
            finally:
                os.close(vcpu)
        finally:
            os.close(vm)
        require(frequency > 0, "PVM TSC frequency is not verifiable")
        proof.update(backend="pvm", tsc_frequency_khz=frequency, tsc_scaling=False)
print(json.dumps(proof))
