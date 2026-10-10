// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firecracker

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// KVM backend identities recorded in checkpoint compatibility tuples and
// compared on restore. The empty string represents a legacy manifest written
// before backend tagging existed.
const (
	// KvmBackendPVM identifies the kvm-pvm vendor module (PVM: software
	// virtualization running the guest at CPL3).
	KvmBackendPVM = "pvm"
	// KvmBackendHardware identifies hardware virtualization backends
	// (kvm-intel or kvm-amd).
	KvmBackendHardware = "kvm"
)

// msrPVMVCPUStruct is MSR_PVM_VCPU_STRUCT from the PVM specification
// (uapi/asm/pvm_para.h). KVM_GET_MSR_INDEX_LIST includes it only when the
// kvm-pvm backend is loaded: init_msr_lists filters emulated_msrs_all
// through the vendor has_emulated_msr callback, and vmx_has_emulated_msr
// returns false for the entire PVM_VIRTUAL_MSR range.
const msrPVMVCPUStruct uint32 = 0x4b564df1

// KVM ioctl numbers, encoded per include/uapi/asm-generic/ioctl.h with
// _IOC_NRBITS=8, _IOC_TYPEBITS=8 (type occupies bits 8–15, not 16–23).
// Verified against the independent C UAPI probe:
//
//	kvmGetMSRIndexList = 3221532162 (0xC004AE02)
//	kvmCheckExtension  =     44547 (0xAE03)
const (
	kvmGetMSRIndexList = 0xC004AE02 // _IOWR(KVMIO, 0x02, struct kvm_msr_list), size=4
	kvmCheckExtension  = 0xAE03     // _IO(KVMIO, 0x03)
)

// KVM extension capability numbers (include/uapi/linux/kvm.h).
const (
	kvmCapTSCControl = 60 // KVM_CAP_TSC_CONTROL
	kvmCapGetTSCKHZ  = 61 // KVM_CAP_GET_TSC_KHZ
)

// KVM_GET_MSR_INDEX_LIST operates on the system-wide /dev/kvm fd
// (kvm_arch_dev_ioctl in arch/x86/kvm/x86.c), not on a VM fd. The header
// is a single __u32 nmsrs that serves as both input capacity and output
// count.
const kvmMSRListHeaderSize = 4

// maxKvmMSRIndexListEntries bounds the second-pass allocation. A typical
// kvm-intel backend reports ~100 entries; kvm-pvm reports a similar count.
const maxKvmMSRIndexListEntries = 1 << 16

// kvmTSCCapabilities reports whether the loaded KVM backend supports TSC
// frequency scaling (KVM_CAP_TSC_CONTROL) and reading the TSC frequency
// (KVM_CAP_GET_TSC_KHZ). PVM reports scaling=0 (no KVM_SET_TSC_KHZ) and
// reading=1; hardware backends report both on modern Intel CPUs.
type kvmTSCCapabilities struct {
	ScalingSupported  bool
	FrequencyReadable bool
}

// probeKvmBackend identifies the KVM vendor backend behind /dev/kvm by
// inspecting the ABI rather than module names or operator-supplied strings.
// It issues KVM_GET_MSR_INDEX_LIST on the system-wide KVM fd and checks for
// MSR_PVM_VCPU_STRUCT: kvm_arch_dev_ioctl builds the list from
// msrs_to_save + emulated_msrs, which is filtered by the loaded vendor
// module's has_emulated_msr callback. vmx_has_emulated_msr returns false
// for PVM_VIRTUAL_MSR_BASE..MAX, so only the kvm-pvm backend reports it.
//
// The two-pass protocol: the first call with zero capacity makes the kernel
// write the actual count into nmsrs and return E2BIG; the second call with
// that count as the input capacity receives the indices array. The caller
// must write the capacity into nmsrs before the second ioctl, or the kernel
// sees a stale zero and returns E2BIG again.
func probeKvmBackend(kvmDevice string) (backend string, err error) {
	kvmFD, err := syscall.Open(kvmDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open %s for backend probe: %w", kvmDevice, err)
	}
	defer syscall.Close(kvmFD)

	indices, err := readKvmMSRIndexList(kvmFD)
	if err != nil {
		return "", fmt.Errorf("KVM_GET_MSR_INDEX_LIST: %w", err)
	}
	for _, index := range indices {
		if index == msrPVMVCPUStruct {
			return KvmBackendPVM, nil
		}
	}
	return KvmBackendHardware, nil
}

// probeKvmTSCCapabilities queries KVM extension capabilities on the
// system-wide /dev/kvm fd.
func probeKvmTSCCapabilities(kvmDevice string) (kvmTSCCapabilities, error) {
	kvmFD, err := syscall.Open(kvmDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return kvmTSCCapabilities{}, fmt.Errorf("open %s for TSC probe: %w", kvmDevice, err)
	}
	defer syscall.Close(kvmFD)

	checkCap := func(cap int) (bool, error) {
		ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(kvmFD),
			kvmCheckExtension, uintptr(cap))
		if errno != 0 {
			return false, fmt.Errorf("KVM_CHECK_EXTENSION(%d): %w", cap, errno)
		}
		return ret != 0, nil
	}

	scaling, err := checkCap(kvmCapTSCControl)
	if err != nil {
		return kvmTSCCapabilities{}, err
	}
	reading, err := checkCap(kvmCapGetTSCKHZ)
	if err != nil {
		return kvmTSCCapabilities{}, err
	}
	return kvmTSCCapabilities{ScalingSupported: scaling, FrequencyReadable: reading}, nil
}

// KVM_CREATE_VM and KVM_CREATE_VCPU ioctls (uapi/linux/kvm.h):
// _IO(KVMIO, 0x01) and _IO(KVMIO, 0x41).
const (
	kvmCreateVM   = 0xAE01 // _IO(KVMIO, 0x01)
	kvmCreateVCPU = 0xAE41 // _IO(KVMIO, 0x41)
)

// KVM_GET_TSC_KHZ ioctl (uapi/linux/kvm.h): _IO(KVMIO, 0xa3).
const kvmGetTSCKHZ = 0xAEA3

// probeKvmTSCFrequency creates a short-lived probe VM with one vCPU and
// reads the vCPU's TSC frequency via KVM_GET_TSC_KHZ. The returned value
// (in kHz) reflects the actual frequency guests will observe on this node;
// it is recorded in checkpoint compat tuples so a restore can reject a
// frequency mismatch before the VMM tries KVM_SET_TSC_KHZ (which PVM does
// not support).
func probeKvmTSCFrequency(kvmDevice string) (uint32, error) {
	kvmFD, err := syscall.Open(kvmDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s for TSC frequency probe: %w", kvmDevice, err)
	}
	defer syscall.Close(kvmFD)

	vmFD, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(kvmFD),
		kvmCreateVM, 0)
	if errno != 0 {
		return 0, fmt.Errorf("KVM_CREATE_VM for TSC probe: %w", errno)
	}
	defer syscall.Close(int(vmFD))

	vcpuFD, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vmFD),
		kvmCreateVCPU, 0)
	if errno != 0 {
		return 0, fmt.Errorf("KVM_CREATE_VCPU for TSC probe: %w", errno)
	}
	defer syscall.Close(int(vcpuFD))

	ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpuFD),
		kvmGetTSCKHZ, 0)
	if errno != 0 {
		return 0, fmt.Errorf("KVM_GET_TSC_KHZ: %w", errno)
	}
	freq := uint32(ret)
	if freq == 0 {
		return 0, fmt.Errorf("KVM_GET_TSC_KHZ returned 0 (frequency unavailable)")
	}
	return freq, nil
}

// readKvmMSRIndexList issues KVM_GET_MSR_INDEX_LIST on a system-wide KVM fd
// and returns the reported MSR indices. The two-pass flow:
//
//	pass 1: zero-capacity buffer → kernel writes actual nmsrs, returns E2BIG
//	pass 2: buffer sized to nmsrs, capacity written into nmsrs field →
//	        kernel copies the indices array
func readKvmMSRIndexList(kvmFD int) ([]uint32, error) {
	// Pass 1: probe with zero capacity to learn nmsrs.
	probe := make([]byte, kvmMSRListHeaderSize)
	binary.LittleEndian.PutUint32(probe, 0)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(kvmFD),
		kvmGetMSRIndexList, uintptr(unsafe.Pointer(&probe[0])))
	// The kernel always returns E2BIG on the first pass (capacity 0 < count)
	// after writing the actual count; any other errno is a real failure.
	if errno != 0 && errno != syscall.E2BIG {
		return nil, errno
	}
	nmsrs := binary.LittleEndian.Uint32(probe)
	if nmsrs == 0 || nmsrs > maxKvmMSRIndexListEntries {
		return nil, fmt.Errorf(
			"KVM_GET_MSR_INDEX_LIST reported %d MSRs (out of expected range)", nmsrs)
	}

	// Pass 2: allocate the right-sized buffer and write the capacity into
	// nmsrs so the kernel accepts the request.
	buf := make([]byte, kvmMSRListHeaderSize+int(nmsrs)*4)
	binary.LittleEndian.PutUint32(buf, nmsrs) // input capacity
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(kvmFD),
		kvmGetMSRIndexList, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return nil, errno
	}
	return decodeKvmMSRIndices(buf), nil
}

// decodeKvmMSRIndices parses a populated kvm_msr_list buffer. The nmsrs
// field may have been updated by the kernel to the actual count written.
func decodeKvmMSRIndices(buf []byte) []uint32 {
	if len(buf) < kvmMSRListHeaderSize {
		return nil
	}
	nmsrs := binary.LittleEndian.Uint32(buf)
	if int(kvmMSRListHeaderSize+nmsrs*4) > len(buf) {
		nmsrs = uint32((len(buf) - kvmMSRListHeaderSize) / 4)
	}
	indices := make([]uint32, 0, nmsrs)
	for i := 0; i < int(nmsrs); i++ {
		off := kvmMSRListHeaderSize + i*4
		if off+4 > len(buf) {
			break
		}
		indices = append(indices, binary.LittleEndian.Uint32(buf[off:]))
	}
	return indices
}
