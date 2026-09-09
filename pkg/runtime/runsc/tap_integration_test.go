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

package runsc

import (
	"fmt"
	"net"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestOpenTAPResetsVMOffloads reproduces a Firecracker/Kata -> runsc pooled
// TAP handoff against the kernel. Run only inside an isolated network namespace.
func TestOpenTAPResetsVMOffloads(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_TAP_INTEGRATION") != "1" {
		t.Skip("set SANDBOXD_RUN_TAP_INTEGRATION=1 in an isolated network namespace")
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	name := fmt.Sprintf("sdtap%d", os.Getpid())
	req, err := unix.NewIfreq(name)
	require.NoError(t, err)
	req.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	require.NoError(t, unix.IoctlIfreq(fd, unix.TUNSETIFF, req))
	require.NoError(t, unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1))
	defer func() {
		cleanupFD, openErr := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if openErr != nil {
			t.Error(openErr)
			return
		}
		defer unix.Close(cleanupFD)
		cleanupReq, _ := unix.NewIfreq(name)
		cleanupReq.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(cleanupFD, unix.TUNSETIFF, cleanupReq); err != nil {
			t.Error(err)
			return
		}
		if err := unix.IoctlSetInt(cleanupFD, unix.TUNSETPERSIST, 0); err != nil {
			t.Error(err)
		}
	}()
	require.NoError(t, unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, unix.TUN_F_CSUM|unix.TUN_F_TSO4|unix.TUN_F_TSO6))
	require.EqualValues(t, 1, tapFeature(t, name, unix.ETHTOOL_GTXCSUM))
	require.EqualValues(t, 1, tapFeature(t, name, unix.ETHTOOL_GTSO))
	require.NoError(t, unix.Close(fd))
	fd = -1
	tap, err := OpenTAP(net.Interface{Name: name})
	require.NoError(t, err)
	defer tap.Close()
	require.Zero(t, tapFeature(t, name, unix.ETHTOOL_GTXCSUM), "VM checksum offloads survived runsc handoff")
	require.Zero(t, tapFeature(t, name, unix.ETHTOOL_GTSO), "VM segmentation offloads survived runsc handoff")
}

// Legacy ethtool feature queries use an ethtool_value behind ifreq.ifr_data.
func tapFeature(t *testing.T, name string, command uint32) uint32 {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	value := struct{ Command, Data uint32 }{Command: command}
	request := struct {
		Name    [unix.IFNAMSIZ]byte
		Data    unsafe.Pointer
		Padding [unsafe.Sizeof(unix.Ifreq{}) - unix.IFNAMSIZ - unsafe.Sizeof(uintptr(0))]byte
	}{Data: unsafe.Pointer(&value)}
	copy(request.Name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&request)))
	require.Zero(t, errno)
	return value.Data
}
