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

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func receiveFD(conn *net.UnixConn) (int, error) {
	file, err := conn.File()
	if err != nil {
		return -1, err
	}
	defer file.Close()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return -1, err
	}
	buffer := make([]byte, 1)
	control := make([]byte, syscall.CmsgSpace(4))
	_, controlSize, _, _, err := syscall.Recvmsg(
		int(file.Fd()),
		buffer,
		control,
		0,
	)
	if err != nil {
		return -1, err
	}
	messages, err := syscall.ParseSocketControlMessage(control[:controlSize])
	if err != nil {
		return -1, err
	}
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_SOCKET ||
			message.Header.Type != syscall.SCM_RIGHTS {
			continue
		}
		fds, err := syscall.ParseUnixRights(&message)
		if err != nil {
			return -1, err
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no file descriptor received")
}

func setRawMode() (*syscall.Termios, error) {
	oldState, err := tcgetattr(int(os.Stdin.Fd()))
	if errors.Is(err, syscall.ENOTTY) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	newState := *oldState
	newState.Iflag &^= syscall.BRKINT | syscall.ICRNL | syscall.INPCK |
		syscall.ISTRIP | syscall.IXON
	newState.Oflag &^= syscall.OPOST
	newState.Cflag |= syscall.CS8
	newState.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN |
		syscall.ISIG
	newState.Cc[syscall.VMIN] = 1
	newState.Cc[syscall.VTIME] = 0
	if err := tcsetattr(int(os.Stdin.Fd()), &newState); err != nil {
		return nil, err
	}
	return oldState, nil
}

func restoreMode(state *syscall.Termios) {
	if state != nil {
		_ = tcsetattr(int(os.Stdin.Fd()), state)
	}
}

func tcgetattr(fd int) (*syscall.Termios, error) {
	var termios syscall.Termios
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		syscall.TCGETS,
		uintptr(unsafe.Pointer(&termios)),
	)
	if err != 0 {
		return nil, err
	}
	return &termios, nil
}

func tcsetattr(fd int, termios *syscall.Termios) error {
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		syscall.TCSETS,
		uintptr(unsafe.Pointer(termios)),
	)
	if err != 0 {
		return err
	}
	return nil
}

func syncWindowSize(sourceFD, targetFD int) {
	window, err := unix.IoctlGetWinsize(sourceFD, unix.TIOCGWINSZ)
	if err != nil {
		logrus.Debugf("read terminal size: %v", err)
		return
	}
	if err := unix.IoctlSetWinsize(targetFD, unix.TIOCSWINSZ, window); err != nil {
		logrus.Debugf("set terminal size: %v", err)
	}
}
