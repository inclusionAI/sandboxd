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

// firecracker-agent is the static PID 1 used by the sandboxd Firecracker
// backend. It mounts the block-backed sandbox root, configures the cached TAP,
// launches the sandbox process, and provides administrative exec over vsock.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	containerMountRoot = "/container/root"
	containerLower     = "/container/lower"
	containerOverlay   = "/container/overlay"
	containerNative    = "/container/overlay/native"
	sandboxInitMode    = "sandbox-init"
	sandboxConfigFD    = 3
	sandboxStatusFD    = 4
)

var containerRoot = containerMountRoot

type rootSwitchOperations struct {
	mount  func(string, string, string, uintptr, string) error
	open   func(string, int, uint32) (int, error)
	close  func(int) error
	fchdir func(int) error
	chroot func(string) error
	chdir  func(string) error
}

var systemRootSwitchOperations = rootSwitchOperations{
	mount:  unix.Mount,
	open:   unix.Open,
	close:  unix.Close,
	fchdir: unix.Fchdir,
	chroot: unix.Chroot,
	chdir:  unix.Chdir,
}

type namespaceOperations struct {
	unshare func(int) error
	open    func(string, int, uint32) (int, error)
	close   func(int) error
	setns   func(int, int) error
}

var systemNamespaceOperations = namespaceOperations{
	unshare: unix.Unshare,
	open:    unix.Open,
	close:   unix.Close,
	setns:   unix.Setns,
}

type sandboxNamespace struct {
	name string
	flag int
}

var sandboxNamespaces = []sandboxNamespace{
	{name: "ipc", flag: unix.CLONE_NEWIPC},
	{name: "uts", flag: unix.CLONE_NEWUTS},
	{name: "mnt", flag: unix.CLONE_NEWNS},
	// Joining a PID namespace only affects children created afterward, so it
	// must happen before exec.Cmd.Start forks the requested process.
	{name: "pid", flag: unix.CLONE_NEWPID},
}

type checkpointHandoff struct {
	fifoPath        string
	environmentPath string
	mu              sync.Mutex
	reader          chan string
	pendingRestore  bool
	closed          bool
	stop            chan struct{}
	done            chan struct{}
	stopOnce        sync.Once
}

type agentState struct {
	mu         sync.RWMutex
	configured bool
	process    firecrackerproto.ProcessSpec
	mainPID    int
	mainDone   chan struct{}
	mainExit   int
	handoff    *checkpointHandoff
}

var state agentState

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) == 2 && os.Args[1] == sandboxInitMode {
		if err := runSandboxInit(); err != nil {
			reportSandboxInitError(err)
			log.Fatalf("start sandbox init: %v", err)
		}
		return
	}
	if os.Getpid() != 1 {
		log.Printf("warning: firecracker-agent is PID %d, not PID 1", os.Getpid())
	}
	if err := prepareInitramfs(); err != nil {
		log.Fatalf("prepare initramfs: %v", err)
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		log.Fatalf("create vsock listener: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrVM{
		CID:  unix.VMADDR_CID_ANY,
		Port: firecrackerproto.AgentPort,
	}); err != nil {
		log.Fatalf("bind vsock listener: %v", err)
	}
	if err := unix.Listen(fd, 128); err != nil {
		log.Fatalf("listen on vsock: %v", err)
	}
	log.Printf("firecracker-agent protocol v%d ready on vsock port %d",
		firecrackerproto.Version, firecrackerproto.AgentPort)
	for {
		client, _, err := unix.Accept(fd)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			log.Printf("accept vsock connection: %v", err)
			continue
		}
		unix.CloseOnExec(client)
		go handleConnection(os.NewFile(uintptr(client), "vsock"))
	}
}

func prepareInitramfs() error {
	for _, path := range []string{"/dev", "/proc", "/sys", "/container"} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}
	for _, mount := range []struct {
		source string
		target string
		fsType string
		flags  uintptr
		data   string
	}{
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755"},
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, ""},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, ""},
	} {
		if err := mountIfNeeded(mount.source, mount.target, mount.fsType, mount.flags, mount.data); err != nil {
			return err
		}
	}
	return nil
}

func handleConnection(connection *os.File) {
	defer connection.Close()
	messageType, payload, err := firecrackerproto.ReadMessage(connection)
	if err != nil {
		log.Printf("read agent request: %v", err)
		return
	}
	switch messageType {
	case firecrackerproto.MessageHealth:
		writeResponse(connection, nil)
	case firecrackerproto.MessageConfigure:
		var request firecrackerproto.ConfigureRequest
		if err := firecrackerproto.Decode(payload, &request); err != nil {
			writeResponse(connection, err)
			return
		}
		writeResponse(connection, configure(request))
	case firecrackerproto.MessageSetNetwork:
		var request firecrackerproto.NetworkSpec
		if err := firecrackerproto.Decode(payload, &request); err != nil {
			writeResponse(connection, err)
			return
		}
		writeResponse(connection, reconfigureNetwork(request))
	case firecrackerproto.MessageFlush:
		// Checkpoint quiesce hook: sync() drains the writable layer (the
		// guest's only persistent filesystem) before the host snapshots it.
		// The reply doubles as the ack — the host proceeds on timeout anyway.
		log.Printf("flushing guest filesystems for checkpoint")
		syscall.Sync()
		writeResponse(connection, nil)
	case firecrackerproto.MessageShrink:
		// Checkpoint shrink hook: sync, then drop the page caches.
		log.Printf("shrinking guest caches for checkpoint")
		syscall.Sync()
		if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0o200); err != nil {
			log.Printf("drop_caches: %v", err)
		}
		writeResponse(connection, nil)
	case firecrackerproto.MessageCheckpoint:
		var request firecrackerproto.CheckpointRequest
		if err := firecrackerproto.Decode(payload, &request); err != nil {
			writeResponse(connection, err)
			return
		}
		writeResponse(connection, releaseCheckpoint(request))
	case firecrackerproto.MessageShutdown:
		writeResponse(connection, nil)
		go powerOff()
	case firecrackerproto.MessageWait:
		handleWait(connection)
	case firecrackerproto.MessageExec, firecrackerproto.MessageExecTTY:
		var request firecrackerproto.ExecRequest
		if err := firecrackerproto.Decode(payload, &request); err != nil {
			writeResponse(connection, err)
			return
		}
		handleExec(connection, request, messageType == firecrackerproto.MessageExecTTY)
	default:
		writeResponse(connection, fmt.Errorf("unsupported message type %d", messageType))
	}
}

func writeResponse(w io.Writer, err error) {
	response := firecrackerproto.Response{OK: err == nil}
	if err != nil {
		response.Error = err.Error()
	}
	if writeErr := firecrackerproto.WriteMessage(
		w,
		firecrackerproto.MessageResponse,
		response,
	); writeErr != nil {
		log.Printf("write agent response: %v", writeErr)
	}
}

func handleWait(connection io.Writer) {
	state.mu.RLock()
	if !state.configured || state.mainDone == nil {
		state.mu.RUnlock()
		writeResponse(connection, errors.New("sandbox is not configured"))
		return
	}
	done := state.mainDone
	state.mu.RUnlock()
	<-done
	state.mu.RLock()
	exitCode := state.mainExit
	state.mu.RUnlock()
	if err := firecrackerproto.WriteMessage(
		connection,
		firecrackerproto.MessageResponse,
		firecrackerproto.Response{OK: true, ExitCode: &exitCode},
	); err != nil {
		log.Printf("write wait response: %v", err)
	}
}

func configure(request firecrackerproto.ConfigureRequest) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.configured {
		return errors.New("sandbox is already configured")
	}
	if request.RootDevice == "" || request.OverlayDevice == "" {
		return errors.New("root and overlay block devices are required")
	}
	if len(request.Process.Args) == 0 {
		return errors.New("sandbox command is empty")
	}
	for _, path := range []string{
		containerRoot,
		containerLower,
		containerOverlay,
		filepath.Join(containerOverlay, "upper"),
		filepath.Join(containerOverlay, "work"),
	} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}
	if err := unix.Mount(
		request.RootDevice,
		containerLower,
		"erofs",
		unix.MS_RDONLY|unix.MS_NODEV,
		"",
	); err != nil {
		return fmt.Errorf("mount root EROFS %s: %w", request.RootDevice, err)
	}
	if err := unix.Mount(
		request.OverlayDevice,
		containerOverlay,
		"ext4",
		unix.MS_NODEV,
		"",
	); err != nil {
		return fmt.Errorf("mount writable layer %s: %w", request.OverlayDevice, err)
	}
	upper := filepath.Join(containerOverlay, "upper")
	work := filepath.Join(containerOverlay, "work")
	if err := os.MkdirAll(upper, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(work, 0755); err != nil {
		return err
	}
	overlayData := fmt.Sprintf(
		"lowerdir=%s,upperdir=%s,workdir=%s",
		containerLower,
		upper,
		work,
	)
	if err := unix.Mount(
		"overlay",
		containerRoot,
		"overlay",
		unix.MS_NODEV,
		overlayData,
	); err != nil {
		return fmt.Errorf("mount root overlay: %w", err)
	}

	for _, mount := range request.Mounts {
		if _, err := ensureContainerDirectory(mount.Target); err != nil {
			return fmt.Errorf("create mount target %s: %w", mount.Target, err)
		}
	}
	for _, mount := range request.NativeWritableMounts {
		if _, err := ensureContainerDirectory(mount.Target); err != nil {
			return fmt.Errorf(
				"create native writable mount target %s: %w",
				mount.Target,
				err,
			)
		}
	}
	for _, file := range request.Files {
		if err := injectFile(file); err != nil {
			return err
		}
	}
	if err := mountRuntimeFilesystems(); err != nil {
		return err
	}
	for _, mount := range request.Mounts {
		if err := mountGuestFilesystem(mount); err != nil {
			return err
		}
	}
	for index, mount := range request.NativeWritableMounts {
		if err := mountNativeWritable(index, mount); err != nil {
			return err
		}
	}
	if request.RootReadonly {
		if err := unix.Mount(
			"",
			containerRoot,
			"",
			unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NODEV,
			"",
		); err != nil {
			return fmt.Errorf("remount sandbox root read-only: %w", err)
		}
	}
	if err := configureNetwork(request.Network); err != nil {
		return err
	}
	handoff, err := prepareCheckpointHandoff(
		containerRoot,
		request.Process.Env,
	)
	if err != nil {
		return fmt.Errorf("prepare checkpoint handoff: %w", err)
	}
	command, err := startSandboxProcess(request.Hostname, request.Process)
	if err != nil {
		handoff.close()
		return fmt.Errorf("start sandbox process: %w", err)
	}
	state.process = request.Process
	state.mainPID = command.Process.Pid
	state.handoff = handoff
	state.configured = true
	state.mainDone = make(chan struct{})
	go waitMainProcess(command, state.mainDone)
	log.Printf("started sandbox process pid=%d command=%q", command.Process.Pid, request.Process.Args)
	return nil
}

type sandboxInitRequest struct {
	Executable string                       `json:"executable"`
	Hostname   string                       `json:"hostname,omitempty"`
	Process    firecrackerproto.ProcessSpec `json:"process"`
}

func startSandboxProcess(
	hostname string,
	process firecrackerproto.ProcessSpec,
) (*exec.Cmd, error) {
	if len(process.Args) == 0 {
		return nil, errors.New("sandbox command is empty")
	}
	executable, err := resolveExecutable(process.Args[0], process.Env)
	if err != nil {
		return nil, err
	}
	configReader, configWriter, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create sandbox init config pipe: %w", err)
	}
	defer configWriter.Close()
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		configReader.Close()
		return nil, fmt.Errorf("create sandbox init status pipe: %w", err)
	}
	defer statusReader.Close()

	command := sandboxInitCommand(configReader, statusWriter)
	if err := command.Start(); err != nil {
		configReader.Close()
		statusWriter.Close()
		return nil, err
	}
	configReader.Close()
	statusWriter.Close()

	request := sandboxInitRequest{
		Executable: executable,
		Hostname:   hostname,
		Process:    process,
	}
	writeErr := firecrackerproto.WriteMessage(
		configWriter,
		firecrackerproto.MessageConfigure,
		request,
	)
	closeErr := configWriter.Close()
	status, statusErr := io.ReadAll(statusReader)
	if writeErr != nil || closeErr != nil || statusErr != nil || len(status) != 0 {
		_ = command.Process.Kill()
		_ = command.Wait()
		switch {
		case writeErr != nil:
			return nil, fmt.Errorf("send sandbox init config: %w", writeErr)
		case closeErr != nil:
			return nil, fmt.Errorf("close sandbox init config: %w", closeErr)
		case statusErr != nil:
			return nil, fmt.Errorf("read sandbox init status: %w", statusErr)
		default:
			return nil, errors.New(string(status))
		}
	}
	return command, nil
}

func sandboxInitCommand(configReader, statusWriter *os.File) *exec.Cmd {
	return &exec.Cmd{
		Path:       "/init",
		Args:       []string{"/init", sandboxInitMode},
		Env:        []string{},
		Dir:        "/",
		Stdin:      nil,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		ExtraFiles: []*os.File{configReader, statusWriter},
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags: unix.CLONE_NEWNS |
				unix.CLONE_NEWPID |
				unix.CLONE_NEWUTS |
				unix.CLONE_NEWIPC,
			Setpgid: true,
		},
	}
}

func runSandboxInit() error {
	// Credential changes and exec apply to the calling thread. Keep the whole
	// bootstrap sequence on one OS thread until exec replaces the Go process.
	goruntime.LockOSThread()
	if os.Getpid() != 1 {
		return fmt.Errorf("sandbox init is PID %d, want PID 1", os.Getpid())
	}
	unix.CloseOnExec(sandboxStatusFD)
	config := os.NewFile(sandboxConfigFD, "sandbox-init-config")
	if config == nil {
		return errors.New("sandbox init config fd is unavailable")
	}
	messageType, payload, err := firecrackerproto.ReadMessage(config)
	config.Close()
	if err != nil {
		return fmt.Errorf("read sandbox init config: %w", err)
	}
	if messageType != firecrackerproto.MessageConfigure {
		return fmt.Errorf("unexpected sandbox init config type %d", messageType)
	}
	var request sandboxInitRequest
	if err := firecrackerproto.Decode(payload, &request); err != nil {
		return err
	}
	if request.Executable == "" || len(request.Process.Args) == 0 {
		return errors.New("sandbox init command is empty")
	}
	if request.Hostname != "" {
		if err := unix.Sethostname([]byte(request.Hostname)); err != nil {
			return fmt.Errorf("set sandbox hostname: %w", err)
		}
	}
	if err := switchContainerRoot(containerRoot, systemRootSwitchOperations); err != nil {
		return fmt.Errorf("switch to sandbox root: %w", err)
	}
	if err := remountSandboxProc(); err != nil {
		return err
	}
	workingDirectory := request.Process.Cwd
	if workingDirectory == "" {
		workingDirectory = "/"
	}
	if err := unix.Chdir(workingDirectory); err != nil {
		return fmt.Errorf("change sandbox directory to %s: %w", workingDirectory, err)
	}
	groups := make([]int, len(request.Process.AdditionalGIDs))
	for index, group := range request.Process.AdditionalGIDs {
		groups[index] = int(group)
	}
	if err := unix.Setgroups(groups); err != nil {
		return fmt.Errorf("set sandbox supplementary groups: %w", err)
	}
	if err := unix.Setresgid(
		int(request.Process.GID),
		int(request.Process.GID),
		int(request.Process.GID),
	); err != nil {
		return fmt.Errorf("set sandbox gid: %w", err)
	}
	if err := unix.Setresuid(
		int(request.Process.UID),
		int(request.Process.UID),
		int(request.Process.UID),
	); err != nil {
		return fmt.Errorf("set sandbox uid: %w", err)
	}
	unix.Umask(0022)
	return unix.Exec(
		request.Executable,
		append([]string(nil), request.Process.Args...),
		append([]string(nil), request.Process.Env...),
	)
}

func reportSandboxInitError(err error) {
	status := os.NewFile(sandboxStatusFD, "sandbox-init-status")
	if status == nil {
		return
	}
	defer status.Close()
	_, _ = io.WriteString(status, err.Error())
}

func remountSandboxProc() error {
	if err := unix.Unmount("/proc", unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("unmount inherited procfs: %w", err)
	}
	if err := unix.Mount(
		"proc",
		"/proc",
		"proc",
		unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV,
		"",
	); err != nil {
		return fmt.Errorf("mount sandbox procfs: %w", err)
	}
	return nil
}

func switchContainerRoot(root string, operations rootSwitchOperations) error {
	if root == "" || root == "/" {
		return fmt.Errorf("new root %q must identify a mounted child filesystem", root)
	}
	if err := operations.mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make root mount private: %w", err)
	}
	rootFD, err := operations.open(root, unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open new root %s: %w", root, err)
	}
	defer operations.close(rootFD)
	if err := operations.mount(root, "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move new root %s: %w", root, err)
	}
	if err := operations.fchdir(rootFD); err != nil {
		return fmt.Errorf("enter new root %s: %w", root, err)
	}
	if err := operations.chroot("."); err != nil {
		return fmt.Errorf("chroot to new root %s: %w", root, err)
	}
	if err := operations.chdir("/"); err != nil {
		return fmt.Errorf("change directory to new root: %w", err)
	}
	return nil
}

func prepareCheckpointHandoff(
	root string,
	environment []string,
) (*checkpointHandoff, error) {
	fifoPath := filepath.Join(
		root,
		strings.TrimPrefix(firecrackerproto.CheckpointHandoffPath, "/"),
	)
	environmentPath := filepath.Join(
		root,
		strings.TrimPrefix(firecrackerproto.RestoreEnvPath, "/"),
	)
	if err := os.MkdirAll(filepath.Dir(fifoPath), 0755); err != nil {
		return nil, err
	}
	if err := replaceCheckpointFIFO(fifoPath); err != nil {
		return nil, err
	}
	if err := writeCheckpointEnvironment(environmentPath, environment); err != nil {
		_ = os.Remove(fifoPath)
		return nil, err
	}
	handoff := &checkpointHandoff{
		fifoPath:        fifoPath,
		environmentPath: environmentPath,
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}
	go handoff.serve()
	return handoff, nil
}

func replaceCheckpointFIFO(path string) error {
	replacement := path + ".next"
	if err := os.Remove(replacement); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := unix.Mkfifo(replacement, 0600); err != nil {
		return err
	}
	if err := os.Rename(replacement, path); err != nil {
		_ = os.Remove(replacement)
		return err
	}
	return nil
}

func writeCheckpointEnvironment(path string, environment []string) error {
	for _, entry := range environment {
		if strings.IndexByte(entry, 0) >= 0 {
			return errors.New("checkpoint environment contains a NUL byte")
		}
	}
	content := []byte(strings.Join(environment, "\x00"))
	if len(content) != 0 {
		content = append(content, 0)
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (handoff *checkpointHandoff) serve() {
	defer close(handoff.done)
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	lastOpenError := ""
	for {
		file, generation, err := handoff.openWriter()
		if err != nil {
			if message := err.Error(); message != lastOpenError {
				log.Printf("open checkpoint handoff: %v", err)
				lastOpenError = message
			}
			select {
			case <-handoff.stop:
				return
			case <-retry.C:
				continue
			}
		}
		lastOpenError = ""
		if file == nil {
			select {
			case <-handoff.stop:
				return
			case <-retry.C:
				continue
			}
		}
		select {
		case outcome := <-generation:
			// Publish the next FIFO inode before completing this generation.
			// New readers cannot attach to the old inode while its current
			// reader is consuming the outcome and waiting for EOF.
			if err := replaceCheckpointFIFO(handoff.fifoPath); err != nil {
				log.Printf("replace checkpoint handoff: %v", err)
				_ = file.Close()
				return
			}
			if _, err := io.WriteString(file, outcome+"\n"); err != nil {
				log.Printf("write checkpoint handoff: %v", err)
			}
			if err := file.Close(); err != nil {
				log.Printf("close checkpoint handoff: %v", err)
			}
		case <-handoff.stop:
			handoff.clearReader(generation)
			_ = file.Close()
			return
		}
	}
}

func (handoff *checkpointHandoff) openWriter() (*os.File, chan string, error) {
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed {
		return nil, nil, nil
	}
	fd, err := unix.Open(
		handoff.fifoPath,
		unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, unix.ENXIO) || errors.Is(err, unix.EINTR) {
		return nil, nil, nil
	}
	if errors.Is(err, unix.ENOENT) {
		if err := replaceCheckpointFIFO(handoff.fifoPath); err != nil {
			return nil, nil, fmt.Errorf("recreate checkpoint handoff: %w", err)
		}
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	generation := make(chan string, 1)
	if handoff.pendingRestore {
		handoff.pendingRestore = false
		generation <- "restore"
	} else {
		handoff.reader = generation
	}
	return os.NewFile(uintptr(fd), handoff.fifoPath), generation, nil
}

func (handoff *checkpointHandoff) clearReader(generation chan string) {
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.reader == generation {
		handoff.reader = nil
	}
}

func (handoff *checkpointHandoff) signal(outcome string) error {
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed {
		log.Printf("drop checkpoint handoff outcome %q: handoff is closed", outcome)
		return nil
	}
	if handoff.reader == nil {
		if outcome == "restore" {
			handoff.pendingRestore = true
			log.Printf("defer checkpoint handoff outcome %q until a reader registers", outcome)
			return nil
		}
		log.Printf("drop checkpoint handoff outcome %q: no reader registered", outcome)
		return nil
	}
	generation := handoff.reader
	handoff.reader = nil
	generation <- outcome
	return nil
}

func (handoff *checkpointHandoff) close() {
	handoff.stopOnce.Do(func() {
		handoff.mu.Lock()
		handoff.closed = true
		close(handoff.stop)
		handoff.mu.Unlock()
	})
	<-handoff.done
}

func releaseCheckpoint(request firecrackerproto.CheckpointRequest) error {
	if request.Outcome != "resume" && request.Outcome != "restore" && request.Outcome != "error" {
		return fmt.Errorf("invalid checkpoint outcome %q", request.Outcome)
	}
	state.mu.RLock()
	handoff := state.handoff
	state.mu.RUnlock()
	if handoff == nil {
		return errors.New("checkpoint handoff is not configured")
	}
	if request.Outcome == "restore" {
		if err := writeCheckpointEnvironment(handoff.environmentPath, request.Environment); err != nil {
			return fmt.Errorf("write restored checkpoint environment: %w", err)
		}
	}
	return handoff.signal(request.Outcome)
}

func mountRuntimeFilesystems() error {
	mounts := []struct {
		source string
		target string
		fsType string
		flags  uintptr
		data   string
	}{
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755"},
		{"devpts", "/dev/pts", "devpts", unix.MS_NOSUID | unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"},
		{"tmpfs", "/dev/shm", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=1777"},
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, ""},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, ""},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, ""},
		{"tmpfs", "/run", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=0755"},
		{"tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=1777"},
	}
	for _, mount := range mounts {
		target, err := ensureContainerDirectory(mount.target)
		if err != nil {
			return err
		}
		if err := mountIfNeeded(mount.source, target, mount.fsType, mount.flags, mount.data); err != nil {
			return fmt.Errorf("mount %s at %s: %w", mount.fsType, target, err)
		}
	}
	ptmx := filepath.Join(containerRoot, "dev/ptmx")
	if err := os.Remove(ptmx); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink("pts/ptmx", ptmx); err != nil {
		return fmt.Errorf("create ptmx symlink: %w", err)
	}
	return nil
}

func mountIfNeeded(source, target, fsType string, flags uintptr, data string) error {
	err := unix.Mount(source, target, fsType, flags, data)
	if errors.Is(err, unix.EBUSY) {
		return nil
	}
	return err
}

func mountGuestFilesystem(mount firecrackerproto.MountSpec) error {
	switch mount.FSType {
	case "erofs":
		return mountGuestEROFS(mount)
	case "tmpfs":
		return mountGuestTmpfs(mount)
	default:
		return fmt.Errorf(
			"unsupported guest mount device=%q fs=%q",
			mount.Device,
			mount.FSType,
		)
	}
}

func mountNativeWritable(
	index int,
	mount firecrackerproto.NativeWritableMountSpec,
) error {
	return mountNativeWritableUnder(
		containerNative,
		containerRoot,
		index,
		mount,
		unix.Mount,
	)
}

func mountNativeWritableUnder(
	sourceRoot,
	root string,
	index int,
	mount firecrackerproto.NativeWritableMountSpec,
	mountFn func(string, string, string, uintptr, string) error,
) error {
	if index < 0 {
		return fmt.Errorf("native writable mount index %d is negative", index)
	}
	source := filepath.Join(sourceRoot, strconv.Itoa(index))
	if err := os.MkdirAll(source, 0755); err != nil {
		return fmt.Errorf("create native writable mount source %s: %w", source, err)
	}
	target, err := ensureContainerDirectoryUnder(root, mount.Target)
	if err != nil {
		return err
	}
	if err := mountFn(source, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf(
			"bind native writable mount %s at %s: %w",
			source,
			mount.Target,
			err,
		)
	}
	return nil
}

func mountGuestEROFS(mount firecrackerproto.MountSpec) error {
	if mount.Device == "" {
		return errors.New("EROFS guest mount device is empty")
	}
	target, err := ensureContainerDirectory(mount.Target)
	if err != nil {
		return err
	}
	flags := uintptr(unix.MS_RDONLY | unix.MS_NODEV)
	for _, option := range mount.Options {
		switch option {
		case "ro", "loop":
		case "nodev":
			flags |= unix.MS_NODEV
		case "noexec":
			flags |= unix.MS_NOEXEC
		case "nosuid":
			flags |= unix.MS_NOSUID
		default:
			return fmt.Errorf("unsupported EROFS mount option %q", option)
		}
	}
	if err := unix.Mount(mount.Device, target, "erofs", flags, ""); err != nil {
		return fmt.Errorf("mount EROFS %s at %s: %w", mount.Device, mount.Target, err)
	}
	return nil
}

func mountGuestTmpfs(mount firecrackerproto.MountSpec) error {
	if mount.Device != "" {
		return fmt.Errorf("tmpfs guest mount has unexpected device %q", mount.Device)
	}
	target, err := ensureContainerDirectory(mount.Target)
	if err != nil {
		return err
	}
	flags, data, err := firecrackerTmpfsParameters(mount.Options)
	if err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", target, "tmpfs", flags, data); err != nil {
		return fmt.Errorf("mount tmpfs at %s: %w", mount.Target, err)
	}
	return nil
}

func firecrackerTmpfsParameters(options []string) (uintptr, string, error) {
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV)
	data := make([]string, 0, len(options))
	for _, option := range options {
		switch option {
		case "ro":
			flags |= unix.MS_RDONLY
		case "rw":
			flags &^= unix.MS_RDONLY
		case "nodev":
			flags |= unix.MS_NODEV
		case "dev":
			flags &^= unix.MS_NODEV
		case "noexec":
			flags |= unix.MS_NOEXEC
		case "exec":
			flags &^= unix.MS_NOEXEC
		case "nosuid":
			flags |= unix.MS_NOSUID
		case "suid":
			flags &^= unix.MS_NOSUID
		default:
			key, value, found := strings.Cut(option, "=")
			if !found || value == "" {
				return 0, "", fmt.Errorf("unsupported tmpfs option %q", option)
			}
			switch key {
			case "size", "mode", "uid", "gid", "nr_inodes":
				data = append(data, option)
			default:
				return 0, "", fmt.Errorf("unsupported tmpfs option %q", option)
			}
		}
	}
	return flags, strings.Join(data, ","), nil
}

func injectFile(file firecrackerproto.FileSpec) error {
	if len(file.Content) > 1<<20 {
		return fmt.Errorf("injected file %s exceeds 1 MiB", file.Target)
	}
	target, err := prepareContainerFile(file.Target)
	if err != nil {
		return err
	}
	mode := os.FileMode(file.Mode & 0777)
	if mode == 0 {
		mode = 0644
	}
	fd, err := unix.Open(
		target,
		unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		uint32(mode),
	)
	if err != nil {
		return fmt.Errorf("open injected file %s: %w", file.Target, err)
	}
	output := os.NewFile(uintptr(fd), target)
	if err := output.Chmod(mode); err != nil {
		output.Close()
		return fmt.Errorf("set injected file mode %s: %w", file.Target, err)
	}
	if _, err := output.Write(file.Content); err != nil {
		output.Close()
		return fmt.Errorf("inject file %s: %w", file.Target, err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close injected file %s: %w", file.Target, err)
	}
	if file.Readonly {
		if err := unix.Mount(target, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind injected file %s: %w", file.Target, err)
		}
		if err := unix.Mount(
			"", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "",
		); err != nil {
			return fmt.Errorf("remount injected file %s read-only: %w", file.Target, err)
		}
	}
	return nil
}

func containerPath(target string) (string, error) {
	return containerPathUnder(containerRoot, target)
}

func containerPathUnder(root, target string) (string, error) {
	if !filepath.IsAbs(target) {
		return "", fmt.Errorf("guest target %q is not absolute", target)
	}
	clean := filepath.Clean(target)
	if clean == "/" {
		return "", errors.New("guest target cannot replace root")
	}
	resolved := filepath.Join(root, strings.TrimPrefix(clean, "/"))
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", fmt.Errorf("guest target %q escapes the sandbox root", target)
	}
	return resolved, nil
}

func ensureContainerDirectory(target string) (string, error) {
	return ensureContainerDirectoryUnder(containerRoot, target)
}

func ensureContainerDirectoryUnder(root, target string) (string, error) {
	resolved, err := containerPathUnder(root, target)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil {
		return "", err
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0755); err != nil {
				return "", err
			}
			continue
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf(
				"guest target %q traverses symlink %s",
				target,
				current,
			)
		}
		if !info.IsDir() {
			return "", fmt.Errorf(
				"guest directory target %q contains non-directory %s",
				target,
				current,
			)
		}
	}
	return resolved, nil
}

func prepareContainerFile(target string) (string, error) {
	return prepareContainerFileUnder(containerRoot, target)
}

func prepareContainerFileUnder(root, target string) (string, error) {
	resolved, err := containerPathUnder(root, target)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(strings.TrimPrefix(filepath.Clean(target), "/"))
	if parent != "." {
		if _, err := ensureContainerDirectoryUnder(
			root,
			"/"+filepath.ToSlash(parent),
		); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(resolved)
	if os.IsNotExist(err) {
		return resolved, nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(resolved); err != nil {
			return "", err
		}
		return resolved, nil
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("guest file target %q is not a regular file", target)
	}
	return resolved, nil
}

func reconfigureNetwork(networkSpec firecrackerproto.NetworkSpec) error {
	state.mu.RLock()
	configured := state.configured
	state.mu.RUnlock()
	if !configured {
		return errors.New("sandbox is not configured")
	}
	return configureNetwork(networkSpec)
}

func configureNetwork(networkSpec firecrackerproto.NetworkSpec) error {
	name := networkSpec.Interface
	if name == "" {
		name = "eth0"
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find guest interface %s: %w", name, err)
	}
	if networkSpec.MAC != "" {
		hardwareAddr, err := net.ParseMAC(networkSpec.MAC)
		if err != nil {
			return fmt.Errorf("parse guest MAC: %w", err)
		}
		if err := netlink.LinkSetHardwareAddr(link, hardwareAddr); err != nil {
			return fmt.Errorf("set guest MAC: %w", err)
		}
	}
	ip := net.ParseIP(networkSpec.Address).To4()
	maskIP := net.ParseIP(networkSpec.Netmask).To4()
	if ip == nil || maskIP == nil {
		return fmt.Errorf(
			"invalid guest IPv4 address %q or mask %q",
			networkSpec.Address,
			networkSpec.Netmask,
		)
	}
	ones, bits := net.IPMask(maskIP).Size()
	if bits != 32 {
		return fmt.Errorf("invalid guest IPv4 netmask %q", networkSpec.Netmask)
	}
	address, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", ip, ones))
	if err != nil {
		return err
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list guest IPv4 addresses: %w", err)
	}
	for index := range addresses {
		existing := addresses[index]
		if err := netlink.AddrDel(link, &existing); err != nil {
			return fmt.Errorf(
				"remove old guest address %s: %w",
				existing.String(),
				err,
			)
		}
	}
	if err := netlink.AddrReplace(link, address); err != nil {
		return fmt.Errorf("set guest address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring guest interface up: %w", err)
	}
	gateway := net.ParseIP(networkSpec.Gateway).To4()
	if gateway == nil {
		return fmt.Errorf("invalid guest gateway %q", networkSpec.Gateway)
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        gateway,
	}); err != nil {
		return fmt.Errorf("set guest default route: %w", err)
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find guest loopback: %w", err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		return fmt.Errorf("bring guest loopback up: %w", err)
	}
	return nil
}

func waitMainProcess(command *exec.Cmd, done chan struct{}) {
	err := command.Wait()
	exitCode := processExitCode(err)
	state.mu.Lock()
	state.mainExit = exitCode
	close(done)
	state.mu.Unlock()
	log.Printf("sandbox process exited: code=%d err=%v", exitCode, err)
}

func powerOff() {
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		log.Printf("power off guest: %v", err)
	}
}

func startCommandInSandbox(mainPID int, command *exec.Cmd) error {
	started := make(chan error, 1)
	go func() {
		// Namespace membership is per-thread. The goroutine deliberately never
		// unlocks this thread: after Start returns, the goroutine exits and the Go
		// runtime terminates the namespace-tainted OS thread.
		goruntime.LockOSThread()
		if err := joinSandboxNamespaces(
			mainPID,
			systemNamespaceOperations,
		); err != nil {
			started <- err
			return
		}
		started <- command.Start()
	}()
	return <-started
}

func joinSandboxNamespaces(mainPID int, operations namespaceOperations) error {
	if mainPID <= 0 {
		return fmt.Errorf("invalid sandbox init PID %d", mainPID)
	}
	// setns(CLONE_NEWNS) rejects a caller that shares CLONE_FS state. The
	// locked worker thread gets a private fs_struct before entering the mount
	// namespace and is terminated instead of being returned to the Go runtime.
	if err := operations.unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("unshare exec filesystem state: %w", err)
	}
	type namespaceFD struct {
		sandboxNamespace
		fd int
	}
	fds := make([]namespaceFD, 0, len(sandboxNamespaces))
	defer func() {
		for _, namespace := range fds {
			_ = operations.close(namespace.fd)
		}
	}()
	for _, namespace := range sandboxNamespaces {
		path := fmt.Sprintf("/proc/%d/ns/%s", mainPID, namespace.name)
		fd, err := operations.open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open sandbox %s namespace: %w", namespace.name, err)
		}
		fds = append(fds, namespaceFD{sandboxNamespace: namespace, fd: fd})
	}
	for _, namespace := range fds {
		if err := operations.setns(namespace.fd, namespace.flag); err != nil {
			return fmt.Errorf("join sandbox %s namespace: %w", namespace.name, err)
		}
	}
	return nil
}

func handleExec(connection *os.File, request firecrackerproto.ExecRequest, tty bool) {
	state.mu.RLock()
	if !state.configured {
		state.mu.RUnlock()
		writeResponse(connection, errors.New("sandbox is not configured"))
		return
	}
	base := state.process
	mainPID := state.mainPID
	done := state.mainDone
	state.mu.RUnlock()
	select {
	case <-done:
		writeResponse(connection, errors.New("sandbox process has exited"))
		return
	default:
	}

	process, err := execProcessSpec(base, request)
	if err != nil {
		writeResponse(connection, err)
		return
	}
	command, err := sandboxCommand(process)
	if err != nil {
		writeResponse(connection, err)
		return
	}
	if tty {
		runTTYExec(connection, command, request, mainPID)
		return
	}
	runPipeExec(connection, command, mainPID)
}

func runPipeExec(connection *os.File, command *exec.Cmd, mainPID int) {
	stdin, err := command.StdinPipe()
	if err != nil {
		writeResponse(connection, err)
		return
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		writeResponse(connection, err)
		return
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		writeResponse(connection, err)
		return
	}
	if err := startCommandInSandbox(mainPID, command); err != nil {
		writeResponse(connection, err)
		return
	}
	writeResponse(connection, nil)

	var writeMu sync.Mutex
	var output sync.WaitGroup
	copyOutput := func(frameType firecrackerproto.FrameType, reader io.Reader) {
		defer output.Done()
		buffer := make([]byte, 32<<10)
		for {
			count, readErr := reader.Read(buffer)
			if count > 0 {
				writeMu.Lock()
				writeErr := firecrackerproto.WriteFrame(connection, frameType, buffer[:count])
				writeMu.Unlock()
				if writeErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}
	output.Add(2)
	go copyOutput(firecrackerproto.FrameData, stdout)
	go copyOutput(firecrackerproto.FrameStderr, stderr)
	inputDone := make(chan struct{})
	go forwardInput(connection, stdin, command.Process.Pid, nil, inputDone)

	output.Wait()
	waitErr := command.Wait()
	close(inputDone)
	_ = stdin.Close()
	writeMu.Lock()
	_ = firecrackerproto.WriteFrame(
		connection,
		firecrackerproto.FrameExit,
		firecrackerproto.ExitPayload(processExitCode(waitErr)),
	)
	writeMu.Unlock()
}

func runTTYExec(
	connection *os.File,
	command *exec.Cmd,
	request firecrackerproto.ExecRequest,
	mainPID int,
) {
	master, slave, err := openPTY(request.Rows, request.Cols)
	if err != nil {
		writeResponse(connection, err)
		return
	}
	defer master.Close()
	command.Stdin = slave
	command.Stdout = slave
	command.Stderr = slave
	command.SysProcAttr.Setsid = true
	command.SysProcAttr.Setpgid = false
	command.SysProcAttr.Setctty = true
	command.SysProcAttr.Ctty = 0
	if err := startCommandInSandbox(mainPID, command); err != nil {
		slave.Close()
		writeResponse(connection, err)
		return
	}
	slave.Close()
	writeResponse(connection, nil)

	var writeMu sync.Mutex
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		buffer := make([]byte, 32<<10)
		for {
			count, readErr := master.Read(buffer)
			if count > 0 {
				writeMu.Lock()
				writeErr := firecrackerproto.WriteFrame(
					connection,
					firecrackerproto.FrameData,
					buffer[:count],
				)
				writeMu.Unlock()
				if writeErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()
	inputDone := make(chan struct{})
	go forwardInput(connection, master, command.Process.Pid, master, inputDone)

	waitErr := command.Wait()
	close(inputDone)
	_ = master.Close()
	<-outputDone
	writeMu.Lock()
	_ = firecrackerproto.WriteFrame(
		connection,
		firecrackerproto.FrameExit,
		firecrackerproto.ExitPayload(processExitCode(waitErr)),
	)
	writeMu.Unlock()
}

func forwardInput(
	connection io.Reader,
	stdin io.WriteCloser,
	processID int,
	terminal *os.File,
	done <-chan struct{},
) {
	for {
		frameType, payload, err := firecrackerproto.ReadFrame(connection)
		if err != nil {
			_ = stdin.Close()
			select {
			case <-done:
				return
			default:
			}
			_ = unix.Kill(-processID, unix.SIGKILL)
			return
		}
		switch frameType {
		case firecrackerproto.FrameData:
			if _, err := stdin.Write(payload); err != nil {
				return
			}
		case firecrackerproto.FrameEOF:
			finishExecInput(stdin, terminal != nil)
			return
		case firecrackerproto.FrameResize:
			if terminal == nil {
				continue
			}
			rows, cols, err := firecrackerproto.Resize(payload)
			if err == nil {
				_ = unix.IoctlSetWinsize(
					int(terminal.Fd()),
					unix.TIOCSWINSZ,
					&unix.Winsize{Row: rows, Col: cols},
				)
			}
		case firecrackerproto.FrameSignal:
			signal, err := firecrackerproto.Signal(payload)
			if err == nil && signal > 0 {
				_ = unix.Kill(-processID, syscall.Signal(signal))
			}
		}
	}
}

func finishExecInput(stdin io.WriteCloser, terminal bool) {
	if terminal {
		// Closing a PTY master sends SIGHUP to its controlling session.
		// Send the terminal EOF character instead and let Wait report the
		// process's own exit status.
		_, _ = stdin.Write([]byte{4})
		return
	}
	_ = stdin.Close()
}

func openPTY(rows, cols uint16) (*os.File, *os.File, error) {
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}
	masterFD, err := unix.Open(
		filepath.Join(containerRoot, "dev/ptmx"),
		unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open ptmx: %w", err)
	}
	closeMaster := true
	defer func() {
		if closeMaster {
			unix.Close(masterFD)
		}
	}()
	if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, fmt.Errorf("unlock pty: %w", err)
	}
	number, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("read pty number: %w", err)
	}
	slave, err := os.OpenFile(
		filepath.Join(containerRoot, "dev/pts", strconv.Itoa(number)),
		os.O_RDWR|syscall.O_NOCTTY,
		0,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open pty slave: %w", err)
	}
	if err := unix.IoctlSetWinsize(
		masterFD,
		unix.TIOCSWINSZ,
		&unix.Winsize{Row: rows, Col: cols},
	); err != nil {
		slave.Close()
		return nil, nil, err
	}
	closeMaster = false
	return os.NewFile(uintptr(masterFD), "ptmx"), slave, nil
}

func execProcessSpec(
	base firecrackerproto.ProcessSpec,
	request firecrackerproto.ExecRequest,
) (firecrackerproto.ProcessSpec, error) {
	if request.Command == "" {
		return firecrackerproto.ProcessSpec{}, errors.New("exec command is empty")
	}
	result := base
	result.Args = append([]string{request.Command}, request.Args...)
	result.Env = mergeEnvironment(base.Env, request.Env)
	if request.Cwd != "" {
		result.Cwd = request.Cwd
	}
	if request.User != "" {
		uid, gid, err := resolveUser(request.User)
		if err != nil {
			return firecrackerproto.ProcessSpec{}, err
		}
		result.UID = uid
		result.GID = gid
		result.AdditionalGIDs = nil
	}
	return result, nil
}

func resolveUser(value string) (uint32, uint32, error) {
	parts := strings.SplitN(value, ":", 2)
	uid, gid, err := resolvePasswdIdentity(parts[0])
	if err != nil {
		return 0, 0, err
	}
	if len(parts) == 2 {
		gid, err = resolveGroupIdentity(parts[1])
		if err != nil {
			return 0, 0, err
		}
	}
	return uid, gid, nil
}

func resolvePasswdIdentity(value string) (uint32, uint32, error) {
	if numeric, err := strconv.ParseUint(value, 10, 32); err == nil {
		return uint32(numeric), uint32(numeric), nil
	}
	file, err := os.Open(filepath.Join(containerRoot, "etc/passwd"))
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 4 || fields[0] != value {
			continue
		}
		uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
		gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
		if uidErr == nil && gidErr == nil {
			return uint32(uid), uint32(gid), nil
		}
	}
	return 0, 0, fmt.Errorf("unknown sandbox user %q", value)
}

func resolveGroupIdentity(value string) (uint32, error) {
	if numeric, err := strconv.ParseUint(value, 10, 32); err == nil {
		return uint32(numeric), nil
	}
	file, err := os.Open(filepath.Join(containerRoot, "etc/group"))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 || fields[0] != value {
			continue
		}
		gid, parseErr := strconv.ParseUint(fields[2], 10, 32)
		if parseErr == nil {
			return uint32(gid), nil
		}
	}
	return 0, fmt.Errorf("unknown sandbox group %q", value)
}

func sandboxCommand(process firecrackerproto.ProcessSpec) (*exec.Cmd, error) {
	if len(process.Args) == 0 {
		return nil, errors.New("sandbox command is empty")
	}
	path, err := resolveExecutable(process.Args[0], process.Env)
	if err != nil {
		return nil, err
	}
	command := &exec.Cmd{
		Path: path,
		Args: append([]string(nil), process.Args...),
		Env:  append([]string(nil), process.Env...),
		Dir:  process.Cwd,
	}
	if command.Dir == "" {
		command.Dir = "/"
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Credential: &syscall.Credential{
			Uid:    process.UID,
			Gid:    process.GID,
			Groups: append([]uint32(nil), process.AdditionalGIDs...),
		},
	}
	return command, nil
}

func resolveExecutable(command string, environment []string) (string, error) {
	if strings.ContainsRune(command, '/') {
		return command, nil
	}
	pathValue := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, entry := range environment {
		if strings.HasPrefix(entry, "PATH=") {
			pathValue = strings.TrimPrefix(entry, "PATH=")
		}
	}
	for _, directory := range filepath.SplitList(pathValue) {
		if !filepath.IsAbs(directory) {
			continue
		}
		candidate := filepath.Join(directory, command)
		info, err := os.Stat(filepath.Join(containerRoot, strings.TrimPrefix(candidate, "/")))
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("sandbox executable %q was not found in PATH", command)
}

func mergeEnvironment(base, override []string) []string {
	values := make(map[string]string, len(base)+len(override))
	for _, entry := range append(append([]string(nil), base...), override...) {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key != "" {
			values[key] = value
		}
	}
	if _, ok := values["PATH"]; !ok {
		values["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func processExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		status, ok := exitError.Sys().(syscall.WaitStatus)
		if ok {
			if status.Signaled() {
				return 128 + int(status.Signal())
			}
			return status.ExitStatus()
		}
	}
	return 255
}
