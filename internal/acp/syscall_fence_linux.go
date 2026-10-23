//go:build linux

package acp

import (
	"fmt"
	"golang.org/x/sys/unix"
	"runtime"
	"unsafe"
)

func installExecutionSyscallFence() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("governed syscall fence requires amd64")
	}
	// Deny foreign FD acquisition and asynchronous socket creation/I/O paths,
	// namespace/cgroup escapes, mount API and ptrace. Unprivileged child is
	// already capability-free with no-new-privileges; this is defense in depth.
	f := []unix.SockFilter{{Code: 0x20, K: 4}, {Code: 0x15, Jt: 1, K: unix.AUDIT_ARCH_X86_64}, {Code: 0x06, K: unix.SECCOMP_RET_KILL_PROCESS}, {Code: 0x20, K: 0}}
	denied := []uint32{unix.SYS_PIDFD_GETFD, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PROCESS_VM_READV, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_BPF, unix.SYS_MOUNT, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSMOUNT, unix.SYS_MOUNT_SETATTR}
	// x32 syscalls have a distinct ABI bit and must not bypass the filter.
	f = append(f, unix.SockFilter{Code: 0x35, Jf: 1, K: 0x40000000}, unix.SockFilter{Code: 0x06, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	for _, n := range denied {
		f = append(f, unix.SockFilter{Code: 0x15, Jf: 1, K: n}, unix.SockFilter{Code: 0x06, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	f = append(f, unix.SockFilter{Code: 0x06, K: unix.SECCOMP_RET_ALLOW})
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	_, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
	if e != 0 {
		return e
	}
	return nil
}
