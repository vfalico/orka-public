//go:build linux

package acp

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"time"
)

type execGate struct {
	readyRead, readyWrite, releaseRead, releaseWrite *os.File
	released                                         bool
}

func prepareExecGate(cmd *exec.Cmd, cfg ProcessConfig) (*execGate, error) {
	g := &execGate{}
	if cfg.BeforeExec == nil {
		return g, nil
	}
	var err error
	g.readyRead, g.readyWrite, err = os.Pipe()
	if err != nil {
		return nil, err
	}
	g.releaseRead, g.releaseWrite, err = os.Pipe()
	if err != nil {
		g.readyRead.Close()
		g.readyWrite.Close()
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{g.readyWrite, g.releaseRead}
	// Fixed FD roles are private helper ABI; no agent environment controls them.
	cmd.Args = append(cmd.Args[:1], append([]string{"--held"}, cmd.Args[1:]...)...)
	return g, nil
}
func (g *execGate) closeParentCopies() {
	if g == nil {
		return
	}
	for _, f := range []*os.File{g.readyRead, g.readyWrite, g.releaseRead} {
		if f != nil {
			f.Close()
		}
	}
}
func (g *execGate) ready(ctx context.Context) error {
	if g.readyRead == nil {
		return fmt.Errorf("missing helper gate")
	}
	g.readyWrite.Close()
	g.releaseRead.Close()
	deadline := time.Now().Add(60 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	if err := g.readyRead.SetReadDeadline(deadline); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			g.readyRead.Close()
		case <-done:
		}
	}()
	var b [1]byte
	if _, err := io.ReadFull(g.readyRead, b[:]); err != nil {
		return fmt.Errorf("held helper readiness: %w", err)
	}
	if b[0] != 'H' {
		return fmt.Errorf("invalid helper readiness")
	}
	return nil
}
func (g *execGate) release() error {
	if g == nil || g.releaseWrite == nil || g.released {
		return fmt.Errorf("missing or already used release gate")
	}
	g.released = true
	defer g.releaseWrite.Close()
	_, err := g.releaseWrite.Write([]byte{'R'})
	return err
}
func waitExecGate(environment []string, expectedParentPID int) error {
	// parseExecHelperInvocation strips --held and records it via an explicit
	// helper-only argument flag; do not use workload-controlled environment.
	if !helperHeld {
		return nil
	}
	for _, fd := range []int{0, 1, 2} {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFSOCK {
			return fmt.Errorf("socket stdio forbidden")
		}
	}
	if err := unix.CloseRange(5, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("seal inherited descriptors: %w", err)
	}
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	ready := os.NewFile(3, "ready")
	release := os.NewFile(4, "release")
	defer ready.Close()
	defer release.Close()
	// Drop privilege acquisition and alternate socket/namespace FD acquisition.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := installExecutionSyscallFence(); err != nil {
		return err
	}
	if _, err := ready.Write([]byte{'H'}); err != nil {
		return err
	}
	var b [1]byte
	if _, err := io.ReadFull(release, b[:]); err != nil {
		return err
	}
	if b[0] != 'R' {
		return fmt.Errorf("invalid release")
	}
	if err := verifyReleasedHelperParent(expectedParentPID, os.Getppid()); err != nil {
		return err
	}
	// No inherited nonessential descriptors may reach the governed entrypoint.
	if err := unix.CloseRange(5, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err
	}
	return nil
}

var helperHeld bool

// A supervisor may legitimately be PID 1 in a private PID namespace. The
// trusted helper invocation pins its original parent before PR_SET_PDEATHSIG;
// compare that exact identity after the gate rather than guessing from PID 1.
// The already-installed parent-death signal remains the lifetime authority.
func verifyReleasedHelperParent(expected, observed int) error {
	if expected <= 0 || expected != observed {
		return fmt.Errorf("supervisor identity changed before release")
	}
	return nil
}
