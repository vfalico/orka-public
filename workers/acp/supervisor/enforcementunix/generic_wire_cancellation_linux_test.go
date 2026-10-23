//go:build linux

package enforcementunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Real AF_UNIX calls. No fake policy receipt, target or workload. An owned
// listener/filler bounds even a broken implementation without killing workers.
func TestGenericWireCancellationAtSaturatedBacklog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer")
	listener, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(listener)
	if e = unix.Bind(listener, &unix.SockaddrUnix{Name: path}); e != nil {
		t.Fatal(e)
	}
	if e = unix.Listen(listener, 0); e != nil {
		t.Fatal(e)
	}
	filler, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(filler)
	if e = unix.Connect(filler, &unix.SockaddrUnix{Name: path}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := (Connection{Socket: path}).call(ctx, "assess", "cancel-backlog", nil, nil, nil)
		done <- e
	}()
	time.Sleep(40 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("cancellation result: %v", e)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("late cancel")
		}
	case <-time.After(700 * time.Millisecond):
		// Drain the exact filler connection, allowing the blocked caller to
		// finish Connect. Then shut down its accepted peer to join Recvmsg.
		fillPeer, _, e := unix.Accept4(listener, unix.SOCK_CLOEXEC)
		if e != nil {
			t.Fatal(e)
		}
		_ = unix.Close(fillPeer)
		callerPeer, _, e := unix.Accept4(listener, unix.SOCK_CLOEXEC)
		if e != nil {
			t.Fatal(e)
		}
		_ = unix.Shutdown(callerPeer, unix.SHUT_RDWR)
		_ = unix.Close(callerPeer)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("owned Connect did not wake after listener shutdown")
		}
		t.Fatal("generic transport ignored cancellation at saturated backlog")
	}
}

func TestGenericWireCancellationWhileAwaitingReply(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-authenticated real peer")
	}
	path := filepath.Join(t.TempDir(), "peer")
	listener, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(listener)
	if e = unix.Bind(listener, &unix.SockaddrUnix{Name: path}); e != nil {
		t.Fatal(e)
	}
	if e = unix.Listen(listener, 1); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := (Connection{Socket: path}).call(ctx, "assess", "cancel-recv", nil, nil, nil)
		done <- e
	}()
	peer, _, e := unix.Accept4(listener, unix.SOCK_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(peer)
	if e = unix.SetsockoptTimeval(peer, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4096)
	if _, _, _, _, e = unix.Recvmsg(peer, b, nil, 0); e != nil {
		t.Fatal(e)
	}
	time.Sleep(40 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("cancellation result: %v", e)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("late cancel")
		}
	case <-time.After(700 * time.Millisecond):
		_ = unix.Shutdown(peer, unix.SHUT_RDWR)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("owned Recvmsg did not wake after peer shutdown")
		}
		t.Fatal("generic transport ignored cancellation while awaiting reply")
	}
}

func TestGenericWireConnectHonorsAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	e = connectContext(ctx, fd, &unix.SockaddrUnix{Name: filepath.Join(t.TempDir(), "absent")}, time.Now().Add(time.Second))
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("already cancelled Connect: %v", e)
	}
}

func TestGenericWireConnectHonorsOneDeadlineAtBacklog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer")
	listener, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(listener)
	if e = unix.Bind(listener, &unix.SockaddrUnix{Name: path}); e != nil {
		t.Fatal(e)
	}
	if e = unix.Listen(listener, 0); e != nil {
		t.Fatal(e)
	}
	filler, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(filler)
	if e = unix.Connect(filler, &unix.SockaddrUnix{Name: path}); e != nil {
		t.Fatal(e)
	}
	fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	start := time.Now()
	e = connectContext(t.Context(), fd, &unix.SockaddrUnix{Name: path}, start.Add(60*time.Millisecond))
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("deadline Connect: %v", e)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("one Connect deadline took %v", elapsed)
	}
}
