//go:build linux

package enforcementunix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"golang.org/x/sys/unix"
)

const protocol = "execution-enforcement/v1"

type Connection struct{ Socket string }

func encode(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// Canonical neutral-wire JSON preserves exact integers through recovery.
func jsonMap(v any) map[string]any {
	var result map[string]any
	d := json.NewDecoder(bytes.NewReader(encode(v)))
	d.UseNumber()
	if err := d.Decode(&result); err != nil {
		panic(err)
	}
	return result
}
func digest(v any) string {
	var normalized any
	d := json.NewDecoder(bytes.NewReader(encode(v)))
	d.UseNumber()
	if err := d.Decode(&normalized); err != nil {
		panic(err)
	}
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err := e.Encode(normalized); err != nil {
		panic(err)
	}
	sum := sha256.Sum256(bytes.TrimSuffix(out.Bytes(), []byte{'\n'}))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func requirement(r *harnessv2.ExecutionRequirement) map[string]any {
	return map[string]any{"format": r.Format, "bytes": r.PolicyBytes, "capabilities": r.RequiredCapabilities, "digest": r.PayloadDigest}
}
func operation(a *association) string { return digest(a.Binding) }
func exactBound(result map[string]json.RawMessage, a *association, flag string) error {
	var ok bool
	if err := json.Unmarshal(result[flag], &ok); err != nil || !ok {
		return fmt.Errorf("enforcer did not establish %s", flag)
	}
	assoc := map[string]any{"requirement": requirement(a.Requirement), "target": a.Target}
	for k, v := range map[string]string{"operation": operation(a), "binding": digest(assoc), "requirement": digest(requirement(a.Requirement)), "target": digest(a.Target)} {
		var got string
		if err := json.Unmarshal(result[k], &got); err != nil || got != v {
			return fmt.Errorf("enforcer %s association mismatch", k)
		}
	}
	return nil
}

func (c Connection) call(ctx context.Context, method, operation string, req, target any, fds []int) (map[string]json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	// Join the cancellation callback before closing/reusing this exact fd.
	// Shutdown wakes blocking send/receive; Connect is separately nonblocking.
	cancelled := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() { _ = unix.Shutdown(fd, unix.SHUT_RDWR); close(cancelled) })
	defer func() {
		if !stopCancel() {
			<-cancelled
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, context.DeadlineExceeded
	}
	tv := unix.NsecToTimeval(remaining.Nanoseconds())
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		return nil, err
	}
	if err = connectContext(ctx, fd, &unix.SockaddrUnix{Name: c.Socket}, deadline); err != nil {
		return nil, err
	}
	peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, err
	}
	if peer.Uid != 0 {
		return nil, fmt.Errorf("untrusted enforcer peer")
	}
	data := encode(map[string]any{"version": protocol, "method": method, "operation": operation, "requirement": req, "target": target})
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("request bounds exceeded")
	}
	var rights []byte
	if len(fds) > 0 {
		rights = unix.UnixRights(fds...)
	}
	n, err := retryInterrupted(ctx, deadline, func() (int, error) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		tv := unix.NsecToTimeval(remaining.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
			return 0, err
		}
		return unix.SendmsgN(fd, data, rights, nil, 0)
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if n != len(data) {
		return nil, fmt.Errorf("short enforcer request")
	}
	buffer := make([]byte, 1<<20)
	var flags int
	n, err = retryInterrupted(ctx, deadline, func() (int, error) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		tv := unix.NsecToTimeval(remaining.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return 0, err
		}
		count, _, gotFlags, _, recvErr := unix.Recvmsg(fd, buffer, nil, 0)
		flags = gotFlags
		return count, recvErr
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return nil, fmt.Errorf("truncated enforcer reply")
	}
	var reply struct {
		Version string                     `json:"version"`
		OK      bool                       `json:"ok"`
		Error   string                     `json:"error"`
		Result  map[string]json.RawMessage `json:"result"`
	}
	if err = json.Unmarshal(buffer[:n], &reply); err != nil {
		return nil, err
	}
	if reply.Version != protocol || !reply.OK {
		return nil, fmt.Errorf("enforcer refusal: %s", reply.Error)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return reply.Result, nil
}

var _ = os.Geteuid

// Retry only a kernel-interrupted syscall on the SAME socket, never reconnect
// or resend a successfully submitted operation after an uncertain reply.
func retryInterrupted(ctx context.Context, deadline time.Time, call func() (int, error)) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if !time.Now().Before(deadline) {
			return 0, context.DeadlineExceeded
		}
		n, err := call()
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
	}
}

// Linux AF_UNIX SOCK_SEQPACKET reports EAGAIN when the listen queue is full.
// It did NOT queue an operation; retry Connect on this same socket only. No
// successful request is ever resent, and each wait consumes one total deadline.
func connectContext(ctx context.Context, fd int, address *unix.SockaddrUnix, deadline time.Time) error {
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		err := unix.Connect(fd, address)
		if err == nil || errors.Is(err, unix.EISCONN) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return unix.SetNonblock(fd, false)
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EAGAIN) {
			return err
		}
		pause := 10 * time.Millisecond
		if remaining < pause {
			pause = remaining
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
