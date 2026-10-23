//go:build linux

package enforcementunix

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"testing"
	"time"
)

func TestInterruptedWireBoundedSameCall(t *testing.T) {
	count := 0
	n, err := retryInterrupted(t.Context(), time.Now().Add(time.Second), func() (int, error) {
		count++
		if count < 3 {
			return 0, unix.EINTR
		}
		return 7, nil
	})
	if err != nil || n != 7 || count != 3 {
		t.Fatal(n, err, count)
	}
	count = 0
	_, err = retryInterrupted(t.Context(), time.Now().Add(time.Second), func() (int, error) { count++; return 0, unix.EAGAIN })
	if !errors.Is(err, unix.EAGAIN) || count != 1 {
		t.Fatal(err, count)
	}
	ctx, cancel := context.WithCancel(t.Context())
	count = 0
	_, err = retryInterrupted(ctx, time.Now().Add(time.Second), func() (int, error) { count++; cancel(); return 0, unix.EINTR })
	if !errors.Is(err, context.Canceled) || count != 1 {
		t.Fatal(err, count)
	}
	_, err = retryInterrupted(t.Context(), time.Now().Add(-time.Second), func() (int, error) { t.Fatal("expired call executed"); return 0, nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
