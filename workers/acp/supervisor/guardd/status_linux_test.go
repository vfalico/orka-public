//go:build linux

package guardd

import (
	"context"
	"github.com/orka-agents/orka/internal/acp"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
	"strings"
	"testing"
	"time"
)

func TestLaunchObservationCancellationReplacementAndFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &launch{backend: &Backend{Name: "guardd", Revision: "r3"}, request: v2.CreateRuntimeSessionRequest{Requirement: &v2.ExecutionRequirement{Identity: "sha256:" + strings.Repeat("a", 64)}}}
	l.generation = 1
	target := map[string]any{"generation": 1, "pid": 42, "start": "123", "fence": "original"}
	for _, phase := range []string{"preparing", "activating", "active"} {
		l.observe(ctx, phase, target)
		got := l.EnforcementStatus()
		if got.Phase != phase || got.Backend != "guardd@r3" || got.TargetIdentity == "" || got.TargetGeneration != 1 {
			t.Fatalf("observation %+v", got)
		}
	}
	old := l.EnforcementStatus().TargetIdentity
	cancel()
	if l.EnforcementStatus().Phase != "cancelled" {
		t.Fatal("late active observation after cancellation")
	}
	l.observe(context.Background(), "cleanup-pending", target)
	if l.EnforcementStatus().Phase != "cleanup-pending" {
		t.Fatal("cleanup hidden by cancellation")
	}
	l.observe(context.Background(), "cleaned", target)
	if l.EnforcementStatus().Phase != "cleaned" {
		t.Fatal("cleanup missing")
	}
	// Actual Prepare invalidates prior target before new allocation or validation.
	err := l.Prepare(context.Background(), &acp.ProcessConfig{})
	got := l.EnforcementStatus()
	if err == nil || got.Phase != "failed" || got.TargetGeneration != 2 || got.TargetIdentity != "" {
		t.Fatalf("replacement reused stale activation: %+v %v", got, err)
	}
	l.observe(context.Background(), "active", map[string]any{"generation": 2, "pid": 42, "start": "456", "fence": "original"})
	if l.EnforcementStatus().TargetIdentity == old {
		t.Fatal("recycled PID reused activation identity")
	}
	// A blocked activation lock cannot prevent authenticated status observation.
	l.mu.Lock()
	defer l.mu.Unlock()
	done := make(chan struct{})
	go func() { l.EnforcementStatus(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("status waits on activation I/O lock")
	}
}
