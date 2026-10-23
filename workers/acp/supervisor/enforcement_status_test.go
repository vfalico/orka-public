package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/orka-agents/orka/internal/acp"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type observedLaunch struct {
	mu     sync.Mutex
	status acp.LaunchEnforcementStatus
}

func (l *observedLaunch) Prepare(context.Context, *acp.ProcessConfig) error { return nil }
func (l *observedLaunch) AbortPreparation(context.Context) error            { return nil }
func (l *observedLaunch) EnforcementStatus() acp.LaunchEnforcementStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status
}
func (l *observedLaunch) set(s acp.LaunchEnforcementStatus) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.status = s
}

type statusBackend struct {
	selectionBackend
	entered, release chan struct{}
	launch           acp.LaunchEnforcer
}

func (b *statusBackend) Launch(ctx context.Context, r v2.CreateRuntimeSessionRequest) (acp.LaunchEnforcer, error) {
	close(b.entered)
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return b.launch, errors.New("injected preparation failure")
}

// Exercise the production selection + create association and authenticated HTTP
// status path while backend preparation is blocked. No provider is substituted
// for the native end-to-end qualification; this is the generic second backend.
func TestRequirementSelectionVisibleInAuthenticatedStatus(t *testing.T) {
	server, cfg, profile := newTestServer(t, "immediate")
	request := testCreateSessionRequest(t, cfg, profile)
	r := &v2.ExecutionRequirement{Format: "future.opaque/v1", PolicyBytes: []byte("opaque"), RequiredCapabilities: []string{"future/rule"}, PayloadDigest: "sha256:" + strings.Repeat("a", 64)}
	r.Identity = r.ContentIdentity()
	request.Requirement = r
	sealRequest(t, &request.Metadata.RequestDigest, request)
	calls := 0
	first := &selectionBackend{name: "unsupported@r1", calls: &calls}
	chosen := &statusBackend{selectionBackend: selectionBackend{name: "chosen@r7", support: true, calls: &calls}, entered: make(chan struct{}), release: make(chan struct{})}
	last := &selectionBackend{name: "unused@r9", support: true, calls: &calls}
	server.cfg.RequirementBackends = []RequirementBackend{first, chosen, last}
	done := make(chan int, 1)
	go func() {
		resp := performMutation(t, server.Handler(), http.MethodPut, "/v2/runtime-sessions/session-1", request, cfg)
		done <- resp.Code
	}()
	select {
	case <-chosen.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("selection did not reach Launch")
	}
	status := readPromptTestStatus(t, server, cfg)
	if len(status.Sessions) != 1 {
		t.Fatalf("sessions: %+v", status.Sessions)
	}
	got := status.Sessions[0].Enforcement
	if got == nil || got.Backend != "chosen@r7" || got.RequirementIdentity != r.Identity || got.Phase != "selected" || got.TargetGeneration != 0 || got.TargetIdentity != "" {
		t.Fatalf("selection status: %+v", got)
	}
	if calls != 2 || last.launches != 0 {
		t.Fatal("configured order violated")
	}
	close(chosen.release)
	if code := <-done; code < 400 {
		t.Fatal("activation failure accepted")
	}
	status = readPromptTestStatus(t, server, cfg)
	if len(status.Sessions) != 0 {
		t.Fatal("failed create falsely active")
	}
	if calls != 2 || last.launches != 0 {
		t.Fatal("activation failure caused fallback")
	}
}

func TestRequirementEnforcementStatusLifecycle(t *testing.T) {
	server, cfg, _ := newTestServer(t, "immediate")
	requirement := "sha256:" + strings.Repeat("a", 64)
	target := "sha256:" + strings.Repeat("b", 64)
	launch := &observedLaunch{}
	selection := &selectedEnforcement{backend: "generic@r2", requirement: requirement}
	selection.setLaunch(launch, nil)
	server.sessions["s"] = &sessionState{enforcement: selection, descriptor: v2.RuntimeSessionDescriptor{RuntimeSessionID: "s", RuntimeSessionUID: "uid", Generation: 1, State: v2.RuntimeSessionStateCreating, LastTransitionAt: time.Now().UTC()}}
	for _, phase := range []string{"preparing", "activating", "active", "cancelled", "cleanup-pending", "cleaned", "failed"} {
		t.Run(phase, func(t *testing.T) {
			launch.set(acp.LaunchEnforcementStatus{Backend: "generic@r2", RequirementIdentity: requirement, TargetGeneration: 1, TargetIdentity: target, Phase: phase})
			status := readPromptTestStatus(t, server, cfg)
			got := status.Sessions[0].Enforcement
			if got.Phase != phase || got.TargetGeneration != 1 || got.TargetIdentity != target {
				t.Fatalf("observation: %+v", got)
			}
			server.mu.Lock()
			descriptor := sessionDescriptorLocked(server.sessions["s"])
			server.mu.Unlock()
			raw, _ := json.Marshal(descriptor)
			if !strings.Contains(string(raw), `"enforcement"`) || descriptor.Enforcement.Phase != phase {
				t.Fatal("create replay descriptor omits live association")
			}
		})
	}
	// Fresh replacement has no old active identity, even if preparation fails.
	launch.set(acp.LaunchEnforcementStatus{Backend: "generic@r2", RequirementIdentity: requirement, TargetGeneration: 2, Phase: "preparing"})
	got := readPromptTestStatus(t, server, cfg).Sessions[0].Enforcement
	if got.Phase != "preparing" || got.TargetIdentity != "" || got.TargetGeneration != 2 {
		t.Fatalf("stale replacement: %+v", got)
	}
	// Mutation of a caller-owned snapshot cannot change the next response.
	got.Backend = "tampered"
	if readPromptTestStatus(t, server, cfg).Sessions[0].Enforcement.Backend != "generic@r2" {
		t.Fatal("snapshot aliased")
	}
	launch.set(acp.LaunchEnforcementStatus{Backend: "other@r2", RequirementIdentity: requirement, Phase: "active", TargetGeneration: 2, TargetIdentity: target})
	if readPromptTestStatus(t, server, cfg).Sessions[0].Enforcement.Phase != "uncertain" {
		t.Fatal("foreign activation displayed")
	}
	selection.setLaunch(nil, errors.New("failure"))
	if readPromptTestStatus(t, server, cfg).Sessions[0].Enforcement.Phase != "failed" {
		t.Fatal("failed launch displayed active")
	}
	server.sessions["s"].enforcement = nil
	if readPromptTestStatus(t, server, cfg).Sessions[0].Enforcement != nil {
		t.Fatal("policy-free session depends on backend")
	}
}
