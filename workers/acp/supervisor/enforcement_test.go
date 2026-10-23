package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"strings"
	"testing"
)

type selectionBackend struct {
	name     string
	support  bool
	err      error
	calls    *int
	launches int
}

func (b *selectionBackend) Identity() string { return b.name }
func (b *selectionBackend) Support(context.Context, *harnessv2.ExecutionRequirement, string) (bool, error) {
	*b.calls++
	return b.support, b.err
}
func (b *selectionBackend) Launch(context.Context, harnessv2.CreateRuntimeSessionRequest) (acp.LaunchEnforcer, error) {
	b.launches++
	return nil, errors.New("activation failed")
}
func TestRequirementBackendSelectionWholePolicyNoFailover(t *testing.T) {
	r := &harnessv2.ExecutionRequirement{Format: "future.opaque/v1", PolicyBytes: []byte(`{"unknownRule":true}`), RequiredCapabilities: []string{"future/rule"}}
	r.PayloadDigest = "sha256:" + strings.Repeat("a", 64)
	r.Identity = r.ContentIdentity()
	calls := 0
	a := &selectionBackend{name: "first", calls: &calls}
	b := &selectionBackend{name: "second", support: true, calls: &calls}
	c := &selectionBackend{name: "third", support: true, calls: &calls}
	selected, err := selectRequirementBackend(context.Background(), []RequirementBackend{a, b, c}, r)
	if err != nil || selected != b || calls != 2 {
		t.Fatalf("selection %v %v calls=%d", selected, err, calls)
	}
	_, err = selected.Launch(context.Background(), harnessv2.CreateRuntimeSessionRequest{Requirement: r})
	if err == nil || calls != 2 || c.launches != 0 {
		t.Fatal("activation failure fell through")
	}
	calls = 0
	a.err = errors.New("uncertain support")
	if _, err = selectRequirementBackend(context.Background(), []RequirementBackend{a, b}, r); err == nil || calls != 1 {
		t.Fatal("uncertain support allowed fallback")
	}
	calls = 0
	if selected, err = selectRequirementBackend(context.Background(), []RequirementBackend{b}, nil); err != nil || selected != nil || calls != 0 {
		t.Fatal("policy-free execution depends on backend")
	}
	if _, err = selectRequirementBackend(context.Background(), nil, r); err == nil {
		t.Fatal("missing mandatory enforcer accepted")
	}
}
func TestRequirementMandatoryCreateFailsBeforeProvider(t *testing.T) {
	server, cfg, profile := newTestServer(t, "immediate")
	request := testCreateSessionRequest(t, cfg, profile)
	r := &harnessv2.ExecutionRequirement{Format: "future.opaque/v1", PolicyBytes: []byte("opaque"), RequiredCapabilities: []string{"future/rule"}}
	r.PayloadDigest = "sha256:" + strings.Repeat("a", 64)
	r.Identity = r.ContentIdentity()
	request.Requirement = r
	sealRequest(t, &request.Metadata.RequestDigest, request)
	response := performMutation(t, server.Handler(), "PUT", "/v2/runtime-sessions/session-1", request, cfg)
	if response.Code < 400 {
		t.Fatal("missing mandatory backend executed")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.sessions) > 0 {
		t.Fatal("provider session admitted without backend")
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(response.Body.String(), "opaque") {
		t.Fatal("policy bytes leaked into error")
	}
}
