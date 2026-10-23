package supervisor

import (
	"context"
	"fmt"
	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"sync"
)

// RequirementBackend is configured by trusted supervisor startup, in order.
// Support evaluates the whole opaque requirement. No fallback follows Prepare.
type RequirementBackend interface {
	Identity() string
	Support(context.Context, *harnessv2.ExecutionRequirement, string) (bool, error)
	Launch(context.Context, harnessv2.CreateRuntimeSessionRequest) (acp.LaunchEnforcer, error)
}

func selectRequirementBackend(ctx context.Context, backends []RequirementBackend, r *harnessv2.ExecutionRequirement) (RequirementBackend, error) {
	if r == nil {
		return nil, nil
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	for _, b := range backends {
		if b == nil {
			return nil, fmt.Errorf("invalid configured requirement backend")
		}
		yes, err := b.Support(ctx, r.Clone(), "linux-amd64-acp-v1")
		if err != nil {
			return nil, fmt.Errorf("requirement backend %s support uncertain: %w", b.Identity(), err)
		}
		if yes {
			return b, nil
		}
	}
	return nil, fmt.Errorf("no configured backend supports the complete mandatory requirement %s", r.Identity)
}

// selectedEnforcement projects a single accepted create's existing association.
// Its lock protects only pointers; never hold it (or Server.mu) over backend I/O.
type selectedEnforcement struct {
	mu                   sync.Mutex
	backend, requirement string
	launch               acp.LaunchEnforcer
	failed               bool
}

func (e *selectedEnforcement) setLaunch(l acp.LaunchEnforcer, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.launch, e.failed = l, err != nil
}
func (e *selectedEnforcement) snapshot() *harnessv2.RequirementEnforcementStatus {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	l, failed := e.launch, e.failed
	e.mu.Unlock()
	out := &harnessv2.RequirementEnforcementStatus{Backend: e.backend, RequirementIdentity: e.requirement, Phase: "selected"}
	if failed {
		out.Phase = "failed"
		return out
	}
	if l == nil {
		return out
	}
	out.Phase = "preparing"
	if provider, ok := l.(acp.EnforcementStatusProvider); ok {
		status := provider.EnforcementStatus()
		// A backend cannot accidentally project another requirement's activation.
		if status.Backend != e.backend || status.RequirementIdentity != e.requirement {
			out.Phase = "uncertain"
			return out
		}
		out.TargetGeneration, out.TargetIdentity, out.Phase = status.TargetGeneration, status.TargetIdentity, status.Phase
		if out.Phase == "active" && (out.TargetGeneration == 0 || out.TargetIdentity == "") {
			out.Phase = "uncertain"
		}
	}
	return out
}
func sessionDescriptorLocked(state *sessionState) harnessv2.RuntimeSessionDescriptor {
	descriptor := state.descriptor
	descriptor.Enforcement = state.enforcement.snapshot()
	return descriptor
}
