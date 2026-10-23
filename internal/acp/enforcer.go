package acp

import (
	"context"
	"fmt"
)

// LaunchEnforcer is the single trusted pre-exec callback. Prepare must create a
// new exact target for every initial/replacement launch. Activate must retain
// cleanup ownership on failure; only RuntimeSession releases the helper.
type LaunchEnforcer interface {
	Prepare(context.Context, *ProcessConfig) error
	AbortPreparation(context.Context) error
}

// PrepareGovernedLaunch makes cancellation and cleanup errors ordinary ACP
// execution failures. A mandatory requirement never falls back to legacy exec.
func PrepareGovernedLaunch(ctx context.Context, e LaunchEnforcer, cfg *ProcessConfig) error {
	if e == nil {
		return fmt.Errorf("mandatory execution requirement has no configured enforcer")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.Prepare(ctx, cfg)
}

// LaunchEnforcementStatus is a read-only observation, never release authority.
// TargetIdentity is a digest of the exact target (including its fence), not a PID.
// Active means verified restrictions, not that the governed entrypoint ran.
type LaunchEnforcementStatus struct {
	Backend             string
	RequirementIdentity string
	TargetGeneration    uint64
	TargetIdentity      string
	Phase               string
}

// EnforcementStatusProvider must return promptly without waiting for backend I/O.
// Providers without this optional observation surface remain "preparing", never
// inferred active merely because support or Prepare returned successfully.
type EnforcementStatusProvider interface {
	EnforcementStatus() LaunchEnforcementStatus
}
