//go:build !linux

/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package supervisor

import (
	"context"
	"errors"
	"github.com/orka-agents/orka/internal/harness/v2"
	"io"
)

func validateAgentPolicyStartup(cfg Config) error {
	if cfg.AgentPolicyGuarddSocket != "" {
		return errors.New("AgentPolicy activation is only supported on Linux")
	}
	return nil
}

func activateAgentPolicy(context.Context, string, string, v2.AgentPolicyActivation, v2.MutationMetadata, string, int) (io.Closer, *v2.AgentPolicyReceipt, error) {
	return nil, nil, errors.New("AgentPolicy activation is only supported on Linux")
}
