//go:build !linux

package acp

import (
	"context"
	"fmt"
	"os/exec"
)

type execGate struct{}

func prepareExecGate(_ *exec.Cmd, cfg ProcessConfig) (*execGate, error) {
	if cfg.BeforeExec != nil {
		return nil, fmt.Errorf("governed launch requires Linux")
	}
	return &execGate{}, nil
}
func (*execGate) closeParentCopies()          {}
func (*execGate) ready(context.Context) error { return fmt.Errorf("governed launch requires Linux") }
func (*execGate) release() error              { return fmt.Errorf("governed launch requires Linux") }

func (p *Process) PidFD() int { return -1 }
