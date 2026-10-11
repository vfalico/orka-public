/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package controller

import (
	"context"
	"errors"
	"fmt"
	core "github.com/orka-agents/orka/api/v1alpha1"
	policyresolver "github.com/orka-agents/orka/internal/policy"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

var errPolicyActivationPending = errors.New("policy activation evidence is pending")

type TaskPolicyGate interface {
	Admit(context.Context, *core.Task) error
}
type KubernetesTaskPolicyGate struct{ Reader client.Reader }

func (g KubernetesTaskPolicyGate) Admit(ctx context.Context, task *core.Task) error {
	ref := task.Spec.PolicyBindingRef
	if ref == nil {
		return nil
	}
	if g.Reader == nil {
		return errors.New("policy API reader is not configured")
	}
	var binding core.AgentPolicyBinding
	if err := g.Reader.Get(ctx, client.ObjectKey{Namespace: task.Namespace, Name: ref.Name}, &binding); err != nil {
		return err
	}
	if binding.UID != ref.UID {
		return errors.New("policy binding UID does not match Task reference")
	}
	if binding.Status.ObservedGeneration != binding.Generation || binding.Status.BindingDigest != ref.Digest || binding.Status.Phase != core.PolicyBindingAccepted || binding.Status.EffectivePolicy == nil {
		return errors.New("policy binding status is not accepted at the Task digest")
	}
	// Status is evidence, never authority: resolve uncached sources again at every dispatch decision.
	effective, err := (policyresolver.Resolver{Reader: g.Reader, Now: time.Now}).Resolve(ctx, &binding)
	if err != nil {
		return fmt.Errorf("re-resolve policy binding: %w", err)
	}
	if effective.Digest != binding.Status.EffectivePolicy.Digest {
		return errors.New("effective policy drift since binding acceptance")
	}
	return nil
}
