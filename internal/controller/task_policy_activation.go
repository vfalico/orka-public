/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	core "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	policyresolver "github.com/orka-agents/orka/internal/policy"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resolveTaskPolicyActivation re-resolves immutable sources through the uncached
// reader at the last controller boundary before RuntimeSession creation.
func resolveTaskPolicyActivation(ctx context.Context, reader client.Reader, task *core.Task) (*harnessv2.AgentPolicyActivation, error) {
	ref := task.Spec.PolicyBindingRef
	if ref == nil {
		return nil, nil
	}
	if reader == nil {
		return nil, errors.New("policy API reader is not configured")
	}
	var binding core.AgentPolicyBinding
	if err := reader.Get(ctx, client.ObjectKey{Namespace: task.Namespace, Name: ref.Name}, &binding); err != nil {
		return nil, fmt.Errorf("read policy binding: %w", err)
	}
	if binding.UID != ref.UID || binding.Status.ObservedGeneration != binding.Generation || binding.Status.BindingDigest != ref.Digest || binding.Status.Phase != core.PolicyBindingAccepted || binding.Status.EffectivePolicy == nil {
		return nil, errors.New("policy binding identity or accepted status does not match Task reference")
	}
	effective, err := (policyresolver.Resolver{Reader: reader, Now: time.Now}).Resolve(ctx, &binding)
	if err != nil {
		return nil, fmt.Errorf("re-resolve policy binding: %w", err)
	}
	if effective.Digest != binding.Status.EffectivePolicy.Digest {
		return nil, errors.New("effective policy drift since binding acceptance")
	}
	activation := &harnessv2.AgentPolicyActivation{
		Version: harnessv2.AgentPolicyActivationVersion,
		Digest:  effective.Digest,
		ViolationResponse: harnessv2.AgentPolicyViolationResponse{
			Threshold: uint32(effective.ViolationResponse.Threshold),
		},
		RequiredCapabilities: append([]string(nil), effective.RequiredCapabilities...),
	}
	for _, object := range effective.DenyWriteObjects {
		activation.DenyFiles = append(activation.DenyFiles, harnessv2.AgentPolicyFileRule{Path: object.Path})
	}
	sort.Strings(activation.RequiredCapabilities)
	if err := activation.Validate(); err != nil {
		return nil, fmt.Errorf("resolved policy is not runtime-enforceable: %w", err)
	}
	return activation, nil
}

func taskPolicyActivationStatus(receipt *harnessv2.AgentPolicyReceipt) *core.TaskPolicyActivationStatus {
	if receipt == nil {
		return nil
	}
	status := &core.TaskPolicyActivationStatus{
		Version: receipt.Version, PolicyDigest: receipt.PolicyDigest, TaskUID: receipt.TaskUID,
		TaskAttempt: receipt.TaskAttempt, RuntimeSessionID: receipt.RuntimeSessionID,
		CgroupID: receipt.CgroupID, ReceiptDigest: receipt.Digest, VerifiedAt: *nowMeta(),
	}
	for _, item := range receipt.Attachments {
		status.Attachments = append(status.Attachments, core.TaskPolicyAttachmentEvidence{
			ProgramName: item.ProgramName, ProgramID: item.ProgramID, LinkID: item.LinkID,
			AttachType: item.AttachType, Target: item.Target,
		})
	}
	return status
}
