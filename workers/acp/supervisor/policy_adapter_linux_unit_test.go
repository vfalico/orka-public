//go:build linux

/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package supervisor

import (
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/harness/v2"
)

func TestGuarddPolicyDocumentDoesNotTurnWriteRulesIntoExecutableRules(t *testing.T) {
	policy := v2.AgentPolicyActivation{
		Version: v2.AgentPolicyActivationVersion,
		Digest:  "sha256:" + strings.Repeat("a", 64),
		DenyFiles: []v2.AgentPolicyFileRule{
			{Path: "/workspace/locked"},
		},
		ViolationResponse:    v2.AgentPolicyViolationResponse{Threshold: 1},
		RequiredCapabilities: []string{"ig.agent-policy/file-permission/v1"},
	}
	document := buildGuarddPolicyDocument(
		policy,
		v2.MutationMetadata{TaskUID: v2.TaskUID("task-uid")},
		"session-id",
		"session-id",
	)
	if len(document.Spec.DenyExecutables) != 0 {
		t.Fatalf("write policy unexpectedly produced executable rules: %#v", document.Spec.DenyExecutables)
	}
	if len(document.Spec.DenyWrites) != 1 || document.Spec.DenyWrites[0].Path != "/workspace/locked" {
		t.Fatalf("write policy was not preserved exactly: %#v", document.Spec.DenyWrites)
	}
	tree := guarddPolicyMap(document)
	spec := tree["spec"].(map[string]any)
	rules := spec["denyWrites"].([]any)
	if ruleID, ok := rules[0].(map[string]any)["id"].(uint32); !ok || ruleID != 1 {
		t.Fatalf("write rule ID lost integer type: %#v", rules[0])
	}
}

func TestGuarddRuntimeConfigTreatsIssuerAsIdentifier(t *testing.T) {
	cfg := guarddRuntimeConfig{
		SocketPath:                  "/run/guardd.sock",
		AuthorizationIssuerID:       "orka-production",
		AuthorizationPrivateKeyFile: "/run/authorization-private.pem",
		ReceiptPublicKeyFile:        "/run/receipt-public.pem",
		ReceiptDirectory:            "/var/lib/orka/receipts",
		GadgetDigest:                "sha256:" + strings.Repeat("a", 64),
		NodeID:                      "node-1",
		CgroupRoot:                  "/sys/fs/cgroup/orka",
	}
	if err := validateGuarddRuntimeConfig(cfg); err != nil {
		t.Fatalf("valid issuer identifier rejected: %v", err)
	}
	cfg.AuthorizationIssuerID = " orka-production "
	if err := validateGuarddRuntimeConfig(cfg); err == nil || !strings.Contains(err.Error(), "issuer ID") {
		t.Fatalf("invalid issuer identifier accepted: %v", err)
	}
}
