/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package v2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestAgentPolicyReceiptValidatesExactTransactionAndDomainDigest(t *testing.T) {
	policy := AgentPolicyActivation{Version: AgentPolicyActivationVersion, Digest: "sha256:" + strings.Repeat("a", 64), DenyFiles: []AgentPolicyFileRule{{Path: "/workspace/secret"}}, ViolationResponse: AgentPolicyViolationResponse{Threshold: 1}, RequiredCapabilities: []string{"ig.agent-policy/file-permission/v1"}}
	receipt := AgentPolicyReceipt{Version: AgentPolicyReceiptVersion, PolicyDigest: policy.Digest, TaskUID: "task-uid", TaskAttempt: 2, RuntimeSessionID: "session", CgroupID: 42, Attachments: []AgentPolicyAttachmentEvidence{{ProgramName: "file_open", ProgramID: 6, LinkID: 7, AttachType: "lsm/file_open", Target: "cgroup:42"}, {ProgramName: "file_permission", ProgramID: 7, LinkID: 8, AttachType: "lsm/file_permission", Target: "cgroup:42"}}}
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte(AgentPolicyReceiptVersion+"\n"), payload...))
	receipt.Digest = "sha256:" + hex.EncodeToString(sum[:])
	if err := receipt.ValidateFor(policy, "task-uid", 2, "session", 42); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AgentPolicyReceipt){
		"task":    func(r *AgentPolicyReceipt) { r.TaskUID = "other" },
		"session": func(r *AgentPolicyReceipt) { r.RuntimeSessionID = "other" },
		"cgroup":  func(r *AgentPolicyReceipt) { r.CgroupID = 99 },
		"link":    func(r *AgentPolicyReceipt) { r.Attachments[0].LinkID = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			forged := receipt
			forged.Attachments = append([]AgentPolicyAttachmentEvidence(nil), receipt.Attachments...)
			mutate(&forged)
			if forged.ValidateFor(policy, "task-uid", 2, "session", 42) == nil {
				t.Fatal("forged receipt accepted")
			}
		})
	}
}
func TestAgentPolicyActivationRequiresExactCapabilities(t *testing.T) {
	policy := AgentPolicyActivation{Version: AgentPolicyActivationVersion, Digest: "sha256:" + strings.Repeat("b", 64), DenyFiles: []AgentPolicyFileRule{{Path: "/workspace/f"}}, ViolationResponse: AgentPolicyViolationResponse{Threshold: 1}, RequiredCapabilities: []string{"ig.agent-policy/cgroup-connect4/v1"}}
	if policy.Validate() == nil {
		t.Fatal("mismatched capability accepted")
	}
}

func TestAgentPolicyReceiptValidatesOpaqueCOSEResult(t *testing.T) {
	policy := AgentPolicyActivation{Version: AgentPolicyActivationVersion, Digest: "sha256:" + strings.Repeat("c", 64), DenyFiles: []AgentPolicyFileRule{{Path: "/workspace/secret"}}, ViolationResponse: AgentPolicyViolationResponse{Threshold: 1}, RequiredCapabilities: []string{"ig.agent-policy/file-permission/v1"}}
	cose := []byte{0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, 0x40, 0x58, 0x40}
	coseSum := sha256.Sum256(cose)
	encoded, err := json.Marshal(base64.StdEncoding.EncodeToString(cose))
	if err != nil {
		t.Fatal(err)
	}
	receipt := AgentPolicyReceipt{Version: AgentPolicyReceiptVersion, PolicyDigest: policy.Digest, TaskUID: "task-uid", TaskAttempt: 2, RuntimeSessionID: "session", CgroupID: 42, GuarddPolicyDigest: policy.Digest, GuarddReceipt: encoded, GuarddReceiptDigest: "sha256:" + hex.EncodeToString(coseSum[:])}
	copy := receipt
	payload, err := json.Marshal(copy)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte(AgentPolicyReceiptVersion+"\n"), payload...))
	receipt.Digest = "sha256:" + hex.EncodeToString(sum[:])
	if err := receipt.ValidateFor(policy, "task-uid", 2, "session", 42); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]json.RawMessage{"not-base64": json.RawMessage(`"%%%"`), "not-string": json.RawMessage(`{}`), "empty": json.RawMessage(`""`)} {
		t.Run(name, func(t *testing.T) {
			forged := receipt
			forged.GuarddReceipt = raw
			if forged.ValidateFor(policy, "task-uid", 2, "session", 42) == nil {
				t.Fatal("malformed COSE representation accepted")
			}
		})
	}
	forged := receipt
	forged.GuarddReceiptDigest = "sha256:" + strings.Repeat("0", 64)
	if forged.ValidateFor(policy, "task-uid", 2, "session", 42) == nil {
		t.Fatal("wrong COSE digest accepted")
	}
}
