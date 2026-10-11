/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package v2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	AgentPolicyActivationVersion = "orka.agent-policy/activation/v1"
	AgentPolicyReceiptVersion    = "ig.agent-policy/attachment-receipt/v1"
)

var policyDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type AgentPolicyFileRule struct {
	Path string `json:"path"`
}
type AgentPolicyViolationResponse struct {
	Threshold uint32 `json:"threshold"`
}
type AgentPolicyActivation struct {
	Version              string                       `json:"version"`
	Digest               string                       `json:"digest"`
	DenyFiles            []AgentPolicyFileRule        `json:"denyFiles,omitempty"`
	ViolationResponse    AgentPolicyViolationResponse `json:"violationResponse"`
	RequiredCapabilities []string                     `json:"requiredCapabilities"`
}

func (p AgentPolicyActivation) Validate() error {
	if p.Version != AgentPolicyActivationVersion || !policyDigestPattern.MatchString(p.Digest) {
		return errors.New("valid AgentPolicy activation version and digest are required")
	}
	if len(p.DenyFiles) == 0 || len(p.DenyFiles) > 128 {
		return errors.New("AgentPolicy rule count is outside bounds")
	}
	if p.ViolationResponse.Threshold == 0 {
		return errors.New("positive AgentPolicy violation threshold is required")
	}
	seen := map[string]bool{}
	for _, r := range p.DenyFiles {
		if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || seen[r.Path] {
			return fmt.Errorf("invalid or duplicate AgentPolicy path %q", r.Path)
		}
		seen[r.Path] = true
	}
	if !sort.StringsAreSorted(p.RequiredCapabilities) || len(p.RequiredCapabilities) == 0 {
		return errors.New("AgentPolicy capabilities must be nonempty and sorted")
	}
	seenCapabilities := map[string]bool{}
	for _, c := range p.RequiredCapabilities {
		if c != "ig.agent-policy/file-permission/v1" {
			return fmt.Errorf("unsupported AgentPolicy capability %q", c)
		}
		if seenCapabilities[c] {
			return fmt.Errorf("duplicate AgentPolicy capability %q", c)
		}
		seenCapabilities[c] = true
	}
	if !seenCapabilities["ig.agent-policy/file-permission/v1"] {
		return errors.New("AgentPolicy capabilities do not exactly match rule families")
	}
	return nil
}

type AgentPolicyAttachmentEvidence struct {
	ProgramName string `json:"programName"`
	ProgramID   uint32 `json:"programID"`
	LinkID      uint32 `json:"linkID"`
	AttachType  string `json:"attachType"`
	Target      string `json:"target"`
}
type AgentPolicyReceipt struct {
	Version             string                          `json:"version"`
	PolicyDigest        string                          `json:"policyDigest"`
	TaskUID             string                          `json:"taskUID"`
	TaskAttempt         uint32                          `json:"taskAttempt"`
	RuntimeSessionID    string                          `json:"runtimeSessionID"`
	CgroupID            uint64                          `json:"cgroupID"`
	Attachments         []AgentPolicyAttachmentEvidence `json:"attachments,omitempty"`
	GuarddPolicyDigest  string                          `json:"guarddPolicyDigest,omitempty"`
	GuarddReceipt       json.RawMessage                 `json:"guarddReceipt,omitempty"`
	GuarddReceiptDigest string                          `json:"guarddReceiptDigest,omitempty"`
	Digest              string                          `json:"digest"`
}

func (r AgentPolicyReceipt) ValidateFor(policy AgentPolicyActivation, taskUID string, attempt uint32, sessionID string, cgroupID uint64) error {
	if r.Version != AgentPolicyReceiptVersion || r.PolicyDigest != policy.Digest || r.TaskUID != taskUID || r.TaskAttempt != attempt || r.RuntimeSessionID != sessionID || r.CgroupID != cgroupID {
		return errors.New("AgentPolicy receipt identity does not match activation transaction")
	}
	if len(r.GuarddReceipt) > 0 {
		if !policyDigestPattern.MatchString(r.GuarddPolicyDigest) || !policyDigestPattern.MatchString(r.GuarddReceiptDigest) {
			return errors.New("guardd receipt digests are invalid")
		}
		var encoded string
		if err := json.Unmarshal(r.GuarddReceipt, &encoded); err != nil {
			return fmt.Errorf("decode embedded guardd COSE representation: %w", err)
		}
		if len(encoded) == 0 || len(encoded) > 2<<20 {
			return errors.New("embedded guardd COSE representation is empty or oversized")
		}
		coseReceipt, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(coseReceipt) == 0 || len(coseReceipt) > 1<<20 {
			return errors.New("embedded guardd COSE receipt is invalid")
		}
		sum := sha256.Sum256(coseReceipt)
		if r.GuarddReceiptDigest != "sha256:"+hex.EncodeToString(sum[:]) {
			return errors.New("embedded guardd receipt digest is invalid")
		}
	} else if len(r.Attachments) == 0 {
		return errors.New("AgentPolicy receipt contains neither guardd receipt nor kernel attachment")
	}
	expected := map[string]int{}
	if len(policy.DenyFiles) > 0 {
		expected["file_open/lsm/file_open"] = 1
		expected["file_permission/lsm/file_permission"] = 1
	}
	seenAttachments := map[string]int{}
	for _, item := range r.Attachments {
		if item.ProgramName == "" || item.ProgramID == 0 || item.LinkID == 0 || item.Target != fmt.Sprintf("cgroup:%d", cgroupID) {
			return errors.New("AgentPolicy attachment evidence is incomplete or targets another cgroup")
		}
		key := item.ProgramName + "/" + item.AttachType
		seenAttachments[key]++
		if expected[key] == 0 || seenAttachments[key] > expected[key] {
			return fmt.Errorf("unexpected AgentPolicy attachment %q", key)
		}
	}
	if len(r.GuarddReceipt) == 0 {
		for key, count := range expected {
			if seenAttachments[key] != count {
				return fmt.Errorf("required AgentPolicy attachment %q is missing", key)
			}
		}
	}
	copy := r
	copy.Digest = ""
	payload, e := json.Marshal(copy)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(append([]byte(AgentPolicyReceiptVersion+"\n"), payload...))
	expectedDigest := "sha256:" + hex.EncodeToString(sum[:])
	if !strings.EqualFold(r.Digest, expectedDigest) {
		return errors.New("AgentPolicy receipt digest is invalid")
	}
	return nil
}
