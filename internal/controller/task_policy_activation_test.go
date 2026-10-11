package controller

import (
	"encoding/json"
	"strings"
	"testing"

	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

func TestTaskPolicyActivationStatusProjectsVerifiedAttachmentsAsArray(t *testing.T) {
	receipt := &harnessv2.AgentPolicyReceipt{
		Version: harnessv2.AgentPolicyReceiptVersion,
		Attachments: []harnessv2.AgentPolicyAttachmentEvidence{
			{
				ProgramName: "agentpolicy_open", ProgramID: 11, LinkID: 21,
				AttachType: "lsm/file_open", Target: "cgroup:42",
			},
			{
				ProgramName: "agentpolicy_permission", ProgramID: 12, LinkID: 22,
				AttachType: "lsm/file_permission", Target: "cgroup:42",
			},
		},
	}
	status := taskPolicyActivationStatus(receipt)
	if status == nil || len(status.Attachments) != 2 {
		t.Fatalf("policy activation status = %#v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"attachments":[`) {
		t.Fatalf("attachments did not serialize as an array: %s", encoded)
	}
}
