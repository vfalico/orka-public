package controller

import (
	"bytes"
	"context"
	"encoding/json"
	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"testing"
)

// This is the actual immutable binding/snapshot verifier, with an explicitly
// in-memory API reader. It consumes Kaimahi's actual captured Task submission.
func TestSuiteRequirementActualKaimahiSnapshot(t *testing.T) {
	input := os.Getenv("ORKA_KAIMAHI_TASK_FIXTURE")
	if input == "" {
		t.Skip("explicit Kaimahi capture required")
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var submitted corev1alpha1.Task
	if err = json.Unmarshal(raw, &submitted); err != nil {
		t.Fatal(err)
	}
	if submitted.Spec.Type != corev1alpha1.TaskTypeAgent || submitted.Spec.Execution == nil || submitted.Spec.Execution.Requirement == nil {
		t.Fatal("not governed Kaimahi submission")
	}
	r := submitted.Spec.Execution.Requirement
	frozen := &harnessv2.ExecutionRequirement{Format: r.Format, PolicyBytes: append([]byte(nil), r.PolicyBytes...), RequiredCapabilities: append([]string(nil), r.RequiredCapabilities...), PayloadDigest: r.PayloadDigest, Identity: r.Identity}
	if err = frozen.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	task := bindingTestTask()
	task.Spec.Prompt = submitted.Spec.Prompt
	task.Spec.Execution = submitted.Spec.Execution
	reconciler, _ := newBindingTestReconciler(t, task, bindingTestAgent(), bindingTestNamespace())
	if _, err, handled := reconciler.ensureAgentExecutionBinding(ctx, task, bindingTestAgent()); err != nil || handled {
		t.Fatalf("binding: %v handled=%v", err, handled)
	}
	if err = reconciler.Get(ctx, client.ObjectKeyFromObject(task), task); err != nil {
		t.Fatal(err)
	}
	bound, err := reconciler.loadVerifiedBoundExecution(ctx, task, task.Status.AgentExecutionBinding)
	if err != nil {
		t.Fatal(err)
	}
	if bound.body.Requirement == nil || bound.body.Requirement.Identity != frozen.Identity || !bytes.Equal(bound.body.Requirement.PolicyBytes, frozen.PolicyBytes) {
		t.Fatal("frozen snapshot substituted policy")
	}
	// No alias through the Kubernetes API DeepCopy path.
	copy := task.DeepCopy()
	copy.Spec.Execution.Requirement.PolicyBytes[0] = 'X'
	if bytes.Equal(copy.Spec.Execution.Requirement.PolicyBytes, task.Spec.Execution.Requirement.PolicyBytes) {
		t.Fatal("Task deep copy aliases accepted bytes")
	}
	// Reference edit must not change an already admitted snapshot.
	agent := bindingTestAgent()
	if err = reconciler.Get(ctx, client.ObjectKeyFromObject(agent), agent); err != nil {
		t.Fatal(err)
	}
	agent.Spec.SystemPrompt = &corev1alpha1.PromptSource{Inline: "changed after acceptance"}
	if err = reconciler.Update(ctx, agent); err != nil {
		t.Fatal(err)
	}
	bound, err = reconciler.loadVerifiedBoundExecution(ctx, task, task.Status.AgentExecutionBinding)
	if err != nil {
		t.Fatal(err)
	}
	if bound.body.Requirement.Identity != frozen.Identity {
		t.Fatal("live Agent edit rewrote accepted requirement")
	}
	// A spec mutation with a new Kubernetes generation cannot dispatch the old
	// binding. Same-generation cache drift still uses the frozen bytes.
	current := &corev1alpha1.Task{}
	if err = reconciler.Get(ctx, client.ObjectKeyFromObject(task), current); err != nil {
		t.Fatal(err)
	}
	current.Generation++
	current.Spec.Execution.Requirement.PolicyBytes = []byte("substitution")
	if err = reconciler.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err = reconciler.loadVerifiedBoundExecution(ctx, task, task.Status.AgentExecutionBinding); err == nil {
		t.Fatal("changed Task dispatched with stale binding")
	}
	if out := os.Getenv("ORKA_FROZEN_REQUIREMENT_OUTPUT"); out != "" {
		raw, err = json.MarshalIndent(frozen, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(out, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("Kaimahi Task -> real immutable snapshot -> verified opaque requirement; live edits cannot substitute accepted policy")
}
