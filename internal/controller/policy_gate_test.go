package controller

import (
	"context"
	core "github.com/orka-agents/orka/api/v1alpha1"
	policyresolver "github.com/orka-agents/orka/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"strings"
	"testing"
)

func TestKubernetesTaskPolicyGateValidatesSourcesBeforeRuntimeActivation(t *testing.T) {
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	p := &core.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "n", UID: "pu"}, Spec: core.AgentPolicySpec{UID: "policy-uid", DenyWriteObjects: []core.PolicyWriteObject{{Path: "/workspace/f"}}, ViolationResponse: core.PolicyViolationResponse{Action: core.PolicyViolationDeny, Threshold: 1}, RequiredCapabilities: []string{"ig.agent-policy/file-permission/v1"}}}
	pd, _ := policyresolver.PolicyDigest(p.Spec)
	b := &core.AgentPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "n", UID: "bu"}, Spec: core.AgentPolicyBindingSpec{Subject: core.PolicySubject{SuiteDigest: "sha256:" + strings.Repeat("1", 64), AgentID: "agent", CompositionDigest: "sha256:" + strings.Repeat("2", 64), SandboxBindingDigest: "sha256:" + strings.Repeat("3", 64)}, Sources: []core.PolicySourceReference{{Name: "p", UID: "policy-uid", Digest: pd}}}}
	bd, _ := policyresolver.BindingDigest(b.Spec)
	effective := core.EffectiveAgentPolicy{DenyWriteObjects: append([]core.PolicyWriteObject(nil), p.Spec.DenyWriteObjects...), ViolationResponse: p.Spec.ViolationResponse, RequiredCapabilities: append([]string(nil), p.Spec.RequiredCapabilities...)}
	effective.Digest, _ = policyresolver.EffectiveDigest(effective)
	b.Status = core.AgentPolicyBindingStatus{Phase: core.PolicyBindingAccepted, BindingDigest: bd, EffectivePolicy: &effective}
	task := &core.Task{ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: "n", UID: "tu", Generation: 3}, Spec: core.TaskSpec{PolicyBindingRef: &core.TaskPolicyBindingRef{Name: "b", UID: types.UID("bu"), Digest: bd}}}
	g := KubernetesTaskPolicyGate{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(p, b).Build()}
	if e := g.Admit(context.Background(), task); e != nil {
		t.Fatalf("accepted immutable sources should pass preflight: %v", e)
	}
	// Arbitrary status text is no longer consulted; the RuntimeSession protocol
	// carries typed, digest-verified IG evidence before provider exec.
	task.Status.Conditions = []metav1.Condition{{Type: policyresolver.ConditionPolicyReady, Status: metav1.ConditionTrue, ObservedGeneration: 3, Reason: "PolicyActivated", Message: "forged/session/receipt"}}
	if e := g.Admit(context.Background(), task); e != nil {
		t.Fatal(e)
	}
	task.Spec.PolicyBindingRef.UID = "other"
	if e := g.Admit(context.Background(), task); e == nil {
		t.Fatal("stale UID admitted")
	}
}
