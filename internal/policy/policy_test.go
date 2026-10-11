package policy

import (
	"context"
	core "github.com/orka-agents/orka/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"strings"
	"testing"
)

func policyFixture() (core.AgentPolicy, core.AgentPolicyBinding) {
	p := core.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "guard", Namespace: "n", UID: "kubernetes-policy-uid"}, Spec: core.AgentPolicySpec{UID: "policy-uid", DenyWriteObjects: []core.PolicyWriteObject{{Path: "/workspace/locked"}}, ViolationResponse: core.PolicyViolationResponse{Action: core.PolicyViolationDeny, Threshold: 1}, RequiredCapabilities: []string{"ig.agent-policy/file-permission/v1"}}}
	d, _ := PolicyDigest(p.Spec)
	b := core.AgentPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: "guard-binding", Namespace: "n", UID: "bu"}, Spec: core.AgentPolicyBindingSpec{Subject: core.PolicySubject{SuiteDigest: "sha256:" + strings.Repeat("1", 64), AgentID: "agent", CompositionDigest: "sha256:" + strings.Repeat("2", 64), SandboxBindingDigest: "sha256:" + strings.Repeat("3", 64)}, Sources: []core.PolicySourceReference{{Name: "guard", UID: "policy-uid", Digest: d}}}}
	return p, b
}
func TestResolverPinsUIDAndDigest(t *testing.T) {
	p, b := policyFixture()
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	r := Resolver{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(&p).Build()}
	got, e := r.Resolve(context.Background(), &b)
	if e != nil {
		t.Fatal(e)
	}
	if got.Digest == "" || len(got.DenyWriteObjects) != 1 {
		t.Fatalf("bad effective policy: %#v", got)
	}
	b.Spec.Sources[0].UID = "stale"
	if _, e = r.Resolve(context.Background(), &b); e == nil || !strings.Contains(e.Error(), "UID drift") {
		t.Fatalf("expected UID drift, got %v", e)
	}
}
func TestTaskAdmissionRequiresExactDurableEvidence(t *testing.T) {
	_, b := policyFixture()
	bd, _ := BindingDigest(b.Spec)
	b.Status.Phase = core.PolicyBindingAccepted
	b.Status.EffectivePolicy = &core.EffectiveAgentPolicy{Digest: "effective"}
	task := &core.Task{ObjectMeta: metav1.ObjectMeta{UID: "tu", Generation: 4}}
	a := TaskAdmission{BindingName: "guard-binding", BindingUID: "bu", BindingDigest: bd, EffectiveDigest: "effective", TaskUID: "tu", TaskGeneration: 4, RuntimeSessionID: "session", AttachmentReceiptDigest: "receipt"}
	if e := AdmitTask(task, &b, a); e == nil {
		t.Fatal("admitted without condition")
	}
	task.Status.Conditions = []metav1.Condition{{Type: ConditionPolicyReady, Status: metav1.ConditionTrue, ObservedGeneration: 4, Reason: "PolicyActivated", Message: "session/receipt"}}
	if e := AdmitTask(task, &b, a); e != nil {
		t.Fatal(e)
	}
	a.BindingUID = types.UID("other")
	if e := AdmitTask(task, &b, a); e == nil {
		t.Fatal("admitted stale binding")
	}
}

func TestKaimahiContractDigestVectors(t *testing.T) {
	p, b := policyFixture()
	pd, err := PolicyDigest(p.Spec)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := BindingDigest(b.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if pd != "sha256:c6cc7347b678b819e529237356492d8222467f68de0dc62a369f3660d428be72" || bd != "sha256:342eeb5999e887a536d8d3d260b522bc31227d950d92862947aa543bd8857e72" {
		t.Fatalf("update cross-project vectors after intentional contract change: policy=%s binding=%s", pd, bd)
	}
}

func TestResolverRejectsMalformedBindingAndDuplicateRules(t *testing.T) {
	p, b := policyFixture()
	b.Spec.Subject.AgentID = ""
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	r := Resolver{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(&p).Build()}
	if _, err := r.Resolve(context.Background(), &b); err == nil {
		t.Fatal("expected malformed subject rejection")
	}
	p, b = policyFixture()
	p.Spec.DenyWriteObjects = append(p.Spec.DenyWriteObjects, p.Spec.DenyWriteObjects[0])
	b.Spec.Sources[0].Digest, _ = PolicyDigest(p.Spec)
	r = Resolver{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(&p).Build()}
	if _, err := r.Resolve(context.Background(), &b); err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatalf("expected duplicate path rejection, got %v", err)
	}
}

func TestResolverUsesMostRestrictiveViolationResponse(t *testing.T) {
	p1, b := policyFixture()
	p1.Spec.ViolationResponse = core.PolicyViolationResponse{Action: core.PolicyViolationDeny, Threshold: 5}
	p1d, _ := PolicyDigest(p1.Spec)
	b.Spec.Sources[0].Digest = p1d
	p2 := p1
	p2.Name = "second"
	p2.Spec.UID = "policy-uid-2"
	p2.Spec.ViolationResponse = core.PolicyViolationResponse{Action: core.PolicyViolationDeny, Threshold: 2}
	p2d, _ := PolicyDigest(p2.Spec)
	b.Spec.Sources = append(b.Spec.Sources, core.PolicySourceReference{Name: p2.Name, UID: p2.Spec.UID, Digest: p2d})
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	r := Resolver{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(&p1, &p2).Build()}
	got, err := r.Resolve(context.Background(), &b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ViolationResponse.Threshold != 2 || got.ViolationResponse.Action != core.PolicyViolationDeny {
		t.Fatalf("unexpected merge: %+v", got.ViolationResponse)
	}
}

func TestResolverRejectsUnimplementedCapability(t *testing.T) {
	p, b := policyFixture()
	p.Spec.RequiredCapabilities = []string{"ig.agent-policy/cgroup-skb/v1"}
	b.Spec.Sources[0].Digest, _ = PolicyDigest(p.Spec)
	s := runtime.NewScheme()
	_ = core.AddToScheme(s)
	r := Resolver{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(&p).Build()}
	if _, err := r.Resolve(context.Background(), &b); err == nil || !strings.Contains(err.Error(), "unsupported capability") {
		t.Fatalf("expected unsupported capability rejection, got %v", err)
	}
}
