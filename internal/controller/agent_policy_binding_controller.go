/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package controller

import (
	"context"
	"fmt"
	core "github.com/orka-agents/orka/api/v1alpha1"
	policyresolver "github.com/orka-agents/orka/internal/policy"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// +kubebuilder:rbac:groups=core.orka.ai,resources=agentpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=core.orka.ai,resources=agentpolicybindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=core.orka.ai,resources=agentpolicybindings/status,verbs=get;update;patch
const policySourceNameIndex = ".spec.sources.name"

type AgentPolicyBindingReconciler struct {
	client.Client
	APIReader client.Reader
	Scheme    *runtime.Scheme
}

func (r *AgentPolicyBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var b core.AgentPolicyBinding
	if err := r.Get(ctx, req.NamespacedName, &b); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	resolved, err := policyresolver.Resolver{Reader: r.APIReader}.Resolve(ctx, &b)
	next := b.DeepCopy()
	next.Status.ObservedGeneration = b.Generation
	if err != nil {
		next.Status.Phase = core.PolicyBindingPending
		next.Status.BindingDigest = ""
		next.Status.EffectivePolicy = nil
		apiMeta.SetStatusCondition(&next.Status.Conditions, metav1.Condition{Type: "Accepted", Status: metav1.ConditionFalse, ObservedGeneration: b.Generation, Reason: "ResolutionFailed", Message: err.Error()})
	} else {
		bd, digestErr := policyresolver.BindingDigest(b.Spec)
		if digestErr != nil {
			return ctrl.Result{}, digestErr
		}
		next.Status.Phase = core.PolicyBindingAccepted
		next.Status.BindingDigest = bd
		next.Status.EffectivePolicy = resolved
		apiMeta.SetStatusCondition(&next.Status.Conditions, metav1.Condition{Type: "Accepted", Status: metav1.ConditionTrue, ObservedGeneration: b.Generation, Reason: "Resolved", Message: fmt.Sprintf("effective policy %s", resolved.Digest)})
	}
	if err := r.Status().Patch(ctx, next, client.MergeFrom(&b)); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
func (r *AgentPolicyBindingReconciler) bindingsForPolicy(ctx context.Context, object client.Object) []reconcile.Request {
	var bindings core.AgentPolicyBindingList
	if err := r.List(ctx, &bindings, client.InNamespace(object.GetNamespace()), client.MatchingFields{policySourceNameIndex: object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(bindings.Items))
	for i := range bindings.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&bindings.Items[i])})
	}
	return requests
}

func (r *AgentPolicyBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &core.AgentPolicyBinding{}, policySourceNameIndex, func(object client.Object) []string {
		binding := object.(*core.AgentPolicyBinding)
		names := make([]string, 0, len(binding.Spec.Sources))
		for _, source := range binding.Spec.Sources {
			names = append(names, source.Name)
		}
		return names
	}); err != nil {
		return fmt.Errorf("index policy binding sources: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&core.AgentPolicyBinding{}).
		Watches(&core.AgentPolicy{}, handler.EnqueueRequestsFromMapFunc(r.bindingsForPolicy)).
		Complete(r)
}
