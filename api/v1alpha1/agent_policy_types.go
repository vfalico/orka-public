/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const MaxPolicyWriteObjects = 128

type PolicyViolationAction string

const (
	PolicyViolationDeny PolicyViolationAction = "deny"
)

type PolicyWriteObject struct {
	// +kubebuilder:validation:MinLength=1
	Path string `json:"path"`
}
type PolicyViolationResponse struct {
	// +kubebuilder:validation:Enum=deny
	Action PolicyViolationAction `json:"action"`
	// +kubebuilder:validation:Minimum=1
	Threshold int32 `json:"threshold"`
}
type AgentPolicySpec struct {
	// UID is the portable policy identity, independent of Kubernetes metadata.uid.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid"`
	// +kubebuilder:validation:MaxItems=128
	DenyWriteObjects  []PolicyWriteObject     `json:"denyWriteObjects,omitempty"`
	ViolationResponse PolicyViolationResponse `json:"violationResponse"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	RequiredCapabilities []string `json:"requiredCapabilities"`
}
type AgentPolicyStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Digest             string             `json:"digest,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=apol
// +kubebuilder:validation:XValidation:rule="self.spec == oldSelf.spec",message="spec is immutable"
type AgentPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AgentPolicySpec   `json:"spec"`
	Status            AgentPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type AgentPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentPolicy `json:"items"`
}

func init() { SchemeBuilder.Register(&AgentPolicy{}, &AgentPolicyList{}) }
