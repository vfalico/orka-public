/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type PolicySubject struct {
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	SuiteDigest string `json:"suiteDigest"`
	// +kubebuilder:validation:MinLength=1
	AgentID string `json:"agentID"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	CompositionDigest string `json:"compositionDigest"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	SandboxBindingDigest string `json:"sandboxBindingDigest"`
}
type PolicySourceReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	Digest string `json:"digest"`
}
type AgentPolicyBindingSpec struct {
	Subject PolicySubject `json:"subject"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Sources   []PolicySourceReference `json:"sources"`
	NotBefore *metav1.Time            `json:"notBefore,omitempty"`
	NotAfter  *metav1.Time            `json:"notAfter,omitempty"`
}
type AgentPolicyBindingPhase string

const (
	PolicyBindingPending  AgentPolicyBindingPhase = "Pending"
	PolicyBindingAccepted AgentPolicyBindingPhase = "Accepted"
	PolicyBindingRevoked  AgentPolicyBindingPhase = "Revoked"
)

type EffectiveAgentPolicy struct {
	Digest               string                  `json:"digest"`
	DenyWriteObjects     []PolicyWriteObject     `json:"denyWriteObjects,omitempty"`
	ViolationResponse    PolicyViolationResponse `json:"violationResponse"`
	RequiredCapabilities []string                `json:"requiredCapabilities"`
}
type AgentPolicyBindingStatus struct {
	ObservedGeneration int64                   `json:"observedGeneration,omitempty"`
	Phase              AgentPolicyBindingPhase `json:"phase,omitempty"`
	BindingDigest      string                  `json:"bindingDigest,omitempty"`
	EffectivePolicy    *EffectiveAgentPolicy   `json:"effectivePolicy,omitempty"`
	Conditions         []metav1.Condition      `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=apb
// +kubebuilder:validation:XValidation:rule="self.spec == oldSelf.spec",message="spec is immutable"
type AgentPolicyBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AgentPolicyBindingSpec   `json:"spec"`
	Status            AgentPolicyBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type AgentPolicyBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentPolicyBinding `json:"items"`
}

func init() { SchemeBuilder.Register(&AgentPolicyBinding{}, &AgentPolicyBindingList{}) }
