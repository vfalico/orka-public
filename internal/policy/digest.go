package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gowebpki/jcs"
	core "github.com/orka-agents/orka/api/v1alpha1"
	"sort"
)

type portablePolicySpec struct {
	DenyWriteObjects     []core.PolicyWriteObject     `json:"denyWriteObjects,omitempty"`
	ViolationResponse    core.PolicyViolationResponse `json:"violationResponse"`
	RequiredCapabilities []string                     `json:"requiredCapabilities"`
}

func PolicyDigest(s core.AgentPolicySpec) (string, error) {
	s.DenyWriteObjects = append([]core.PolicyWriteObject(nil), s.DenyWriteObjects...)
	s.RequiredCapabilities = append([]string(nil), s.RequiredCapabilities...)
	sort.Slice(s.DenyWriteObjects, func(i, j int) bool { return s.DenyWriteObjects[i].Path < s.DenyWriteObjects[j].Path })
	sort.Strings(s.RequiredCapabilities)
	return digest("policy", struct {
		UID  string             `json:"uid"`
		Spec portablePolicySpec `json:"spec"`
	}{UID: s.UID, Spec: portablePolicySpec{DenyWriteObjects: s.DenyWriteObjects, ViolationResponse: s.ViolationResponse, RequiredCapabilities: s.RequiredCapabilities}})
}
func BindingDigest(s core.AgentPolicyBindingSpec) (string, error) {
	s.Sources = append([]core.PolicySourceReference(nil), s.Sources...)
	sort.Slice(s.Sources, func(i, j int) bool {
		if s.Sources[i].UID == s.Sources[j].UID {
			if s.Sources[i].Name == s.Sources[j].Name {
				return s.Sources[i].Digest < s.Sources[j].Digest
			}
			return s.Sources[i].Name < s.Sources[j].Name
		}
		return s.Sources[i].UID < s.Sources[j].UID
	})
	return digest("binding", s)
}
func EffectiveDigest(s core.EffectiveAgentPolicy) (string, error) {
	s.Digest = ""
	return digest("effective", s)
}
func digest(k string, v any) (string, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	raw, e = jcs.Transform(raw)
	if e != nil {
		return "", fmt.Errorf("canonicalize: %w", e)
	}
	sum := sha256.Sum256(append([]byte("agentsuite.policy/"+k+"/v1alpha1\n"), raw...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
