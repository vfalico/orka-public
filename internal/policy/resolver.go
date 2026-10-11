package policy

import (
	"context"
	"errors"
	"fmt"
	core "github.com/orka-agents/orka/api/v1alpha1"
	"path/filepath"
	"regexp"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sort"
	"strings"
	"time"
)

var allowedCapabilities = map[string]bool{"ig.agent-policy/file-permission/v1": true}
var sha256DigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Resolver struct {
	Reader client.Reader
	Now    func() time.Time
}

func (r Resolver) Resolve(ctx context.Context, b *core.AgentPolicyBinding) (*core.EffectiveAgentPolicy, error) {
	if r.Reader == nil {
		return nil, errors.New("policy reader is required")
	}
	if b == nil {
		return nil, errors.New("binding is required")
	}
	if err := validateBinding(b.Spec); err != nil {
		return nil, err
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	if b.Spec.NotBefore != nil && now.Before(b.Spec.NotBefore.Time) || b.Spec.NotAfter != nil && !now.Before(b.Spec.NotAfter.Time) {
		return nil, errors.New("binding is outside its validity window")
	}
	if len(b.Spec.Sources) == 0 || len(b.Spec.Sources) > 32 {
		return nil, errors.New("binding requires 1..32 sources")
	}
	out := &core.EffectiveAgentPolicy{}
	paths := map[string]bool{}
	caps := map[string]bool{}
	for _, ref := range b.Spec.Sources {
		var p core.AgentPolicy
		if err := r.Reader.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: ref.Name}, &p); err != nil {
			return nil, fmt.Errorf("get policy %s: %w", ref.Name, err)
		}
		if p.Spec.UID != ref.UID {
			return nil, fmt.Errorf("policy %s contract UID drift", ref.Name)
		}
		d, err := PolicyDigest(p.Spec)
		if err != nil {
			return nil, err
		}
		if d != ref.Digest {
			return nil, fmt.Errorf("policy %s digest drift", ref.Name)
		}
		if err := validatePolicy(p.Spec); err != nil {
			return nil, fmt.Errorf("policy %s: %w", ref.Name, err)
		}
		for _, v := range p.Spec.DenyWriteObjects {
			if !paths[v.Path] {
				paths[v.Path] = true
				out.DenyWriteObjects = append(out.DenyWriteObjects, v)
			}
		}
		for _, v := range p.Spec.RequiredCapabilities {
			if !caps[v] {
				caps[v] = true
				out.RequiredCapabilities = append(out.RequiredCapabilities, v)
			}
		}
		if out.ViolationResponse.Threshold == 0 || p.Spec.ViolationResponse.Threshold < out.ViolationResponse.Threshold {
			out.ViolationResponse.Threshold = p.Spec.ViolationResponse.Threshold
		}
		if out.ViolationResponse.Action == "" {
			out.ViolationResponse.Action = core.PolicyViolationDeny
		}
	}
	if len(out.DenyWriteObjects) > core.MaxPolicyWriteObjects {
		return nil, errors.New("effective policy exceeds limits")
	}
	sort.Slice(out.DenyWriteObjects, func(i, j int) bool { return out.DenyWriteObjects[i].Path < out.DenyWriteObjects[j].Path })
	sort.Strings(out.RequiredCapabilities)
	d, err := EffectiveDigest(*out)
	out.Digest = d
	return out, err
}
func validateBinding(s core.AgentPolicyBindingSpec) error {
	if !sha256DigestRE.MatchString(s.Subject.SuiteDigest) || !sha256DigestRE.MatchString(s.Subject.CompositionDigest) || !sha256DigestRE.MatchString(s.Subject.SandboxBindingDigest) || strings.TrimSpace(s.Subject.AgentID) == "" {
		return errors.New("binding subject requires an agent ID and three sha256 digests")
	}
	if len(s.Sources) == 0 || len(s.Sources) > 32 {
		return errors.New("binding requires 1..32 sources")
	}
	if s.NotBefore != nil && s.NotAfter != nil && !s.NotBefore.Before(s.NotAfter) {
		return errors.New("binding notBefore must precede notAfter")
	}
	seen := make(map[string]struct{}, len(s.Sources))
	for _, ref := range s.Sources {
		if strings.TrimSpace(ref.Name) == "" || strings.TrimSpace(ref.UID) == "" || len(ref.UID) > 128 || !sha256DigestRE.MatchString(ref.Digest) {
			return errors.New("policy source name, UID, and sha256 digest are required")
		}
		if _, ok := seen[ref.UID]; ok {
			return fmt.Errorf("duplicate source UID %q", ref.UID)
		}
		seen[ref.UID] = struct{}{}
	}
	return nil
}

func validatePolicy(s core.AgentPolicySpec) error {
	if strings.TrimSpace(s.UID) == "" || len(s.UID) > 128 {
		return errors.New("policy contract UID must contain 1..128 characters")
	}
	if len(s.DenyWriteObjects) == 0 {
		return errors.New("empty policy")
	}
	if len(s.DenyWriteObjects) > core.MaxPolicyWriteObjects || len(s.RequiredCapabilities) == 0 || len(s.RequiredCapabilities) > 16 {
		return errors.New("policy rule or capability count is outside bounds")
	}
	if s.ViolationResponse.Threshold < 1 {
		return errors.New("positive violation threshold required")
	}
	if s.ViolationResponse.Action != core.PolicyViolationDeny {
		return errors.New("invalid violation action")
	}
	seenPaths := map[string]struct{}{}
	for _, v := range s.DenyWriteObjects {
		if !filepath.IsAbs(v.Path) || filepath.Clean(v.Path) != v.Path {
			return fmt.Errorf("unclean absolute path %q", v.Path)
		}
		if _, ok := seenPaths[v.Path]; ok {
			return fmt.Errorf("duplicate path %q", v.Path)
		}
		seenPaths[v.Path] = struct{}{}
	}
	seenCapabilities := map[string]struct{}{}
	for _, v := range s.RequiredCapabilities {
		if !allowedCapabilities[strings.TrimSpace(v)] {
			return fmt.Errorf("unsupported capability %q", v)
		}
		if _, ok := seenCapabilities[v]; ok {
			return fmt.Errorf("duplicate capability %q", v)
		}
		seenCapabilities[v] = struct{}{}
	}
	return nil
}
