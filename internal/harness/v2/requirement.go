package v2

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
)

// ExecutionRequirement is mandatory, opaque, per-execution input. PayloadDigest
// belongs to the producer; Orka neither interprets nor recomputes its semantics.
type ExecutionRequirement struct {
	Format               string   `json:"format"`
	PolicyBytes          []byte   `json:"policyBytes"`
	RequiredCapabilities []string `json:"requiredCapabilities"`
	PayloadDigest        string   `json:"payloadDigest"`
	Identity             string   `json:"identity"`
}

var requirementIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]{0,127}$`)

func requirementField(h hash.Hash, b []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(b)))
	h.Write(size[:])
	h.Write(b)
}
func (r ExecutionRequirement) ContentIdentity() string {
	h := sha256.New()
	h.Write([]byte("orka.execution-requirement\x00v1\x00"))
	requirementField(h, []byte(r.Format))
	requirementField(h, r.PolicyBytes)
	requirementField(h, []byte(r.PayloadDigest))
	for _, c := range r.RequiredCapabilities {
		requirementField(h, []byte(c))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func (r *ExecutionRequirement) Validate() error {
	if r == nil {
		return nil
	}
	if !requirementIdentifier.MatchString(r.Format) {
		return fmt.Errorf("invalid requirement format")
	}
	if len(r.PolicyBytes) == 0 || len(r.PolicyBytes) > 256<<10 {
		return fmt.Errorf("requirement bytes must be 1..262144")
	}
	if len(r.RequiredCapabilities) == 0 || len(r.RequiredCapabilities) > 32 {
		return fmt.Errorf("requirement capability count must be 1..32")
	}
	seen := map[string]bool{}
	for _, c := range r.RequiredCapabilities {
		if !requirementIdentifier.MatchString(c) || seen[c] {
			return fmt.Errorf("invalid or duplicate requirement capability")
		}
		seen[c] = true
	}
	if err := validateSHA256Digest(r.PayloadDigest); err != nil {
		return fmt.Errorf("requirement payload identity: %w", err)
	}
	if r.Identity != r.ContentIdentity() {
		return fmt.Errorf("requirement content identity mismatch")
	}
	return nil
}
func (r *ExecutionRequirement) Clone() *ExecutionRequirement {
	if r == nil {
		return nil
	}
	c := *r
	c.PolicyBytes = append([]byte(nil), r.PolicyBytes...)
	c.RequiredCapabilities = append([]string(nil), r.RequiredCapabilities...)
	return &c
}
