package v2

import (
	"bytes"
	"strings"
	"testing"
)

func TestExecutionRequirement(t *testing.T) {
	r := ExecutionRequirement{Format: "fixture/v1", PolicyBytes: []byte(`{"opaque":true}`), RequiredCapabilities: []string{"fixture/one"}, PayloadDigest: "sha256:" + strings.Repeat("1", 64)}
	r.Identity = r.ContentIdentity()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	c := r.Clone()
	r.PolicyBytes[0] = 'x'
	if bytes.Equal(c.PolicyBytes, r.PolicyBytes) {
		t.Fatal("clone aliases")
	}
	if r.Validate() == nil {
		t.Fatal("substitution accepted")
	}
	for _, bad := range []ExecutionRequirement{
		{Format: c.Format, PolicyBytes: c.PolicyBytes, RequiredCapabilities: []string{"x", "x"}, PayloadDigest: c.PayloadDigest},
		{Format: c.Format, PolicyBytes: make([]byte, 262145), RequiredCapabilities: c.RequiredCapabilities, PayloadDigest: c.PayloadDigest},
		{Format: "", PolicyBytes: c.PolicyBytes, RequiredCapabilities: c.RequiredCapabilities, PayloadDigest: c.PayloadDigest},
	} {
		bad.Identity = bad.ContentIdentity()
		if bad.Validate() == nil {
			t.Fatal("bad envelope accepted")
		}
	}
}
