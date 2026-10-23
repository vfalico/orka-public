package guardd

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEvidenceSignatureRejectsSubstitution(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := encode(map[string]any{"target": "exact-target", "requirement": "exact-policy"})
	signed := sign(payload, key)
	got, err := verify(signed, pub, "guardd.kmx.io/authorization/v1")
	if err != nil || string(got) != string(payload) {
		t.Fatalf("valid evidence: %v", err)
	}
	if _, err = verify(signed, pub, "guardd.network.activation/v1"); err == nil {
		t.Fatal("authorization was accepted as activation")
	}
	signed[len(signed)-1] ^= 1
	if _, err = verify(signed, pub, "guardd.kmx.io/authorization/v1"); err == nil {
		t.Fatal("changed receipt accepted")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = verify(sign(payload, key), other, "guardd.kmx.io/authorization/v1"); err == nil {
		t.Fatal("wrong signer accepted")
	}
}
func TestResponseDecoderRejectsAmbiguity(t *testing.T) {
	valid := append(field(1, []byte("guardd.kmx.io/v1")), field(2, []byte("request"))...)
	valid = append(valid, number(3, 1)...)
	valid = append(valid, field(4, encode(map[string]any{}))...)
	valid = append(valid, field(5, []byte{})...)
	valid = append(valid, field(6, []byte{})...)
	if _, err := decodeResponse(valid); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte{}, valid...), field(1, []byte("duplicate"))...), append(append([]byte{}, valid...), field(9, []byte("unknown"))...), valid[:len(valid)-1]} {
		if _, err := decodeResponse(bad); err == nil {
			t.Fatal("ambiguous response accepted")
		}
	}
}
