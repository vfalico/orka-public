package guarddclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectors struct {
	Schema          string `json:"schema"`
	SeedHex         string `json:"seed_hex"`
	PublicDERB64    string `json:"public_der_b64"`
	RequestFrameB64 string `json:"request_frame_b64"`
	ReceiptCOSEB64  string `json:"receipt_cose_b64"`
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	b, e := os.ReadFile("vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v vectors
	e = json.Unmarshal(b, &v)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestPythonGoRequestFrameByteExact(t *testing.T) {
	v := readVectors(t)
	seed, e := hex.DecodeString(v.SeedHex)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	b := Binding{"session-vector", "attempt-vector", 1, "sha256:" + repeat("a", 64), "sha256:" + repeat("b", 64), "node-vector"}
	bc, _ := enc.Marshal(b)
	pc, _ := enc.Marshal(map[string]any{"policy": map[string]any{"enabled": true}})
	f := requestFrame{ProtocolVersion, "activate", "000102030405060708090a0b0c0d0e0f", sequence(16, 32), 1700000000, 1700000015, "kmx-vector", keyID(pub), "boot-vector", 0, bc, pc, nil}
	signed := map[string]any{"protocol_version": f.Protocol, "method": f.Method, "request_id": f.RequestID, "nonce": f.Nonce, "issued_at": f.IssuedAt, "expires_at": f.ExpiresAt, "issuer_id": f.IssuerID, "key_id": f.KeyID, "boot_id": f.BootID, "expected_state_version": f.ExpectedStateVersion, "binding": b, "payload": map[string]any{"policy": map[string]any{"enabled": true}}}
	body, _ := enc.Marshal(signed)
	f.Authorization, e = sign1(body, key, coseKID(pub), []byte(authorizationAAD))
	if e != nil {
		t.Fatal(e)
	}
	want, _ := base64.StdEncoding.DecodeString(v.RequestFrameB64)
	if !equal(f.encode(), want) {
		t.Fatalf("request mismatch: go=%x python=%x", sha256.Sum256(f.encode()), sha256.Sum256(want))
	}
}
func TestVerifyPythonCOSEReceipt(t *testing.T) {
	v := readVectors(t)
	seed, _ := hex.DecodeString(v.SeedHex)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	receipt, _ := base64.StdEncoding.DecodeString(v.ReceiptCOSEB64)
	payload, e := verifySign1(receipt, pub, coseKID(pub), []byte(receiptAAD))
	if e != nil {
		t.Fatal(e)
	}
	var rp receiptPayload
	if e = decodeCanonical(payload, &rp); e != nil {
		t.Fatal(e)
	}
	if rp.Schema != ReceiptSchema || rp.Stage != ReceiptStage || rp.StateVersion != 7 ||
		rp.Claims["held"] != true ||
		rp.Claims["assurance"] != "worker_fd_policy_map_readback_and_fail_safe_guardian" {
		t.Fatalf("wrong claims: %#v", rp)
	}
}
func TestMutationsRejected(t *testing.T) {
	v := readVectors(t)
	seed, _ := hex.DecodeString(v.SeedHex)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	r, _ := base64.StdEncoding.DecodeString(v.ReceiptCOSEB64)
	r[len(r)-1] ^= 1
	if _, e := verifySign1(r, pub, coseKID(pub), []byte(receiptAAD)); e == nil {
		t.Fatal("tampered receipt accepted")
	}
	if _, e := decodeResponse([]byte{0x0a, 1, 'v', 0x0a, 1, 'v'}); e == nil {
		t.Fatal("duplicate protobuf accepted")
	}
}
func repeat(s string, n int) string {
	o := ""
	for i := 0; i < n; i++ {
		o += s
	}
	return o
}
func sequence(start, n byte) []byte {
	o := make([]byte, int(n))
	for i := range o {
		o[i] = start + byte(i)
	}
	return o
}
