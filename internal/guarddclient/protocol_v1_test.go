package guarddclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
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
func TestVerifiedGuardianReceiptProjectsSignedAttachments(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	now := time.Unix(1700000000, 0)
	client := &Client{cfg: Config{
		ReceiptPublicKey: pub, BootID: "boot", Timeout: time.Second,
		Now: func() time.Time { return now },
	}}
	cgroup, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(cgroup.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	binding := Binding{"session", "1", 1, "sha256:" + repeat("a", 64), "sha256:" + repeat("b", 64), "node"}
	target := "cgroup:" + fmt.Sprint(stat.Ino)
	claims := map[string]any{
		"assurance": "worker_fd_policy_map_readback_and_fail_safe_guardian",
		"held":      true,
		"cgroup": map[string]any{
			"dev": uint64(stat.Dev), "ino": stat.Ino,
			"mount_id": uint64(7), "cgroup_id": stat.Ino,
		},
		"guardian": map[string]any{
			"armed": true, "pid": uint64(99), "action": "freeze_exact_cgroup",
			"watches": []string{"guardd_pidfd", "ig_worker_pidfd", "event_consumer_liveness", "cgroup_fd"},
		},
		"attachments": []map[string]any{
			{"program_name": "agentpolicy_open", "program_id": uint64(11), "link_id": uint64(21), "attach_type": "lsm/file_open", "target": target},
			{"program_name": "agentpolicy_permission", "program_id": uint64(12), "link_id": uint64(22), "attach_type": "lsm/file_permission", "target": target},
		},
	}
	sign := func() []byte {
		payload, err := enc.Marshal(receiptPayload{
			Schema: ReceiptSchema, Stage: ReceiptStage, Binding: binding,
			Sequence: 7, PriorReceiptHash: "sha256:" + repeat("c", 64),
			BootID: "boot", StateVersion: 3, IssuedAtNS: now.UnixNano(),
			Claims: claims,
		})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := sign1(payload, key, coseKID(pub), []byte(receiptAAD))
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	receiptPayload, attachments, err := client.verifyReceipt(sign(), binding, cgroup)
	if err != nil {
		t.Fatalf("%v; claims=%#v", err, receiptPayload.Claims)
	}
	if len(attachments) != 2 || attachments[0].AttachType != "lsm/file_open" ||
		attachments[1].ProgramName != "agentpolicy_permission" {
		t.Fatalf("attachments = %#v", attachments)
	}
	claims["attachments"].([]map[string]any)[0]["target"] = "cgroup:1"
	if _, _, err := client.verifyReceipt(sign(), binding, cgroup); err == nil {
		t.Fatal("wrong signed attachment target accepted")
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
