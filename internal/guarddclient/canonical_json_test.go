package guarddclient

import (
	"encoding/hex"
	"testing"
)

func TestDigestCanonicalJSONMatchesGuardd(t *testing.T) {
	value := map[string]any{
		"a": "<>&\u2028\u2029",
		"z": []any{1, true, nil},
	}
	got, err := DigestCanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:6901436539c12312d1b99836c89dc1e41498de5de92abcfcc09edcc0223ec81d"
	if got != want {
		t.Fatalf("canonical JSON digest = %s, want %s", got, want)
	}
}

func TestDecodePythonActivationResult(t *testing.T) {
	raw, err := hex.DecodeString("a5657374617465704143544956455f56414c4944415445446872656365697074738141786d73746174655f76657273696f6e07726661696c5f736166655f677561726469616ea463706964187b6561726d6564f566616374696f6e73667265657a655f65786163745f6367726f75706777617463686573846c6775617264645f70696466646f69675f776f726b65725f7069646664776576656e745f636f6e73756d65725f6c6976656e657373696367726f75705f6664781872656c656173655f656c696769626c655f726563656970744178")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		State        string   `cbor:"state"`
		StateVersion uint64   `cbor:"state_version"`
		Receipt      []byte   `cbor:"release_eligible_receipt"`
		Receipts     [][]byte `cbor:"receipts"`
		Guardian     struct {
			Armed   bool     `cbor:"armed"`
			PID     uint64   `cbor:"pid"`
			Watches []string `cbor:"watches"`
			Action  string   `cbor:"action"`
		} `cbor:"fail_safe_guardian"`
	}
	if err := decodeCanonical(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.State != "ACTIVE_VALIDATED" || result.StateVersion != 7 || string(result.Receipt) != "x" ||
		!result.Guardian.Armed || result.Guardian.PID != 123 || result.Guardian.Action != "freeze_exact_cgroup" {
		t.Fatalf("activation result = %#v", result)
	}
}
