package guarddclient

import (
	"crypto/ed25519"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

const coseEdDSA int64 = -8

func sign1(payload []byte, key ed25519.PrivateKey, kid, aad []byte) ([]byte, error) {
	protected, err := enc.Marshal(map[int64]any{1: coseEdDSA, 4: kid})
	if err != nil {
		return nil, err
	}
	sigStructure, err := enc.Marshal([]any{"Signature1", protected, aad, payload})
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(key, sigStructure)
	return enc.Marshal([]any{protected, map[any]any{}, payload, signature})
}

func verifySign1(encoded []byte, key ed25519.PublicKey, wantKID, aad []byte) ([]byte, error) {
	var value []cbor.RawMessage
	if err := decodeCanonical(encoded, &value); err != nil {
		return nil, err
	}
	if len(value) != 4 {
		return nil, errors.New("COSE_Sign1 item count")
	}
	var protected, payload, signature []byte
	var unprotected map[any]any
	if err := dec.Unmarshal(value[0], &protected); err != nil {
		return nil, err
	}
	if err := dec.Unmarshal(value[1], &unprotected); err != nil {
		return nil, err
	}
	if len(unprotected) != 0 {
		return nil, errors.New("COSE unprotected headers forbidden")
	}
	if err := dec.Unmarshal(value[2], &payload); err != nil {
		return nil, err
	}
	if err := dec.Unmarshal(value[3], &signature); err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("COSE signature length")
	}
	var headers map[int64]cbor.RawMessage
	if err := decodeCanonical(protected, &headers); err != nil {
		return nil, err
	}
	if len(headers) != 2 {
		return nil, errors.New("COSE protected headers")
	}
	var alg int64
	var kid []byte
	if err := dec.Unmarshal(headers[1], &alg); err != nil {
		return nil, err
	}
	if err := dec.Unmarshal(headers[4], &kid); err != nil {
		return nil, err
	}
	if alg != coseEdDSA || !equal(kid, wantKID) {
		return nil, errors.New("COSE algorithm or key ID mismatch")
	}
	sigStructure, err := enc.Marshal([]any{"Signature1", protected, aad, payload})
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, sigStructure, signature) {
		return nil, errors.New("COSE signature invalid")
	}
	return payload, nil
}
