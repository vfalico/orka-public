//go:build linux

// Package guardd is the leaf authenticated Guardd adapter, not policy interpretation.
package guardd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"time"
)

var canonical, _ = cbor.CanonicalEncOptions().EncMode()

func encode(v any) []byte {
	b, err := canonical.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func jsonMap(v any) map[string]any {
	raw, _ := json.Marshal(v)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var m map[string]any
	decoder.Decode(&m)
	var normalize func(any) any
	normalize = func(v any) any {
		switch x := v.(type) {
		case json.Number:
			n, err := x.Int64()
			if err != nil {
				panic(err)
			}
			return n
		case map[string]any:
			for k, v := range x {
				x[k] = normalize(v)
			}
			return x
		case []any:
			for i, v := range x {
				x[i] = normalize(v)
			}
			return x
		default:
			return v
		}
	}
	return normalize(m).(map[string]any)
}

func field(n int, v []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(n<<3|2))
	out = binary.AppendUvarint(out, uint64(len(v)))
	return append(out, v...)
}
func number(n int, v uint64) []byte {
	return binary.AppendUvarint(binary.AppendUvarint(nil, uint64(n<<3)), v)
}
func sign(payload []byte, key ed25519.PrivateKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	id := sha256.Sum256(der)
	protected := encode(map[int]any{1: -8, 4: id[:16]})
	signature := ed25519.Sign(key, encode([]any{"Signature1", protected, []byte("guardd.kmx.io/authorization/v1"), payload}))
	return encode([]any{protected, map[string]any{}, payload, signature})
}
func verify(data []byte, key ed25519.PublicKey, aad string) ([]byte, error) {
	var v []cbor.RawMessage
	if err := cbor.Unmarshal(data, &v); err != nil || len(v) != 4 {
		return nil, fmt.Errorf("malformed COSE evidence")
	}
	var protected, payload, sig []byte
	var unprotected map[any]any
	if cbor.Unmarshal(v[0], &protected) != nil || cbor.Unmarshal(v[1], &unprotected) != nil || len(unprotected) != 0 || cbor.Unmarshal(v[2], &payload) != nil || cbor.Unmarshal(v[3], &sig) != nil {
		return nil, fmt.Errorf("invalid COSE fields")
	}
	var h map[int]any
	if err := cbor.Unmarshal(protected, &h); err != nil || len(h) != 2 {
		return nil, fmt.Errorf("invalid COSE headers")
	}
	der, _ := x509.MarshalPKIXPublicKey(key)
	id := sha256.Sum256(der)
	expected := encode(map[int]any{1: -8, 4: id[:16]})
	if string(expected) != string(protected) {
		return nil, fmt.Errorf("COSE signer mismatch")
	}
	if !ed25519.Verify(key, encode([]any{"Signature1", protected, []byte(aad), payload}), sig) {
		return nil, fmt.Errorf("COSE signature mismatch")
	}
	return payload, nil
}

type Connection struct {
	Socket, Issuer, DaemonBoot string
	Private                    ed25519.PrivateKey
	Receipt                    ed25519.PublicKey
}

func (c Connection) call(ctx context.Context, method string, binding any, body map[string]any, fds []int) (map[string]cbor.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(nonce[:16])
	issued := uint64(time.Now().Unix())
	der, _ := x509.MarshalPKIXPublicKey(c.Private.Public())
	digest := sha256.Sum256(der)
	kid := "sha256:" + hex.EncodeToString(digest[:])
	auth := map[string]any{"protocol_version": "guardd.kmx.io/v1", "method": method, "request_id": id, "nonce": nonce, "issued_at": issued, "expires_at": issued + 60, "issuer_id": c.Issuer, "key_id": kid, "boot_id": c.DaemonBoot, "expected_state_version": 0, "binding": binding, "payload": body}
	values := [][]byte{field(1, []byte("guardd.kmx.io/v1")), field(2, []byte(method)), field(3, []byte(id)), field(4, nonce), number(5, issued), number(6, issued+60), field(7, []byte(c.Issuer)), field(8, []byte(kid)), field(9, []byte(c.DaemonBoot)), number(10, 0), field(11, encode(binding)), field(12, encode(body)), field(13, sign(encode(auth), c.Private))}
	var message []byte
	for _, v := range values {
		message = append(message, v...)
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(len(message)))
	packet = append(packet, message...)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	stopCancel := context.AfterFunc(ctx, func() { _ = unix.Shutdown(fd, unix.SHUT_RDWR) })
	defer stopCancel()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	tv := unix.NsecToTimeval(time.Until(deadline).Nanoseconds())
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	if err = unix.Connect(fd, &unix.SockaddrUnix{Name: c.Socket}); err != nil {
		return nil, err
	}
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || cred.Uid != 0 {
		return nil, fmt.Errorf("Guardd peer must be root")
	}
	var rights []byte
	if len(fds) > 0 {
		rights = unix.UnixRights(fds...)
	}
	if _, err = unix.SendmsgN(fd, packet, rights, nil, 0); err != nil {
		return nil, err
	}
	buf := make([]byte, 1<<20)
	n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
	if err != nil {
		return nil, err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n < 4 || int(binary.BigEndian.Uint32(buf)) != n-4 {
		return nil, fmt.Errorf("Guardd response truncated")
	}
	fields, err := decodeResponse(buf[4:n])
	if err != nil {
		return nil, err
	}
	if string(fields[1]) != "guardd.kmx.io/v1" || string(fields[2]) != id {
		return nil, fmt.Errorf("Guardd response identity mismatch")
	}
	if string(fields[3]) != "\x01" {
		return nil, fmt.Errorf("Guardd %s: %s", fields[5], fields[6])
	}
	var result map[string]cbor.RawMessage
	if err = cbor.Unmarshal(fields[4], &result); err != nil {
		return nil, err
	}
	return result, nil
}
func decodeResponse(b []byte) (map[int][]byte, error) {
	m := map[int][]byte{}
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("bad protobuf key")
		}
		b = b[n:]
		num := int(key >> 3)
		if num < 1 || num > 6 || m[num] != nil {
			return nil, fmt.Errorf("unknown or duplicate response field")
		}
		if key&7 == 0 {
			v, k := binary.Uvarint(b)
			if k <= 0 || num != 3 || v > 1 {
				return nil, fmt.Errorf("bad response boolean")
			}
			m[num] = []byte{byte(v)}
			b = b[k:]
		} else if key&7 == 2 {
			size, k := binary.Uvarint(b)
			if k <= 0 || size > uint64(len(b)-k) {
				return nil, fmt.Errorf("bad response size")
			}
			m[num] = append([]byte{}, b[k:k+int(size)]...)
			b = b[k+int(size):]
		} else {
			return nil, fmt.Errorf("unknown response wire type")
		}
	}
	if len(m) != 6 {
		return nil, fmt.Errorf("incomplete response")
	}
	return m, nil
}
func readKey(path string) (ed25519.PrivateKey, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != 0 || st.Mode&0077 != 0 {
		return nil, fmt.Errorf("private authorization key must be root-only")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, err
	}
	k, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Ed25519 key required")
	}
	return k, nil
}
