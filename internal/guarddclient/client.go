// Copyright (c) 2026. MIT License - see LICENSE file for details.
// Package guarddclient implements Orka's fail-closed guardd v1 boundary.
package guarddclient

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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	ProtocolVersion  = "guardd.kmx.io/v1"
	ReceiptSchema    = "guardd.kmx.io/receipt/v1"
	ReceiptStage     = "FAIL_SAFE_GUARDIAN_ARMED"
	authorizationAAD = "guardd.kmx.io/authorization/v1"
	receiptAAD       = "guardd.kmx.io/receipt/v1"
	maxFrame         = 1 << 20
)

type Binding struct {
	SessionID    string `cbor:"session_id" json:"session_id"`
	Attempt      string `cbor:"attempt" json:"attempt"`
	Generation   int64  `cbor:"generation" json:"generation"`
	PolicyDigest string `cbor:"policy_digest" json:"policy_digest"`
	GadgetDigest string `cbor:"gadget_digest" json:"gadget_digest"`
	NodeID       string `cbor:"node_id" json:"node_id"`
}
type Config struct {
	SocketPath              string
	AuthorizationPrivateKey ed25519.PrivateKey
	AuthorizationIssuerID   string
	BootID                  string
	ReceiptPublicKey        ed25519.PublicKey
	ReceiptDirectory        string
	Timeout                 time.Duration
	MaxFrame                int
	Now                     func() time.Time
	Random                  io.Reader
}
type Client struct {
	cfg      Config
	mu       sync.Mutex
	versions map[string]uint64
}
type Receipt []byte

type requestFrame struct {
	Protocol, Method, RequestID             string
	Nonce                                   []byte
	IssuedAt, ExpiresAt                     uint64
	IssuerID, KeyID, BootID                 string
	ExpectedStateVersion                    uint64
	BindingCBOR, PayloadCBOR, Authorization []byte
}
type responseFrame struct {
	Protocol, RequestID     string
	OK                      bool
	Payload                 []byte
	ErrorCode, ErrorMessage string
}
type receiptPayload struct {
	Schema           string         `cbor:"schema"`
	Stage            string         `cbor:"stage"`
	Binding          Binding        `cbor:"binding"`
	Sequence         uint64         `cbor:"sequence"`
	PriorReceiptHash string         `cbor:"prior_receipt_hash"`
	BootID           string         `cbor:"boot_id"`
	StateVersion     uint64         `cbor:"state_version"`
	IssuedAtNS       int64          `cbor:"issued_at_ns"`
	Claims           map[string]any `cbor:"claims"`
}

var enc cbor.EncMode
var dec cbor.DecMode

func init() {
	var err error
	enc, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	dec, err = cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, IntDec: cbor.IntDecConvertNone, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()
	if err != nil {
		panic(err)
	}
}

func New(cfg Config) (*Client, error) {
	if !cleanAbs(cfg.SocketPath) {
		return nil, errors.New("guardd socket path must be clean and absolute")
	}
	if len(cfg.AuthorizationPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("authorization key must be Ed25519")
	}
	if cfg.AuthorizationIssuerID == "" || len(cfg.AuthorizationIssuerID) > 128 {
		return nil, errors.New("authorization issuer ID invalid")
	}
	if cfg.BootID == "" || len(cfg.BootID) > 128 {
		return nil, errors.New("boot ID invalid")
	}
	if len(cfg.ReceiptPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("receipt key must be Ed25519")
	}
	if !cleanAbs(cfg.ReceiptDirectory) {
		return nil, errors.New("receipt directory must be clean and absolute")
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 30*time.Second {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxFrame == 0 {
		cfg.MaxFrame = maxFrame
	}
	if cfg.MaxFrame < 4096 || cfg.MaxFrame > maxFrame {
		return nil, errors.New("invalid maximum frame")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	return &Client{cfg: cfg, versions: map[string]uint64{}}, nil
}
func cleanAbs(v string) bool { return filepath.IsAbs(v) && filepath.Clean(v) == v }
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(b)
}

func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(b)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid private PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return k, nil
}
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKeyPEM(b)
}

func ParsePublicKeyPEM(b []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(b)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid public PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return k, nil
}
func DigestCanonical(v any) (string, error) {
	b, e := enc.Marshal(v)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:]), nil
}
func DigestCanonicalJSON(v any) (string, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return "", err
	}
	raw := bytes.TrimSuffix(output.Bytes(), []byte{'\n'})
	raw = bytes.ReplaceAll(raw, []byte(`\u2028`), []byte("\u2028"))
	raw = bytes.ReplaceAll(raw, []byte(`\u2029`), []byte("\u2029"))
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func Canonical(v any) ([]byte, error) { return enc.Marshal(v) }
func keyID(pub ed25519.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	s := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(s[:])
}
func coseKID(pub ed25519.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	s := sha256.Sum256(der)
	return s[:16]
}
func bindingKey(b Binding) string {
	return fmt.Sprintf("%s/%s/%d", b.SessionID, b.Attempt, b.Generation)
}
func validateBinding(b Binding) error {
	for n, v := range map[string]string{"session": b.SessionID, "attempt": b.Attempt, "node": b.NodeID} {
		if v == "" || len(v) > 128 || strings.ContainsAny(v, "/\\\x00") || v == "." || v == ".." {
			return fmt.Errorf("invalid %s binding", n)
		}
	}
	for _, d := range []string{b.PolicyDigest, b.GadgetDigest} {
		if len(d) != 71 || !strings.HasPrefix(d, "sha256:") {
			return errors.New("invalid binding digest")
		}
		if _, e := hex.DecodeString(d[7:]); e != nil {
			return errors.New("invalid binding digest")
		}
	}
	if b.Generation <= 0 {
		return errors.New("invalid generation")
	}
	return nil
}

func (c *Client) Activate(ctx context.Context, b Binding, policy map[string]any, cgroup *os.File) (Receipt, error) {
	if cgroup == nil {
		return nil, errors.New("cgroup file required")
	}
	if err := validateBinding(b); err != nil {
		return nil, err
	}
	response, err := c.transact(ctx, "activate", b, map[string]any{"policy": policy}, 0, cgroup)
	if err != nil {
		return nil, err
	}
	var shape map[string]any
	if err = decodeCanonical(response.Payload, &shape); err != nil {
		return nil, fmt.Errorf("decode activation shape: %w", err)
	}
	required := map[string]bool{
		"state": true, "state_version": true, "release_eligible_receipt": true,
		"receipts": true, "fail_safe_guardian": true,
	}
	var missing, unknown []string
	for key := range required {
		if _, ok := shape[key]; !ok {
			missing = append(missing, key)
		}
	}
	for key := range shape {
		if !required[key] {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(unknown)
	if len(missing) > 0 || len(unknown) > 0 {
		return nil, fmt.Errorf("activation result fields mismatch: missing=%v unknown=%v", missing, unknown)
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
	if err = decodeCanonical(response.Payload, &result); err != nil {
		return nil, fmt.Errorf("decode activation: %w", err)
	}
	if result.State != "ACTIVE_VALIDATED" || len(result.Receipt) == 0 {
		return nil, errors.New("response is not active-validated")
	}
	expectedWatches := []string{"cgroup_fd", "event_consumer_liveness", "guardd_pidfd", "ig_worker_pidfd"}
	actualWatches := append([]string(nil), result.Guardian.Watches...)
	sort.Strings(actualWatches)
	if !result.Guardian.Armed || result.Guardian.PID == 0 ||
		result.Guardian.Action != "freeze_exact_cgroup" ||
		len(actualWatches) != len(expectedWatches) {
		return nil, errors.New("fail-safe guardian is not release-eligible")
	}
	for index := range expectedWatches {
		if actualWatches[index] != expectedWatches[index] {
			return nil, errors.New("fail-safe guardian watches are incomplete")
		}
	}
	rp, err := c.verifyReceipt(result.Receipt, b)
	if err != nil {
		return nil, err
	}
	if result.StateVersion <= rp.StateVersion {
		return nil, errors.New("activation response state version did not advance")
	}
	c.mu.Lock()
	c.versions[bindingKey(b)] = result.StateVersion
	c.mu.Unlock()
	if err = c.persistReceipt(result.Receipt, b); err != nil {
		return nil, fmt.Errorf("persist receipt before release: %w", err)
	}
	return Receipt(result.Receipt), nil
}
func (c *Client) Action(ctx context.Context, action string, b Binding) error {
	switch action {
	case "terminate_handoff", "deactivate":
	default:
		return errors.New("unsupported lifecycle action")
	}
	c.mu.Lock()
	version, ok := c.versions[bindingKey(b)]
	c.mu.Unlock()
	if !ok {
		return errors.New("missing durable state version")
	}
	response, err := c.transact(ctx, action, b, map[string]any{}, version, nil)
	if err != nil {
		return err
	}
	var result map[string]any
	if err = decodeCanonical(response.Payload, &result); err != nil {
		return err
	}
	if v, ok := result["state_version"].(uint64); ok {
		c.mu.Lock()
		c.versions[bindingKey(b)] = v
		c.mu.Unlock()
	}
	return nil
}
func (c *Client) transact(ctx context.Context, method string, b Binding, payload map[string]any, stateVersion uint64, cgroup *os.File) (responseFrame, error) {
	bindingCBOR, err := enc.Marshal(b)
	if err != nil {
		return responseFrame{}, err
	}
	payloadCBOR, err := enc.Marshal(payload)
	if err != nil {
		return responseFrame{}, err
	}
	rid := make([]byte, 16)
	nonce := make([]byte, 32)
	if _, err = io.ReadFull(c.cfg.Random, rid); err != nil {
		return responseFrame{}, err
	}
	if _, err = io.ReadFull(c.cfg.Random, nonce); err != nil {
		return responseFrame{}, err
	}
	now := c.cfg.Now()
	f := requestFrame{ProtocolVersion, method, hex.EncodeToString(rid), nonce, uint64(now.Unix()), uint64(now.Add(c.cfg.Timeout).Unix()), c.cfg.AuthorizationIssuerID, keyID(c.cfg.AuthorizationPrivateKey.Public().(ed25519.PublicKey)), c.cfg.BootID, stateVersion, bindingCBOR, payloadCBOR, nil}
	signed := map[string]any{"protocol_version": f.Protocol, "method": f.Method, "request_id": f.RequestID, "nonce": f.Nonce, "issued_at": f.IssuedAt, "expires_at": f.ExpiresAt, "issuer_id": f.IssuerID, "key_id": f.KeyID, "boot_id": f.BootID, "expected_state_version": f.ExpectedStateVersion, "binding": b, "payload": payload}
	body, err := enc.Marshal(signed)
	if err != nil {
		return responseFrame{}, err
	}
	f.Authorization, err = sign1(body, c.cfg.AuthorizationPrivateKey, coseKID(c.cfg.AuthorizationPrivateKey.Public().(ed25519.PublicKey)), []byte(authorizationAAD))
	if err != nil {
		return responseFrame{}, err
	}
	msg := f.encode()
	packet := append(make([]byte, 4), msg...)
	binary.BigEndian.PutUint32(packet, uint32(len(msg)))
	if len(packet) > c.cfg.MaxFrame {
		return responseFrame{}, errors.New("request exceeds frame bound")
	}
	d := net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := d.DialContext(ctx, "unixpacket", c.cfg.SocketPath)
	if err != nil {
		return responseFrame{}, err
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return responseFrame{}, errors.New("not unix seqpacket")
	}
	_ = uc.SetDeadline(now.Add(c.cfg.Timeout))
	if cgroup != nil {
		raw, e := uc.SyscallConn()
		if e != nil {
			return responseFrame{}, e
		}
		var se error
		e = raw.Control(func(fd uintptr) { se = syscall.Sendmsg(int(fd), packet, syscall.UnixRights(int(cgroup.Fd())), nil, 0) })
		if e != nil {
			return responseFrame{}, e
		}
		if se != nil {
			return responseFrame{}, se
		}
	} else if _, err = uc.Write(packet); err != nil {
		return responseFrame{}, err
	}
	buf := make([]byte, c.cfg.MaxFrame+1)
	n, err := uc.Read(buf)
	if err != nil {
		return responseFrame{}, err
	}
	if n < 5 || n > c.cfg.MaxFrame {
		return responseFrame{}, errors.New("invalid response size")
	}
	if int(binary.BigEndian.Uint32(buf[:4])) != n-4 {
		return responseFrame{}, errors.New("response length mismatch")
	}
	r, err := decodeResponse(buf[4:n])
	if err != nil {
		return responseFrame{}, err
	}
	if r.Protocol != ProtocolVersion || r.RequestID != f.RequestID {
		return responseFrame{}, errors.New("response binding mismatch")
	}
	if !r.OK {
		return responseFrame{}, fmt.Errorf("guardd %s: %s", r.ErrorCode, r.ErrorMessage)
	}
	return r, nil
}
func (c *Client) verifyReceipt(receipt []byte, b Binding) (receiptPayload, error) {
	payload, err := verifySign1(receipt, c.cfg.ReceiptPublicKey, coseKID(c.cfg.ReceiptPublicKey), []byte(receiptAAD))
	if err != nil {
		return receiptPayload{}, err
	}
	var rp receiptPayload
	if err = decodeCanonical(payload, &rp); err != nil {
		return rp, err
	}
	if rp.Schema != ReceiptSchema || rp.Stage != ReceiptStage || rp.Binding != b || rp.BootID != c.cfg.BootID || rp.Sequence == 0 || rp.StateVersion == 0 {
		return rp, errors.New("receipt claims mismatch")
	}
	if rp.IssuedAtNS <= 0 || time.Unix(0, rp.IssuedAtNS).After(c.cfg.Now().Add(c.cfg.Timeout)) || time.Unix(0, rp.IssuedAtNS).Before(c.cfg.Now().Add(-5*time.Minute)) {
		return rp, errors.New("receipt time invalid")
	}
	held, ok := rp.Claims["held"].(bool)
	if !ok || !held || rp.Claims["assurance"] != "worker_fd_policy_map_readback_and_fail_safe_guardian" {
		return rp, errors.New("receipt lacks held assurance")
	}
	return rp, nil
}
func (c *Client) persistReceipt(r []byte, b Binding) error {
	if err := os.MkdirAll(c.cfg.ReceiptDirectory, 0700); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s-g%d.cose", b.SessionID, b.Attempt, b.Generation)
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		return errors.New("unsafe receipt name")
	}
	tmp, err := os.CreateTemp(c.cfg.ReceiptDirectory, ".receipt-*")
	if err != nil {
		return err
	}
	tn := tmp.Name()
	defer os.Remove(tn)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(r)
	}
	if err == nil {
		err = tmp.Sync()
	}
	ce := tmp.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tn, filepath.Join(c.cfg.ReceiptDirectory, name)); err != nil {
		return err
	}
	d, err := os.Open(c.cfg.ReceiptDirectory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func decodeCanonical(b []byte, v any) error {
	if err := dec.Unmarshal(b, v); err != nil {
		return err
	}
	again, err := enc.Marshal(v)
	if err != nil {
		return err
	}
	if !equal(b, again) {
		return errors.New("non-canonical CBOR")
	}
	return nil
}
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := range a {
		x |= a[i] ^ b[i]
	}
	return x == 0
}
