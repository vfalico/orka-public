//go:build linux

package enforcementunix

import (
	"encoding/json"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"testing"
)

func TestIndependentOpaquePeerFromNormalBackend(t *testing.T) {
	path := os.Getenv("ORKA_TEST_PEER_CONFIG")
	if path == "" {
		t.Skip("explicit independent TEST peer required")
	}
	b, err := ReadBackend(path)
	if err != nil {
		t.Fatal(err)
	}
	req := &v2.ExecutionRequirement{Format: "test.opaque/v1", PolicyBytes: []byte("not-a-Suite-policy\x00"), RequiredCapabilities: []string{"test/opaque/v1"}, PayloadDigest: "sha256:" + strings.Repeat("1", 64)}
	req.Identity = req.ContentIdentity()
	supported, err := b.Support(t.Context(), req, "test-target")
	if err != nil || !supported {
		t.Fatal(supported, err)
	}
	a := &association{Requirement: req, Binding: map[string]any{"generation": 1}, Target: map[string]any{"generation": 1, "opaque": "not-Suite"}}
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	call := func(method, flag string) {
		t.Helper()
		result, err := b.Connection.call(t.Context(), method, operation(a), requirement(req), a.Target, []int{fd})
		if err != nil {
			t.Fatal(err)
		}
		if err = exactBound(result, a, flag); err != nil {
			t.Fatal(err)
		}
	}
	call("activate", "active")
	call("lookup", "active")
	a.Target["generation"] = 2
	if _, err = b.Connection.call(t.Context(), "lookup", operation(a), requirement(req), a.Target, []int{fd}); err == nil {
		t.Fatal("changed target admitted")
	}
	a.Target["generation"] = 1
	call("retire", "retired")
	if _, err = b.Connection.call(t.Context(), "lookup", operation(a), requirement(req), a.Target, nil); err == nil {
		t.Fatal("retired admitted")
	}
	bad := req.Clone()
	bad.Format = "unsupported/v1"
	bad.Identity = bad.ContentIdentity()
	supported, err = b.Support(t.Context(), bad, "test-target")
	if err != nil || supported {
		t.Fatal(supported, err)
	}
	raw, err := json.Marshal(requirement(req))
	if err != nil || !strings.Contains(string(raw), "test.opaque/v1") {
		t.Fatal(string(raw), err)
	}
	t.Log("INDEPENDENT_TEST_PEER_CONFIG_OPAQUE_TRANSPORT_PASS Orka normal backend config; no native gate claim")
}
