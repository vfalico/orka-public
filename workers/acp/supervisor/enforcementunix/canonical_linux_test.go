//go:build linux

package enforcementunix

import (
	"encoding/json"
	"testing"
)

func TestCanonicalIdentityPreservesKernelIntegers(t *testing.T) {
	v := map[string]any{"cgroup": uint64(9007199254740993), "opaque": "<literal>"}
	copied := jsonMap(v)
	if copied["cgroup"] != json.Number("9007199254740993") {
		t.Fatal("identity rounded", copied)
	}
	if digest(v) != digest(copied) {
		t.Fatal("recovery identity changed")
	}
}
