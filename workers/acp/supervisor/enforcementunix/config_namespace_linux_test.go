//go:build linux

package enforcementunix

import (
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustedConfigOptionalImmutableNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned operator config required")
	}
	root := t.TempDir()
	file := filepath.Join(root, "config.json")
	base := map[string]any{"Socket": "/run/peer/socket", "Name": "opaque", "Revision": "v1", "CgroupRoot": "/sys/fs/cgroup/owned", "StateRoot": "/var/lib/owned", "NamespaceState": true}
	raw, e := json.Marshal(base)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	b, e := ReadBackendForInstance(file, "pod-immutable-uid")
	if e != nil {
		t.Fatal(e)
	}
	if b.StateRoot != "/var/lib/owned/pod-immutable-uid" || b.CgroupRoot != base["CgroupRoot"] {
		t.Fatal("wrong scope")
	}
	for _, s := range []string{"", "../other", "x/y", " ", "a.b"} {
		if _, e = ReadBackendForInstance(file, s); e == nil {
			t.Fatalf("invalid immutable instance %q", s)
		}
	}
	base["NamespaceState"] = false
	raw, _ = json.Marshal(base)
	os.WriteFile(file, raw, 0600)
	b, e = ReadBackend(file)
	if e != nil || b.StateRoot != "/var/lib/owned" {
		t.Fatal("legacy config changed", e)
	}
	base["CgroupMount"] = "/run/cgroups"
	raw, _ = json.Marshal(base)
	os.WriteFile(file, raw, 0600)
	if _, e = ReadBackend(file); e == nil {
		t.Fatal("ambiguous roots accepted")
	}
	// Reject before delegated filesystem side effects, and never block on FIFO.
	delete(base, "CgroupRoot")
	base["NamespaceState"] = true
	base["CgroupMount"] = "/definitely-unmounted"
	raw, _ = json.Marshal(base)
	os.WriteFile(file, raw, 0600)
	if _, e = ReadBackendForInstance(file, "../foreign"); e == nil || !strings.Contains(e.Error(), "instance") {
		t.Fatal("namespace check must precede delegation", e)
	}
	os.Remove(file)
	if e = unix.Mkfifo(file, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadBackend(file); e == nil {
		t.Fatal("FIFO config accepted")
	}

	os.Remove(file)
	os.Symlink("missing", file)
	if _, e = ReadBackend(file); e == nil {
		t.Fatal("symlink accepted")
	}
}
