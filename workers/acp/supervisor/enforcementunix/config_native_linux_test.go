//go:build linux

package enforcementunix

import (
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

// Real Pod cgroup discovery/configuration only: no policy, gate or workload
// enforcement claim. Explicit operator fixture must provision the mount.
func TestNativeDelegatedConfiguration(t *testing.T) {
	mount := os.Getenv("EXECUTION_NATIVE_CGROUP_MOUNT")
	if mount == "" {
		t.Skip("explicit delegated cgroup projection required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root operator fixture required")
	}
	root := t.TempDir()
	file := filepath.Join(root, "config.json")
	raw, e := json.Marshal(map[string]any{"Socket": "/run/peer/socket", "Name": "independent", "Revision": "v1", "CgroupMount": mount, "StateRoot": root, "NamespaceState": true})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	b, e := ReadBackendForInstance(file, "immutable-pod-uid")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := os.Remove(b.CgroupRoot); e != nil {
			t.Errorf("exact empty cgroup cleanup: %v", e)
		}
	}()
	if filepath.Base(b.CgroupRoot) != "orka-executions" || b.StateRoot != filepath.Join(root, "immutable-pod-uid") {
		t.Fatal("wrong ownership roots", b.CgroupRoot, b.StateRoot)
	}
	var st unix.Stat_t
	if e = unix.Stat(filepath.Dir(b.CgroupRoot), &st); e != nil {
		t.Fatal(e)
	}
	var visible unix.Stat_t
	if e = unix.Stat("/sys/fs/cgroup", &visible); e != nil {
		t.Fatal(e)
	}
	if st.Dev != visible.Dev || st.Ino != visible.Ino {
		t.Fatal("not our namespace root")
	}
	t.Logf("REAL_POD_DELEGATED_CONFIGURATION_PASS root=%s device=%d inode=%d; NO_POLICY_ACTIVATION", b.CgroupRoot, st.Dev, st.Ino)
}
