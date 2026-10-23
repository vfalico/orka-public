//go:build linux

package enforcementunix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in recovery uses only this root's durable exact associations; no release.
func TestNativeRestartCleanupOnly(t *testing.T) {
	root := os.Getenv("ORKA_NATIVE_RECOVER_ROOT")
	if root == "" {
		t.Skip("explicit task-owned failed incarnation required")
	}
	b, err := ReadBackend(filepath.Join(root, "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err = b.RetireUnfinished(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(b.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("association residue", entries)
	}
	entries, err = os.ReadDir(b.CgroupRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatal("child cgroup residue", entry.Name())
		}
	}
	raw, err := os.ReadFile(filepath.Join(b.CgroupRoot, "cgroup.procs"))
	if err != nil || len(raw) != 0 {
		t.Fatal("process residue", string(raw), err)
	}
	t.Log("NATIVE_RESTART_CLEANUP_ONLY_PASS exact persisted association retired; no workload released")
}
