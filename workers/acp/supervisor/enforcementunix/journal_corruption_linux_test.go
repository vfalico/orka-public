//go:build linux

package enforcementunix

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	v2 "github.com/orka-agents/orka/internal/harness/v2"
)

func TestRecoveryRejectsCorruptJournalWithoutTargetEffects(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned journal recovery")
	}
	for _, scenario := range []string{"missing-cgroup", "wrong-cgroup-type", "missing-device", "missing-inode", "missing-requirement", "trailing-object", "trailing-garbage", "oversized", "directory", "fifo", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			b := &Backend{Name: "fixture", Revision: "corrupt", CgroupRoot: t.TempDir(), StateRoot: t.TempDir()}
			target := filepath.Join(b.CgroupRoot, "exact")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			// A regular sentinel: even attempts to write cgroup.kill are observable.
			sentinel := filepath.Join(target, "cgroup.kill")
			original := []byte("do not signal this target")
			if err := os.WriteFile(sentinel, original, 0600); err != nil {
				t.Fatal(err)
			}
			claimed := map[string]any{"dev": 1, "ino": 1}
			a := &association{Backend: b.Identity(), Cgroup: target, Target: map[string]any{"cgroup": claimed}, Requirement: &v2.ExecutionRequirement{Format: "opaque/v1"}, Phase: "activating"}
			switch scenario {
			case "missing-cgroup":
				delete(a.Target, "cgroup")
			case "wrong-cgroup-type":
				a.Target["cgroup"] = "wrong"
			case "missing-device":
				delete(claimed, "dev")
			case "missing-inode":
				delete(claimed, "ino")
			case "missing-requirement":
				a.Requirement = nil
			}
			raw, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "trailing-object":
				raw = append(raw, []byte(" {}")...)
			case "trailing-garbage":
				raw = append(raw, []byte(" garbage")...)
			case "oversized":
				raw = append(raw, bytes.Repeat([]byte(" "), 1<<20)...)
			}
			journal := filepath.Join(b.StateRoot, "exact.json")
			if scenario == "directory" {
				if err = os.Mkdir(journal, 0700); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "fifo" {
				if err = unix.Mkfifo(journal, 0600); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "symlink" {
				if err = os.Symlink(sentinel, journal); err != nil {
					t.Fatal(err)
				}
			} else if err = os.WriteFile(journal, raw, 0600); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err = b.RetireUnfinished(context.Background()); err == nil {
					t.Fatal("corrupt authority accepted")
				}
			}
			got, err := os.ReadFile(sentinel)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("target altered", string(got), err)
			}
			if scenario != "directory" && scenario != "fifo" && scenario != "symlink" {
				got, err = os.ReadFile(journal)
				if err != nil || !bytes.Equal(got, raw) {
					t.Fatal("uncertain journal lost or rewritten", err)
				}
			}
		})
	}
}
