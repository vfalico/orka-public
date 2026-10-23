//go:build linux

package guardd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v2 "github.com/orka-agents/orka/internal/harness/v2"
	"golang.org/x/sys/unix"
)

func retirementFixture(t *testing.T) (*Backend, *launch, *association) {
	t.Helper()
	root := t.TempDir()
	b := &Backend{Name: "guardd", Revision: "retire", CgroupRoot: filepath.Join(root, "cgroups"), StateRoot: filepath.Join(root, "state")}
	for _, path := range []string{b.CgroupRoot, b.StateRoot} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(b.CgroupRoot, "exact")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	r := &v2.ExecutionRequirement{Identity: "sha256:" + strings.Repeat("a", 64)}
	a := &association{Backend: b.Identity(), Binding: map[string]any{"generation": uint64(1), "session_id": "original"}, Target: map[string]any{"pid": 42, "start": "original"}, Requirement: r, Cgroup: path, Journal: filepath.Join(b.StateRoot, "exact.json"), FD: fd, Phase: "local-retirement"}
	a.Retirement, err = newRetirementCheckpoint(a)
	if err != nil {
		t.Fatal(err)
	}
	if err = persist(a); err != nil {
		t.Fatal(err)
	}
	l := &launch{backend: b, record: a, request: v2.CreateRuntimeSessionRequest{Requirement: r}}
	return b, l, a
}

func TestLocalRetirementFaultRetry(t *testing.T) {
	for _, fault := range []string{"unlink", "open", "fsync"} {
		for _, restart := range []bool{false, true} {
			t.Run(fault+map[bool]string{false: "/retry", true: "/restart"}[restart], func(t *testing.T) {
				b, l, a := retirementFixture(t)
				injected := errors.New("injected " + fault)
				b.retirement = &retirementIO{}
				switch fault {
				case "unlink":
					b.retirement.removeJournal = func(string) error { return injected }
				case "open":
					b.retirement.openParent = func(string) (*os.File, error) { return nil, injected }
				case "fsync":
					b.retirement.syncParent = func(*os.File) error { return injected }
				}
				if err := l.cleanup(context.Background(), a); !errors.Is(err, injected) {
					t.Fatalf("fault not observed: %v", err)
				}
				if _, err := os.Stat(a.Cgroup); !os.IsNotExist(err) {
					t.Fatalf("fault must follow target deletion: %v", err)
				}
				if l.record != a || l.EnforcementStatus().Phase != "cleanup-pending" {
					t.Fatal("uncertainty hidden")
				}
				raw, err := os.ReadFile(a.Journal)
				if err != nil {
					t.Fatalf("ownership not visible: %v", err)
				}
				var disk association
				if err = json.Unmarshal(raw, &disk); err != nil {
					t.Fatal(err)
				}
				if err = validateRetirement(&disk); err != nil {
					t.Fatal(err)
				}
				b.retirement = nil
				if restart {
					if os.Geteuid() != 0 {
						t.Skip("root-owned journal recovery requires root; retry covered separately")
					}
					fresh := &Backend{Name: b.Name, Revision: b.Revision, CgroupRoot: b.CgroupRoot, StateRoot: b.StateRoot}
					if err = fresh.RetireUnfinished(context.Background()); err != nil {
						t.Fatal(err)
					}
				} else {
					// No transport is configured. Success proves no deleted FD was sent back
					// to Guardd; deleted-target validation remains unchanged there.
					if err = l.cleanup(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					if l.record != nil || l.EnforcementStatus().Phase != "cleaned" {
						t.Fatal("retirement did not settle")
					}
				}
				entries, err := os.ReadDir(b.StateRoot)
				if err != nil || len(entries) != 0 {
					t.Fatalf("retirement residue %v %v", entries, err)
				}
			})
		}
	}
}

func TestLocalRetirementRejectsSubstitution(t *testing.T) {
	for _, field := range []string{"binding", "target", "requirement", "backend", "boot", "missing-proof", "replacement"} {
		t.Run(field, func(t *testing.T) {
			_, l, a := retirementFixture(t)
			switch field {
			case "binding":
				a.Binding["session_id"] = "replacement"
			case "target":
				a.Target["start"] = "replacement"
			case "requirement":
				a.Requirement.Identity = "replacement"
			case "backend":
				a.Backend = "replacement"
			case "boot":
				a.Retirement.Boot = "replacement"
			case "missing-proof":
				a.Retirement = nil
			case "replacement":
				// Keep the original inode alive under a different path; no inode reuse.
				if err := os.Rename(a.Cgroup, a.Cgroup+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(a.Cgroup, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := l.cleanup(context.Background(), a); err == nil {
				t.Fatal("substitution retired")
			}
			if l.record == nil {
				t.Fatal("ownership lost")
			}
			if _, err := os.Stat(a.Cgroup); err != nil {
				t.Fatal("replacement/original target touched", err)
			}
			if _, err := os.Stat(a.Journal); err != nil {
				t.Fatal("journal discarded", err)
			}
		})
	}
}

func TestLocalRetirementRestartAfterDeletion(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned journal recovery requires root")
	}
	b, _, a := retirementFixture(t)
	if err := os.Remove(a.Cgroup); err != nil {
		t.Fatal(err)
	} // crash after deletion, before unlink
	fresh := &Backend{Name: b.Name, Revision: b.Revision, CgroupRoot: b.CgroupRoot, StateRoot: b.StateRoot}
	if err := fresh.RetireUnfinished(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.Journal); !os.IsNotExist(err) {
		t.Fatal("restart retirement unfinished", err)
	}
	// An absent target without a completed cleanup proof remains uncertain.
	a.Retirement = nil
	a.Phase = "cleanup-pending"
	if err := persist(a); err != nil {
		t.Fatal(err)
	}
	if err := fresh.RetireUnfinished(context.Background()); err == nil {
		t.Fatal("uncertain absent target discarded")
	}
	if _, err := os.Stat(a.Journal); err != nil {
		t.Fatal("uncertain ownership lost", err)
	}
}
