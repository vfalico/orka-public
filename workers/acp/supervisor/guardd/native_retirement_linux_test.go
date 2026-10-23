//go:build linux

package guardd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/acp"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
)

// Real Guardd activation and native cgroup deletion followed by local I/O
// failures. This complements (does not replace) the real Codex/network fixture.
func TestRealLocalRetirementFaults(t *testing.T) {
	root := os.Getenv("ORKA_REAL_NETWORK_ROOT")
	if root == "" {
		t.Skip("explicit disposable native backend required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	b, err := ReadBackend(filepath.Join(root, "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(b.CgroupRoot, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(os.Getenv("ORKA_NETWORK_REQUIREMENT"))
	if err != nil {
		t.Fatal(err)
	}
	var r v2.ExecutionRequirement
	if err = json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	for index, fault := range []string{"unlink", "open", "fsync", "crash"} {
		t.Run(fault, func(t *testing.T) {
			request := v2.CreateRuntimeSessionRequest{RuntimeSessionID: v2.RuntimeSessionID("retire-" + fault), Requirement: &r, Metadata: v2.MutationMetadata{Fence: v2.Fence{RuntimeInstanceID: "retire-instance", SupervisorBootID: "retire-boot", ControllerEpoch: 1, RuntimePoolUID: "pool", RuntimePoolGeneration: 1, RuntimeSessionUID: "session", RuntimeSessionGeneration: 1, RuntimeProfileDigest: v2.ProfileDigest("sha256:" + strings.Repeat("a", 64)), ProfileDigestSchemaVersion: v2.ProfileDigestSchemaVersion}, TaskUID: "retirement-task", TaskAttempt: uint32(index + 1), OperationID: v2.OperationID("retire-" + fault), RequestDigest: v2.RequestDigest("sha256:" + strings.Repeat("b", 64))}}
			enforcer, e := b.Launch(ctx, request)
			if e != nil {
				t.Fatal(e)
			}
			l := enforcer.(*launch)
			dir := filepath.Join(root, "retire-child-"+fault)
			if e = os.MkdirAll(dir, 0777); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(dir, 0777); e != nil {
				t.Fatal(e)
			}
			marker := filepath.Join(dir, "entrypoint")
			cfg := acp.ProcessConfig{Command: "/bin/sh", Args: []string{"-c", "touch '" + marker + "'; exec /bin/sleep 90"}, Paths: acp.SessionPaths{Workspace: dir}, UID: 44000 + index, GID: 44000 + index, ExecHelperCommand: "/tmp/suite-policy-implementation/native/orka-acp-exec-helper", LaunchContext: ctx}
			if e = l.Prepare(ctx, &cfg); e != nil {
				t.Fatal(e)
			}
			p, e := acp.StartProcess(cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer func() { b.retirement = nil; p.Stop(context.Background(), time.Second) }()
			a := l.record
			injected := errors.New("native local " + fault)
			b.retirement = &retirementIO{}
			switch fault {
			case "unlink", "crash":
				b.retirement.removeJournal = func(string) error { return injected }
			case "open":
				b.retirement.openParent = func(string) (*os.File, error) { return nil, injected }
			case "fsync":
				b.retirement.syncParent = func(*os.File) error { return injected }
			}
			stopped, e := p.Stop(ctx, time.Second)
			if e == nil || stopped.Proven {
				t.Fatalf("false terminal cleanup %v %v", stopped, e)
			}
			if _, e = os.Stat(a.Cgroup); !os.IsNotExist(e) {
				t.Fatalf("target not deleted before local fault %v", e)
			}
			if l.record != a || a.Retirement == nil || l.EnforcementStatus().Phase != "cleanup-pending" {
				t.Fatal("uncertainty not retained")
			}
			if _, e = os.Stat(a.Journal); e != nil {
				t.Fatal("checkpoint missing", e)
			}
			if _, e = os.Stat(marker); !os.IsNotExist(e) {
				t.Fatal("held entrypoint ran", e)
			}
			if e = p.Release(); e == nil {
				t.Fatal("stale release succeeded")
			}
			t.Logf("%s: real native cleanup complete, target removed, local failure visible; exact checkpoint retained; held entrypoint absent and stale release refused", fault)
			b.retirement = nil
			if fault == "crash" || fault == "open" {
				// Discard in-memory launch/backend state: only persisted journal proof is
				// available to conservative recovery. A replacement path is never ours.
				fresh, e := ReadBackend(filepath.Join(root, "backend.json"))
				if e != nil {
					t.Fatal(e)
				}
				if e = os.Mkdir(a.Cgroup, 0700); e != nil {
					t.Fatal(e)
				}
				if e = fresh.RetireUnfinished(ctx); e == nil {
					t.Fatal("replacement target retired")
				}
				if _, e = os.Stat(a.Cgroup); e != nil {
					t.Fatal("replacement touched", e)
				}
				if _, e = os.Stat(a.Journal); e != nil {
					t.Fatal("ownership discarded", e)
				}
				// Explicit exact empty test-owned replacement removal, not product cleanup.
				if e = os.Remove(a.Cgroup); e != nil {
					t.Fatal(e)
				}
				if fault == "crash" {
					executable, e := os.Executable()
					if e != nil {
						t.Fatal(e)
					}
					cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRealLocalRetirementRestartHelper$", "-test.v")
					cmd.Env = append(os.Environ(), "ORKA_RETIRE_RESTART_CHILD=1")
					output, e := cmd.CombinedOutput()
					t.Logf("independent restart process: %s", output)
					if e != nil {
						t.Fatal(e)
					}
				} else if e = fresh.RetireUnfinished(ctx); e != nil {
					t.Fatal(e)
				}
				t.Log("fresh backend rejected same-path replacement, then retired original absent target using cleanup-only durable checkpoint")
			} else {
				stopped, e = p.Stop(ctx, time.Second)
				if e != nil || !stopped.Proven {
					t.Fatalf("retry did not settle %v %v", stopped, e)
				}
			}
			entries, e := os.ReadDir(b.StateRoot)
			if e != nil || len(entries) != 0 {
				t.Fatalf("association residue %v %v", entries, e)
			}
			if _, e = os.Stat(a.Cgroup); !os.IsNotExist(e) {
				t.Fatal("cgroup residue", e)
			}
		})
	}
}

func TestRealLocalRetirementRestartHelper(t *testing.T) {
	if os.Getenv("ORKA_RETIRE_RESTART_CHILD") != "1" {
		t.Skip("subprocess recovery only")
	}
	b, err := ReadBackend(filepath.Join(os.Getenv("ORKA_REAL_NETWORK_ROOT"), "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = b.RetireUnfinished(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("fresh OS process retired checkpoint after cgroup deletion with no live target handle or prior Guardd connection")
}
