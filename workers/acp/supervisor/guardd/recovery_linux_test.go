//go:build linux

package guardd

import (
	"context"
	"encoding/json"
	"github.com/orka-agents/orka/internal/acp"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealRecoveryRetiresExactActiveTarget(t *testing.T) {
	root := os.Getenv("ORKA_REAL_NETWORK_ROOT")
	if root == "" {
		t.Skip("disposable native backend required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := ReadBackend(filepath.Join(root, "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(b.CgroupRoot, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(b.CgroupRoot)
	raw, err := os.ReadFile(os.Getenv("ORKA_NETWORK_REQUIREMENT"))
	if err != nil {
		t.Fatal(err)
	}
	var r v2.ExecutionRequirement
	if err = json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	fence := v2.Fence{RuntimeInstanceID: "instance", SupervisorBootID: "boot", ControllerEpoch: 1, RuntimePoolUID: "pool", RuntimePoolGeneration: 1, RuntimeSessionUID: "session", RuntimeSessionGeneration: 1, RuntimeProfileDigest: v2.ProfileDigest("sha256:" + strings.Repeat("a", 64)), ProfileDigestSchemaVersion: v2.ProfileDigestSchemaVersion}
	request := v2.CreateRuntimeSessionRequest{RuntimeSessionID: "recovery", Requirement: &r, Metadata: v2.MutationMetadata{TaskUID: "task", TaskAttempt: 1, Fence: fence, OperationID: "create-recovery", RequestDigest: v2.RequestDigest("sha256:" + strings.Repeat("b", 64))}}
	enforcer, err := b.Launch(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	l := enforcer.(*launch)
	dir := filepath.Join(root, "recovery-child")
	if err = os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := acp.ProcessConfig{Command: "/bin/sleep", Args: []string{"60"}, Paths: acp.SessionPaths{Workspace: dir}, UID: 24002, GID: 24002, ExecHelperCommand: "/tmp/suite-policy-implementation/native/orka-acp-exec-helper"}
	if err = l.Prepare(ctx, &cfg); err != nil {
		t.Fatal(err)
	}
	p, err := acp.StartProcess(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// This is a real active kernel target but not an agent claim: the main native
	// Codex test establishes agent behavior separately. Recovery has no release.
	if err = p.Release(); err != nil {
		t.Fatal(err)
	}
	originalFD := l.record.FD
	restarted, err := ReadBackend(filepath.Join(root, "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Launch(ctx, request); err == nil {
		t.Fatal("restart adopted unfinished target")
	}
	if err = restarted.RetireUnfinished(ctx); err != nil {
		t.Fatal(err)
	}
	_ = p.Wait(ctx)
	entries, err := os.ReadDir(b.StateRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("recovery residue %v %v", entries, err)
	}
	if _, err = os.Stat(l.record.Cgroup); !os.IsNotExist(err) {
		t.Fatal("recovery did not retire exact target")
	}
	// Original in-memory holder is deliberately not re-used as authority.
	os.NewFile(uintptr(originalFD), "old-cgroup").Close()
	t.Log("fresh backend refused adoption, killed exact live cgroup, cleaned kernel pins and durable association without releasing a replacement")
}
