//go:build linux

package guardd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/orka-agents/orka/internal/acp"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Uses the same real Guardd transport, signed native activation and held helper
// as the Codex path. This fixture exercises lifecycle cuts, not model behavior.
func TestRealGuarddCancellationReplacementCleanupRetry(t *testing.T) {
	root := os.Getenv("ORKA_REAL_NETWORK_ROOT")
	if root == "" {
		t.Skip("explicit disposable native backend required")
	}
	if err := os.Chmod(root, 0711); err != nil {
		t.Fatal(err)
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
	if err = b.RetireUnfinished(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(os.Getenv("ORKA_NETWORK_REQUIREMENT"))
	if err != nil {
		t.Fatal(err)
	}
	var requirement v2.ExecutionRequirement
	if err = json.Unmarshal(raw, &requirement); err != nil {
		t.Fatal(err)
	}
	fence := v2.Fence{RuntimeInstanceID: "native-lifecycle.instance", SupervisorBootID: "native-lifecycle.boot", ControllerEpoch: 1, RuntimePoolUID: "native-lifecycle-pool", RuntimePoolGeneration: 1, RuntimeSessionUID: "native-lifecycle-session", RuntimeSessionGeneration: 1, RuntimeProfileDigest: v2.ProfileDigest("sha256:" + strings.Repeat("a", 64)), ProfileDigestSchemaVersion: v2.ProfileDigestSchemaVersion}
	newLaunch := func(index int) (*launch, acp.ProcessConfig, string) {
		t.Helper()
		request := v2.CreateRuntimeSessionRequest{RuntimeSessionID: "native-lifecycle-session", Requirement: &requirement, Metadata: v2.MutationMetadata{TaskUID: "native-lifecycle-task", TaskAttempt: uint32(index), Fence: fence, OperationID: v2.OperationID(fmt.Sprintf("create-%d", index)), RequestDigest: v2.RequestDigest("sha256:" + strings.Repeat(fmt.Sprint(index), 64))}}
		enforcer, e := b.Launch(ctx, request)
		if e != nil {
			t.Fatal(e)
		}
		l := enforcer.(*launch)
		dir := filepath.Join(root, fmt.Sprintf("child-%d", index))
		if e = os.MkdirAll(dir, 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.Chmod(dir, 0777); e != nil {
			t.Fatal(e)
		}
		marker := filepath.Join(dir, "entrypoint")
		cfg := acp.ProcessConfig{Command: "/bin/sh", Args: []string{"-c", "printf entered > '" + marker + "'; exec /bin/sleep 90"}, Paths: acp.SessionPaths{Workspace: dir}, UID: 43000 + index, GID: 43000 + index, ExecHelperCommand: "/tmp/suite-policy-implementation/native/orka-acp-exec-helper", LaunchContext: ctx}
		if e = l.Prepare(ctx, &cfg); e != nil {
			t.Fatal(e)
		}
		return l, cfg, marker
	}
	assertEmpty := func() {
		t.Helper()
		entries, e := os.ReadDir(b.StateRoot)
		if e != nil || len(entries) != 0 {
			t.Fatalf("association residue %v %v", entries, e)
		}
	}
	// Cancellation wins while the held helper has a complete real activation.
	l, cfg, marker := newLaunch(1)
	launchCtx, launchCancel := context.WithCancel(ctx)
	cfg.LaunchContext = launchCtx
	activated := make(chan struct{})
	original := cfg.BeforeExec
	cfg.BeforeExec = func(c context.Context, p *acp.Process) error {
		if e := original(c, p); e != nil {
			return e
		}
		close(activated)
		<-c.Done()
		return c.Err()
	}
	type outcome struct {
		p   *acp.Process
		err error
	}
	done := make(chan outcome, 1)
	go func() { p, e := acp.StartProcess(cfg); done <- outcome{p, e} }()
	select {
	case <-activated:
	case early := <-done:
		if early.p != nil {
			early.p.Stop(ctx, time.Second)
		}
		l.AbortPreparation(ctx)
		t.Fatalf("helper failed before activation: %v", early.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	observation := l.EnforcementStatus()
	if observation.Phase != "active" || observation.TargetIdentity == "" {
		t.Fatalf("held native activation status: %+v", observation)
	}
	cancelledIdentity := observation.TargetIdentity
	cancelledTarget := l.record.Cgroup
	launchCancel()
	if status := l.EnforcementStatus(); status.Phase != "cancelled" {
		t.Fatalf("late activation after cancellation: %+v", status)
	}
	result := <-done
	if result.p != nil {
		status, e := result.p.Stop(ctx, time.Second)
		if e != nil || !status.Proven {
			t.Fatalf("cancel cleanup %v %v", status, e)
		}
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", result.err)
	}
	if result.p != nil {
		if e := result.p.Release(); e == nil {
			t.Fatal("cancelled process was releasable")
		}
	}
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatalf("cancelled entrypoint ran or uncertain: %v", e)
	}
	assertEmpty()
	if status := l.EnforcementStatus(); status.Phase != "cleaned" {
		t.Fatalf("cancel cleanup status: %+v", status)
	}
	if _, e := os.Stat(cancelledTarget); !os.IsNotExist(e) {
		t.Fatalf("cancelled target retained: %v", e)
	}
	t.Log("actual native activation completed while held; cancellation won, no entrypoint or stale release, exact cleanup completed")
	// A required cleanup transport failure leaves exact ownership retryable.
	l, cfg, marker = newLaunch(2)
	p, err := acp.StartProcess(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), 20*time.Second)
		defer c()
		p.Stop(cleanup, time.Second)
	}()
	observation = l.EnforcementStatus()
	if observation.Phase != "active" || observation.TargetIdentity == cancelledIdentity {
		t.Fatalf("replacement stale activation: %+v", observation)
	}
	priorTarget := l.record.Cgroup
	priorEvidence := append([]byte(nil), l.record.Evidence...)
	if err = p.Release(); err != nil {
		t.Fatal(err)
	}
	for {
		if _, e := os.Stat(marker); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	oldSocket := b.Connection.Socket
	b.Connection.Socket = filepath.Join(root, "unavailable.sock")
	status, err := p.Stop(ctx, time.Second)
	if err == nil || status.Proven {
		t.Fatalf("false cleanup success %v %v", status, err)
	}
	if got := l.EnforcementStatus(); got.Phase != "cleanup-pending" {
		t.Fatalf("failed cleanup status: %+v", got)
	}
	if l.record == nil {
		t.Fatal("cleanup failure discarded exact ownership")
	}
	if _, e := os.Stat(l.record.Journal); e != nil {
		t.Fatal("cleanup journal missing", e)
	}
	if populated, e := os.ReadFile(filepath.Join(priorTarget, "cgroup.events")); e != nil || !strings.Contains(string(populated), "populated 0") {
		t.Fatalf("failed cleanup target not empty %s %v", populated, e)
	}
	b.Connection.Socket = oldSocket
	status, err = p.Stop(ctx, time.Second)
	if err != nil || !status.Proven {
		t.Fatalf("retry cleanup failed %v %v", status, err)
	}
	assertEmpty()
	if got := l.EnforcementStatus(); got.Phase != "cleaned" {
		t.Fatalf("retry cleanup status: %+v", got)
	}
	t.Log("real Guardd cleanup unavailable: no false proof, exact journal retained; restored transport retry cleaned the owned native target")
	// The next generation cannot reuse an old activation: target and evidence differ.
	l, cfg, marker = newLaunch(3)
	replacement, err := acp.StartProcess(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), 20*time.Second)
		defer c()
		replacement.Stop(cleanup, time.Second)
	}()
	if l.record.Cgroup == priorTarget || string(l.record.Evidence) == string(priorEvidence) {
		t.Fatal("replacement reused activation identity")
	}
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("replacement entered before explicit release")
	}
	if err = replacement.Release(); err != nil {
		t.Fatal(err)
	}
	for {
		if _, e := os.Stat(marker); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	status, err = replacement.Stop(ctx, time.Second)
	if err != nil || !status.Proven {
		t.Fatalf("replacement cleanup %v %v", status, err)
	}
	assertEmpty()
	t.Log("replacement held behind a fresh exact target and signed activation, old evidence not reused; new entrypoint and cleanup completed")
}
