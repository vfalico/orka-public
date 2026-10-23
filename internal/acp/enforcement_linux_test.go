//go:build linux

package acp

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Uses the real helper and atomic clone-to-cgroup placement. These tests do not
// assert network semantics; they prove the shared pre-exec/release funnel.
type funnelEnforcer struct {
	group                       string
	fd                          int
	prepareCount, cleanupCount  int
	failActivation, failCleanup bool
	entered                     chan struct{}
	wait                        chan struct{}
	pid                         int
	generation                  int
}

func (e *funnelEnforcer) Prepare(ctx context.Context, cfg *ProcessConfig) error {
	e.prepareCount++
	e.generation++
	group := filepath.Join(e.group, time.Now().Format("150405.000000000"))
	if err := os.Mkdir(group, 0700); err != nil {
		return err
	}
	fd, err := unix.Open(group, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	e.fd = fd
	cfg.CgroupFD = fd
	cfg.BeforeExec = func(ctx context.Context, p *Process) error {
		e.pid = p.PID()
		p.SetEnforcementCleanup(func(context.Context) error {
			e.cleanupCount++
			if e.failCleanup {
				return errors.New("injected cleanup failure")
			}
			if err := os.Remove(group); err != nil {
				return err
			}
			unix.Close(fd)
			return nil
		})
		if e.entered != nil {
			close(e.entered)
		}
		if e.wait != nil {
			select {
			case <-e.wait:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if e.failActivation {
			return errors.New("injected activation uncertainty")
		}
		return nil
	}
	return nil
}
func (e *funnelEnforcer) AbortPreparation(context.Context) error { return nil }
func enforcementRoot(t *testing.T) string {
	t.Helper()
	if os.Getenv("ORKA_REAL_FUNNEL_TESTS") == "" {
		t.Skip("requires disposable root cgroup-v2 environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	p := "/sys/fs/cgroup/suite-policy-funnel"
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
	})
	return p
}
func funnelConfig(t *testing.T, e *funnelEnforcer) RuntimeSessionConfig {
	t.Helper()
	root, err := os.MkdirTemp("", "orka-funnel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	os.Chmod(root, 0755)
	paths, err := PrepareSessionPaths(filepath.Join(root, "sessions"), "test-session")
	if err != nil {
		t.Fatal(err)
	}
	if err := FinalizeSessionOwnership(paths.Root, 24002, 24002); err != nil {
		t.Fatal(err)
	}
	env, err := BuildChildEnvironment(paths, EnvironmentConfig{Values: map[string]string{"GO_WANT_ACP_HELPER": "1", "ACP_HELPER_MODE": "immediate"}})
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeSessionConfig{ID: "test-session", Generation: 1, ProfileDigest: "sha256:profile", Enforcer: e, Process: ProcessConfig{Command: testAdapterCommand(t), Args: []string{"-test.run=TestACPHelperProcess"}, Environment: env, Paths: paths, UID: 24002, GID: 24002, ExecHelperCommand: testExecHelperCommand(t)}, PromptLease: time.Second, CancelGrace: time.Second}
}

func TestGovernedFunnelFailureAndCancellationNeverExec(t *testing.T) {
	root := enforcementRoot(t)
	for _, cancelCase := range []bool{false, true} {
		t.Run(map[bool]string{false: "activation-failure", true: "cancel-wins"}[cancelCase], func(t *testing.T) {
			e := &funnelEnforcer{group: root, failActivation: !cancelCase}
			cfg := funnelConfig(t, e)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if cancelCase {
				e.entered = make(chan struct{})
				e.wait = make(chan struct{})
				go func() { <-e.entered; cancel() }()
			}
			_, err := NewRuntimeSession(ctx, cfg)
			if err == nil {
				t.Fatal("failed/cancelled activation released")
			}
			if e.prepareCount != 1 || e.cleanupCount != 1 {
				t.Fatalf("ownership %d %d", e.prepareCount, e.cleanupCount)
			}
			if _, err := os.Stat(filepath.Join(cfg.Process.Paths.Home, "native-session-counter")); err == nil {
				t.Fatal("agent entrypoint ran before activation")
			}
		})
	}
}
func TestGovernedFunnelCleanupFailureIsRetryable(t *testing.T) {
	e := &funnelEnforcer{group: enforcementRoot(t), failActivation: true, failCleanup: true}
	cfg := funnelConfig(t, e)
	_, err := NewRuntimeSession(context.Background(), cfg)
	var initErr *InitializationError
	if !errors.As(err, &initErr) || initErr.Cleanup.Proven {
		t.Fatalf("cleanup uncertainty lost: %v", err)
	}
	if initErr.RuntimeSession() == nil {
		t.Fatal("cleanup session ownership lost")
	}
	e.failCleanup = false
	status, err := initErr.RuntimeSession().Delete(context.Background())
	if err != nil || !status.Proven || e.cleanupCount != 2 {
		t.Fatalf("cleanup retry %+v %v count=%d", status, err, e.cleanupCount)
	}
}
func TestGovernedFunnelReleaseExactlyOnceAndStopWins(t *testing.T) {
	e := &funnelEnforcer{group: enforcementRoot(t)}
	cfg := funnelConfig(t, e)
	cfg.Process.Args = []string{"-test.run=TestACPHelperProcess"}
	if err := e.Prepare(context.Background(), &cfg.Process); err != nil {
		t.Fatal(err)
	}
	p, err := StartProcess(cfg.Process)
	if err != nil {
		t.Fatal(err)
	}
	status, err := p.Stop(context.Background(), time.Second)
	if err != nil || !status.Proven {
		t.Fatalf("stop %+v %v", status, err)
	}
	if err = p.Release(); err == nil || !strings.Contains(err.Error(), "stop won") {
		t.Fatalf("release after stop: %v", err)
	}
	e2 := &funnelEnforcer{group: e.group}
	cfg = funnelConfig(t, e2)
	if err = e2.Prepare(context.Background(), &cfg.Process); err != nil {
		t.Fatal(err)
	}
	p, err = StartProcess(cfg.Process)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background(), time.Second)
	if err = p.Release(); err != nil {
		t.Fatal(err)
	}
	if err = p.Release(); err == nil {
		t.Fatal("duplicate release accepted")
	}
}
func TestGovernedFunnelInitialAndReplacementUseFreshTarget(t *testing.T) {
	e := &funnelEnforcer{group: enforcementRoot(t)}
	cfg := funnelConfig(t, e)
	s, err := NewRuntimeSession(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Delete(context.Background())
	old := s.process
	status, err := old.Stop(context.Background(), time.Second)
	if err != nil || !status.Proven {
		t.Fatalf("initial cleanup %+v %v", status, err)
	}
	replacement, _, err := s.launchAdapter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Stop(context.Background(), time.Second)
	if replacement.PID() == old.PID() || e.prepareCount != 2 || e.generation != 2 {
		t.Fatal("replacement reused activation target")
	}
	t.Log("shared initial/replacement funnel prepared two fresh targets before either entrypoint")
}
