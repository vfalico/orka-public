//go:build linux

package enforcementunix

import (
	"context"
	"fmt"
	"github.com/orka-agents/orka/internal/acp"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This independent peer does NOT enforce kernel restrictions. The test proves
// Orka's real trusted held-exec gate consumes a non-Suite configured backend.
func TestIndependentOpaquePeerHeldExecGate(t *testing.T) {
	config := os.Getenv("ORKA_TEST_PEER_CONFIG")
	root := os.Getenv("ORKA_TEST_PEER_GATE_ROOT")
	if config == "" || root == "" {
		t.Skip("explicit disposable independent TEST peer gate resources required")
	}
	b, err := ReadBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(b.CgroupRoot, 0700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(b.CgroupRoot); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	for index, scenario := range []string{"supported", "refused", "cancel-before-release"} {
		t.Run(scenario, func(t *testing.T) {
			r := &v2.ExecutionRequirement{Format: "test.opaque/v1", PolicyBytes: []byte("not-a-Suite-policy\x00"), RequiredCapabilities: []string{"test/opaque/v1"}, PayloadDigest: "sha256:" + strings.Repeat("1", 64)}
			if scenario == "refused" {
				r.RequiredCapabilities = append(r.RequiredCapabilities, "test/refuse-activation")
			}
			r.Identity = r.ContentIdentity()
			yes, err := b.Support(ctx, r, "test-target")
			if err != nil || !yes {
				t.Fatal(yes, err)
			}
			request := v2.CreateRuntimeSessionRequest{RuntimeSessionID: v2.RuntimeSessionID("opaque-" + scenario), Requirement: r, Metadata: v2.MutationMetadata{OperationID: v2.OperationID("opaque-" + scenario), RequestDigest: v2.RequestDigest("sha256:" + strings.Repeat("2", 64))}}
			enforcer, err := b.Launch(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, scenario)
			if err = os.MkdirAll(dir, 0777); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(dir, 0777); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, "entrypoint")
			cfg := acp.ProcessConfig{Command: "/bin/sh", Args: []string{"-c", "touch '" + marker + "'; exec /bin/sleep 30"}, Environment: []string{"PATH=/usr/bin:/bin"}, Paths: acp.SessionPaths{Workspace: dir}, UID: 45000 + index, GID: 45000 + index, ExecHelperCommand: os.Getenv("ORKA_NEUTRAL_EXEC_HELPER"), LaunchContext: ctx}
			if err = enforcer.Prepare(ctx, &cfg); err != nil {
				t.Fatal(err)
			}
			p, launchErr := acp.StartProcess(cfg)
			if p != nil {
				defer func() {
					status, err := p.Stop(context.Background(), time.Second)
					if err != nil || !status.Proven {
						t.Errorf("exact process cleanup %+v %v", status, err)
					}
				}()
			}
			if _, err = os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("entrypoint before explicit release: %v", err)
			}
			if scenario == "refused" {
				if launchErr == nil {
					t.Fatal("refused activation started")
				}
				if p == nil {
					t.Fatal("expected held process ownership for refusal")
				}
				status, err := p.Stop(ctx, time.Second)
				if err != nil || !status.Proven {
					t.Fatal(status, err)
				}
				if err = p.Release(); err == nil {
					t.Fatal("failed gate released")
				}
			} else {
				if launchErr != nil {
					t.Fatal(launchErr)
				}
				if p.LaunchState() != "held" {
					t.Fatal(p.LaunchState())
				}
				if scenario == "cancel-before-release" {
					status, err := p.Stop(ctx, time.Second)
					if err != nil || !status.Proven {
						t.Fatal(status, err)
					}
					if err = p.Release(); err == nil {
						t.Fatal("stop lost release race")
					}
				} else {
					if err = p.Release(); err != nil {
						t.Fatal(err)
					}
					deadline := time.Now().Add(3 * time.Second)
					for {
						if _, err = os.Stat(marker); err == nil {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("released child marker absent", err)
						}
						time.Sleep(10 * time.Millisecond)
					}
					status, err := p.Stop(ctx, time.Second)
					if err != nil || !status.Proven {
						t.Fatal(status, err)
					}
				}
			}
			if scenario != "supported" {
				if _, err = os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("refused/cancelled child ran", err)
				}
			}
			records, err := os.ReadDir(b.StateRoot)
			if err != nil || len(records) != 0 {
				t.Fatal("retained association after exact cleanup", records, err)
			}
			t.Log(fmt.Sprintf("INDEPENDENT_OPAQUE_REAL_HELD_EXEC_%s_PASS no Guardd import and exact cleanup", scenario))
		})
	}
}
