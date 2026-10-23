package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	core "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/executionmode"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
	kubestore "github.com/orka-agents/orka/internal/store/kube"
	"github.com/orka-agents/orka/internal/store/sqlite"
	"github.com/orka-agents/orka/internal/tools"
	coord "k8s.io/api/coordination/v1"
	kcore "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
	"testing"
	"time"
)

// Explicit disposable integration: every Task write and observation goes to the
// actual API server. No fake client, injected Task status, or synthetic result.
func TestLiveKaimahiControllerGuarddNative(t *testing.T) {
	root := os.Getenv("ORKA_LIVE_ROOT")
	if root == "" {
		t.Skip("explicit isolated cluster required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err = core.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kcore.AddToScheme(scheme)
	coord.AddToScheme(scheme)
	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.NewDB(filepath.Join(root, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	persistence := sqlite.NewStore(db, "live-disposable")
	cipher, err := sqlite.NewAgentExecutionSnapshotCipher(bytes.Repeat([]byte{0x61}, sqlite.AgentExecutionSnapshotKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err = persistence.SetAgentExecutionSnapshotCipher(cipher); err != nil {
		t.Fatal(err)
	}
	controls, err := kubestore.NewComposite(c, "orka-system", persistence, kubestore.WithAPIReader(c))
	if err != nil {
		t.Fatal(err)
	}
	epochs := NewControllerEpochManager(controls, "live-disposable")
	epochDone := make(chan error, 1)
	go func() { epochDone <- epochs.Start(ctx) }()
	defer func() { cancel(); <-epochDone }()
	epoch, err := epochs.CurrentFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	images := ACPRuntimeImages{Codex: "docker.io/example/qualified-host-runtime@sha256:" + strings.Repeat("a", 64)}
	reconciler := &TaskReconciler{Client: c, APIReader: c, Scheme: scheme, ResultStore: persistence, PlanStore: persistence, MessageStore: persistence, DurableControlStore: controls, AgentExecutionSnapshots: persistence, ControllerEpochManager: epochs, ExecutionEventStore: persistence, Recorder: record.NewFakeRecorder(200), ACPRuntimeEnabled: true, ACPRuntimeImages: images, ACPRuntimeNamespace: "orka-system", Mode: executionmode.HarnessV2, MCPRegistry: tools.NewRegistry()}
	continuity, err := NewACPSessionContinuity(ACPSessionContinuityConfig{SessionControls: controls, Transcripts: persistence, Publications: controls, BranchClaims: controls, Lineages: persistence})
	if err != nil {
		t.Fatal(err)
	}
	d := &ACPDispatcher{Client: c, APIReader: c, Store: controls, ResultStore: persistence, EventStore: persistence, PlanStore: persistence, Snapshots: persistence, Epochs: epochs, Sessions: continuity, Interval: 50 * time.Millisecond, ACPRuntimeImages: images}
	// Kaimahi's real CLI creates the Task and reads the real result API through
	// kubectl port-forward to a task-owned relay Pod in the isolated cluster.
	kmx, kubeContext := os.Getenv("ORKA_LIVE_KMX"), os.Getenv("ORKA_LIVE_CONTEXT")
	if kmx == "" || kubeContext == "" {
		t.Fatal("ORKA_LIVE_KMX and ORKA_LIVE_CONTEXT are required for the isolated live fixture")
	}
	command := exec.CommandContext(ctx, kmx, "--context", kubeContext, "run", "--agent", "sample", "--namespace", "orka-system", "--policy-workspace", filepath.Join(root, "workspace"), "--prompt", "Probe the authored network ceiling and answer NETWORK_NATIVE_OK.", "--wait", "2m")
	var output, diagnostics bytes.Buffer
	command.Stdout = &output
	command.Stderr = &diagnostics
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	kmxDone := make(chan error, 1)
	go func() { kmxDone <- command.Wait() }()
	var task core.Task
	for {
		var list core.TaskList
		if err = c.List(ctx, &list, client.InNamespace("orka-system")); err != nil {
			t.Fatal(err)
		}
		if len(list.Items) == 1 {
			task = list.Items[0]
			break
		}
		select {
		case err = <-kmxDone:
			t.Fatalf("kmx failed before submission %v %s", err, diagnostics.String())
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	raw, _ := json.MarshalIndent(task, "", "  ")
	os.WriteFile(filepath.Join(root, "live-submitted-task.json"), raw, 0600)
	if task.Spec.Execution == nil || task.Spec.Execution.Requirement == nil {
		t.Fatal("Kaimahi Task omitted mandatory policy")
	}
	agent := &core.Agent{}
	if err = c.Get(ctx, client.ObjectKey{Namespace: "orka-system", Name: "sample"}, agent); err != nil {
		t.Fatal(err)
	}
	plan := frozenACPDispatcherPlanForTest(t, &task, agent, images)
	// Existing queue logic creates the real pool and immutable control records.
	var pool core.RuntimePool
	for i := 0; i < 40; i++ {
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&task)})
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Get(ctx, client.ObjectKeyFromObject(&task), &task); err != nil {
			t.Fatal(err)
		}
		if task.Status.AgentExecutionBinding != nil && task.Status.Execution != nil {
			verified, e := reconciler.loadVerifiedBoundExecution(ctx, &task, task.Status.AgentExecutionBinding)
			if e != nil {
				t.Fatal(e)
			}
			plan = verified.plan
			err = c.Get(ctx, client.ObjectKey{Namespace: task.Namespace, Name: task.Status.Execution.RuntimePoolName}, &pool)
		} else {
			err = fmt.Errorf("not yet queued")
		}
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("pool was not queued: %v", err)
	}
	token := strings.Repeat("t", 32)
	capability := []byte(strings.Repeat("s", 32))
	secret := &kcore.Secret{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("live-auth-e%d", epoch.Epoch), Namespace: "orka-system", Labels: map[string]string{runtimePoolUIDLabel: string(pool.UID), runtimePoolAuthLabel: "true", runtimePoolCredentialEpochLabel: fmt.Sprint(epoch.Epoch)}}, Data: map[string][]byte{runtimePoolControllerTokenKey: []byte(token), runtimePoolCapabilitySecretKey: capability}}
	if err = c.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	fence := v2.Fence{RuntimeInstanceID: "live-host.instance", SupervisorBootID: "live-host.boot", ControllerEpoch: uint64(epoch.Epoch), RuntimePoolUID: v2.RuntimePoolUID(pool.UID), RuntimePoolGeneration: uint64(pool.Generation), RuntimeProfileDigest: plan.Digest, ProfileDigestSchemaVersion: v2.ProfileDigestSchemaVersion}
	startup := struct {
		Profile v2.RuntimeProfile
		Fence   v2.Fence
	}{plan.Profile, fence}
	raw, _ = json.Marshal(startup)
	if err = os.WriteFile(filepath.Join(root, "runtime-plan.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Trusted qualification infrastructure starts the real supervisor. This is
	// manually provisioned pool infrastructure, not a pool-operator rollout test.
	for {
		conn, e := net.DialTimeout("tcp", "127.0.0.1:28285", 100*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	pool.Status.Lifecycle = core.RuntimePoolLifecycleServing
	pool.Status.AdmissionState = core.RuntimePoolAdmissionAccepting
	pool.Status.ActiveInstance = &core.RuntimePoolActiveInstanceStatus{PodNamespace: "orka-system", PodName: "qualified-host-supervisor", PodUID: "qualified-host-supervisor", PodAddress: "127.0.0.1:28285", RuntimeInstanceID: string(fence.RuntimeInstanceID), BootID: string(fence.SupervisorBootID), ControllerEpoch: epoch.Epoch, ProtocolVersion: core.RuntimePoolProtocolHarnessV2, ProfileDigest: string(plan.Digest), ProfileDigestSchemaVersion: "1", ProviderTokenGeneration: "1111111111111111"}
	pool.Status.ObservedGeneration = pool.Generation
	if err = c.Status().Update(ctx, &pool); err != nil {
		t.Fatal(err)
	}
	dispatchDone := make(chan error, 1)
	go func() { dispatchDone <- d.Start(ctx) }()
	defer func() {
		cancel()
		if e := <-dispatchDone; e != nil {
			t.Log("dispatcher shutdown", e)
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err = <-kmxDone:
			os.WriteFile(filepath.Join(root, "kmx-stdout.log"), output.Bytes(), 0600)
			os.WriteFile(filepath.Join(root, "kmx-stderr.log"), diagnostics.Bytes(), 0600)
			if os.Getenv("ORKA_LIVE_MODE") != "" {
				if err == nil {
					t.Fatal("failed mandatory execution reported CLI success")
				}
				if e := c.Get(ctx, client.ObjectKeyFromObject(&task), &task); e != nil {
					t.Fatal(e)
				}
				raw, e := json.MarshalIndent(task, "", "  ")
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(root, "live-terminal-task.json"), raw, 0600); e != nil {
					t.Fatal(e)
				}
				if task.Status.Phase != core.TaskPhaseFailed {
					t.Fatalf("mandatory failure terminal phase: %s", task.Status.Phase)
				}
				t.Logf("live %s: actual kmx nonzero, actual Task Failed, no successful result", os.Getenv("ORKA_LIVE_MODE"))
				return
			}
			if err != nil {
				t.Fatalf("kmx result %v\n%s\n%s", err, output.String(), diagnostics.String())
			}
			if !strings.Contains(output.String(), "NETWORK_NATIVE_OK") {
				t.Fatal("native result missing", output.String())
			}
			if err = c.Get(ctx, client.ObjectKeyFromObject(&task), &task); err != nil {
				t.Fatal(err)
			}
			raw, _ = json.MarshalIndent(task, "", "  ")
			os.WriteFile(filepath.Join(root, "live-terminal-task.json"), raw, 0600)
			if task.Status.Phase != core.TaskPhaseSucceeded {
				t.Fatalf("unexpected actual terminal phase %s", task.Status.Phase)
			}
			t.Log("Actual kmx CLI -> isolated Kubernetes Task -> immutable snapshot -> ordinary reconciler queue -> ACP dispatcher -> native Guardd supervisor -> result API -> actual kmx stdout PASS")
			return
		case <-ctx.Done():
			t.Fatalf("deadline: %v kmx=%s", ctx.Err(), diagnostics.String())
		case <-ticker.C:
			if _, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&task)}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
		}
	}
}
