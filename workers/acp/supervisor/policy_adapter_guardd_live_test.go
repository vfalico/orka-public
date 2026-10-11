//go:build linux

package supervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/acp"
	"github.com/orka-agents/orka/internal/harness/v2"
	policyresolver "github.com/orka-agents/orka/internal/policy"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLiveGuarddHeldStartActivation(t *testing.T) {
	if os.Getenv("ORKA_LIVE_GUARDD_E2E") != "1" {
		t.Skip("set ORKA_LIVE_GUARDD_E2E=1 and run as root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("live guardd E2E requires root")
	}
	guarddSource := os.Getenv("ORKA_LIVE_GUARDD_SOURCE")
	oci := os.Getenv("ORKA_LIVE_GUARDD_OCI")
	kmxBinary := os.Getenv("ORKA_LIVE_KMX_BIN")
	igBinary := os.Getenv("ORKA_LIVE_IG_BIN")
	gadgetDigest := os.Getenv("ORKA_LIVE_GADGET_DIGEST")
	if guarddSource == "" || oci == "" || kmxBinary == "" || igBinary == "" || gadgetDigest == "" {
		t.Fatal("ORKA_LIVE_GUARDD_SOURCE, ORKA_LIVE_GUARDD_OCI, ORKA_LIVE_KMX_BIN, ORKA_LIVE_IG_BIN, and ORKA_LIVE_GADGET_DIGEST are required")
	}
	temp := t.TempDir()
	socket := filepath.Join(temp, "guardd.sock")
	state := filepath.Join(temp, "state.db")
	authPrivate := filepath.Join(temp, "authorization-private.pem")
	authPublic := filepath.Join(temp, "authorization-public.pem")
	private := filepath.Join(temp, "receipt-private.pem")
	public := filepath.Join(temp, "receipt-public.pem")
	receipts := filepath.Join(temp, "orka-receipts")
	cgroupRoot := filepath.Join("/sys/fs/cgroup", "orka-guardd-live-"+strconv.Itoa(os.Getpid()))
	run(t, "openssl", "genpkey", "-algorithm", "ED25519", "-out", authPrivate)
	run(t, "chmod", "0600", authPrivate)
	run(t, "openssl", "pkey", "-in", authPrivate, "-pubout", "-out", authPublic)
	run(t, "openssl", "genpkey", "-algorithm", "ED25519", "-out", private)
	run(t, "chmod", "0600", private)
	run(t, "openssl", "pkey", "-in", private, "-pubout", "-out", public)
	igDigest := fileDigest(t, igBinary)
	ociDigest := fileDigest(t, oci)
	config := map[string]any{"node_id": "node-orka-live", "allowed_uids": []int{0}, "gadget_digest": gadgetDigest, "policy_digest_allowlist": []string{}, "ig_path": igBinary, "ig_sha256": igDigest, "oci_archive": oci, "oci_sha256": ociDigest, "bpftool_path": "/usr/sbin/bpftool", "socket_path": socket, "socket_mode": "0600", "state_db": state, "authorization_issuer_id": "orka-production", "authorization_public_key_file": authPublic, "max_policy_bytes": 262144, "freeze_timeout_s": 5.0, "stable_empty_s": 0.2, "receipt_private_key_file": private, "receipt_public_key_file": public}
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(temp, "guardd.json")
	if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(temp, "guardd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	launcher := filepath.Join(guarddSource, "packaging", "guardd-launch.py")
	daemon := exec.Command("python3", launcher, "--config", configPath)
	daemon.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(guarddSource, "src"))
	daemon.Stdout = logFile
	daemon.Stderr = logFile
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if daemon.Process != nil {
			_ = daemon.Process.Kill()
			_ = daemon.Wait()
		}
	}()
	waitForPath(t, socket, 10*time.Second)
	if err := os.Mkdir(cgroupRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cgroupRoot)

	repositoryRoot := repoRoot(t)
	helperDir := filepath.Join("/tmp", "orka-guardd-helper-"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(helperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(helperDir)
	helper := filepath.Join(helperDir, "orka-acp-exec-helper")
	build := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-o", helper, "./cmd/orka-acp-exec-helper")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build exec helper: %v: %s", err, output)
	}
	if err := os.Chmod(helper, 0o755); err != nil {
		t.Fatal(err)
	}
	token := strconv.FormatInt(time.Now().UnixNano(), 10)
	deny := filepath.Join("/tmp", "orka-guardd-deny-"+token)
	allow := filepath.Join("/tmp", "orka-guardd-allow-"+token)
	status := filepath.Join("/tmp", "orka-guardd-status-"+token)
	defer os.Remove(deny)
	defer os.Remove(allow)
	defer os.Remove(status)
	policy := renderKMXActivation(t, kmxBinary, temp, deny)
	metadata := v2.MutationMetadata{TaskUID: v2.TaskUID("task-live"), TaskAttempt: 1}
	guarddCfg := guarddRuntimeConfig{SocketPath: socket, AuthorizationIssuerID: "orka-production", AuthorizationPrivateKeyFile: authPrivate, ReceiptPublicKeyFile: public, ReceiptDirectory: receipts, GadgetDigest: gadgetDigest, NodeID: "node-orka-live", CgroupRoot: cgroupRoot}
	script := fmt.Sprintf("printf denied > %q; d=$?; printf allowed > %q; a=$?; printf '%%s %%s' \"$d\" \"$a\" > %q; sleep 300", deny, allow, status)
	var activationReceipt *v2.AgentPolicyReceipt
	process, err := acp.StartProcess(acp.ProcessConfig{Command: "/bin/sh", Args: []string{"-c", script}, Environment: []string{"PATH=/usr/bin:/bin"}, Paths: acp.SessionPaths{Workspace: "/tmp"}, UID: 65534, GID: 65534, ExecHelperCommand: helper, ActivatePolicy: func(pid int) (io.Closer, error) {
		stateBytes, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if readErr != nil {
			return nil, readErr
		}
		if !strings.Contains(string(stateBytes), "State:\tT") && !strings.Contains(string(stateBytes), "State:\tt") {
			return nil, fmt.Errorf("exec helper is not held: %s", stateBytes)
		}
		lifetime, receipt, activateErr := activateAgentPolicy(context.Background(), guarddCfg, policy, metadata, "session-live-"+token, pid)
		activationReceipt = receipt
		return lifetime, activateErr
	}})
	if err != nil {
		logBytes, _ := os.ReadFile(filepath.Join(temp, "guardd.log"))
		t.Fatalf("held-start activation: %v\nguardd log:\n%s", err, logBytes)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = process.Stop(ctx, time.Second)
	}()
	waitForPath(t, status, 15*time.Second)
	result, err := os.ReadFile(status)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(result))
	if len(fields) != 2 || fields[0] == "0" || fields[1] != "0" {
		t.Fatalf("deny/allow exits=%q", result)
	}
	denied, err := os.ReadFile(deny)
	if err != nil || len(denied) != 0 {
		t.Fatalf("denied write bytes=%q err=%v", denied, err)
	}
	allowed, err := os.ReadFile(allow)
	if err != nil || string(allowed) != "allowed" {
		t.Fatalf("allowed write=%q err=%v", allowed, err)
	}
	if activationReceipt == nil || len(activationReceipt.GuarddReceipt) == 0 {
		t.Fatal("verified guardd receipt missing")
	}
	var signedReceipt string
	if err := json.Unmarshal(activationReceipt.GuarddReceipt, &signedReceipt); err != nil {
		t.Fatalf("decode compatibility receipt: %v", err)
	}
	expectedReceipt, err := base64.StdEncoding.DecodeString(signedReceipt)
	if err != nil {
		t.Fatalf("decode signed receipt: %v", err)
	}
	persisted, err := os.ReadDir(receipts)
	if err != nil {
		t.Fatalf("read persisted receipts: %v", err)
	}
	if len(persisted) != 1 || persisted[0].IsDir() {
		t.Fatalf("persisted receipt entries = %#v", persisted)
	}
	persistedReceipt, err := os.ReadFile(filepath.Join(receipts, persisted[0].Name()))
	if err != nil {
		t.Fatalf("read persisted receipt: %v", err)
	}
	if !bytes.Equal(persistedReceipt, expectedReceipt) {
		t.Fatal("persisted receipt does not match the verified activation receipt")
	}
	t.Logf(
		"held_start=true deny_exit=%s allow_exit=%s receipt_sha256=%x receipt_file=%s",
		fields[0], fields[1], sha256.Sum256(persistedReceipt), persisted[0].Name(),
	)
}

func renderKMXActivation(t *testing.T, kmxBinary, temp, deny string) v2.AgentPolicyActivation {
	t.Helper()
	const namespace = "orka-live"
	policySpec := core.AgentPolicySpec{
		UID:                  "policy-live-uid",
		DenyWriteObjects:     []core.PolicyWriteObject{{Path: deny}},
		ViolationResponse:    core.PolicyViolationResponse{Action: core.PolicyViolationDeny, Threshold: 1},
		RequiredCapabilities: []string{"ig.agent-policy/file-permission/v1"},
	}
	policyDigest, err := policyresolver.PolicyDigest(policySpec)
	if err != nil {
		t.Fatal(err)
	}
	portablePolicy := map[string]any{
		"apiVersion": "agentsuite.dev/v1alpha1", "kind": "AgentPolicy",
		"metadata": map[string]any{"name": "policy-live", "uid": policySpec.UID},
		"spec": map[string]any{
			"denyWriteObjects":     policySpec.DenyWriteObjects,
			"violationResponse":    policySpec.ViolationResponse,
			"requiredCapabilities": policySpec.RequiredCapabilities,
		},
	}
	portableBinding := map[string]any{
		"apiVersion": "agentsuite.dev/v1alpha1", "kind": "AgentPolicyBinding",
		"metadata": map[string]any{"name": "binding-live", "uid": "binding-live-uid"},
		"spec": map[string]any{
			"subject": map[string]any{
				"suiteDigest": "sha256:" + strings.Repeat("1", 64), "agentID": "agent-live",
				"compositionDigest":    "sha256:" + strings.Repeat("2", 64),
				"sandboxBindingDigest": "sha256:" + strings.Repeat("3", 64),
			},
			"sources": []map[string]any{{"name": "policy-live", "uid": policySpec.UID, "digest": policyDigest}},
		},
	}
	writeJSON := func(name string, value any) string {
		path := filepath.Join(temp, name)
		data, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		return path
	}
	cmd := exec.Command(kmxBinary, "suite", "render-policy", writeJSON("policy.json", portablePolicy), writeJSON("binding.json", portableBinding), "--namespace", namespace)
	rendered, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("KMX AgentSuite policy render: %v: %s", err, rendered)
	}
	decoder := k8syaml.NewYAMLToJSONDecoder(bytes.NewReader(rendered))
	var policy core.AgentPolicy
	var binding core.AgentPolicyBinding
	for i := 0; i < 2; i++ {
		var raw map[string]any
		if err := decoder.Decode(&raw); err != nil {
			t.Fatalf("decode KMX resource %d: %v", i, err)
		}
		data, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		switch raw["kind"] {
		case "AgentPolicy":
			if err := json.Unmarshal(data, &policy); err != nil {
				t.Fatal(err)
			}
		case "AgentPolicyBinding":
			if err := json.Unmarshal(data, &binding); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unexpected KMX resource kind %q", raw["kind"])
		}
	}
	if policy.Namespace != namespace || binding.Namespace != namespace {
		t.Fatal("KMX namespace binding missing")
	}
	scheme := k8sruntime.NewScheme()
	if err := core.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&policy).Build()
	effective, err := (policyresolver.Resolver{Reader: reader, Now: time.Now}).Resolve(context.Background(), &binding)
	if err != nil {
		t.Fatalf("Orka resolution of KMX resources: %v", err)
	}
	if len(effective.DenyWriteObjects) != 1 || effective.DenyWriteObjects[0].Path != deny {
		t.Fatalf("KMX/Orka deny path drift: %+v", effective.DenyWriteObjects)
	}
	return v2.AgentPolicyActivation{
		Version: v2.AgentPolicyActivationVersion, Digest: effective.Digest,
		DenyFiles:            []v2.AgentPolicyFileRule{{Path: effective.DenyWriteObjects[0].Path}},
		ViolationResponse:    v2.AgentPolicyViolationResponse{Threshold: uint32(effective.ViolationResponse.Threshold)},
		RequiredCapabilities: append([]string(nil), effective.RequiredCapabilities...),
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if output, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", name, err, output)
	}
}
func fileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func waitForPath(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
func repoRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
}
