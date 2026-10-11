//go:build linux

package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	core "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/acp"
	"github.com/orka-agents/orka/internal/harness/v2"
	policyresolver "github.com/orka-agents/orka/internal/policy"
	"golang.org/x/sys/unix"
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
	fault := os.Getenv("ORKA_LIVE_GUARDD_FAULT")
	if fault != "" && fault != "worker" && fault != "event_consumer" &&
		fault != "guardd" && fault != "control" {
		t.Fatalf("unsupported ORKA_LIVE_GUARDD_FAULT %q", fault)
	}
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
	daemonArgs := []string{launcher, "--config", configPath}
	faultControl := filepath.Join(temp, "fault-control.sock")
	guarddDeathStatus := faultControl + ".guardian-status"
	defer os.Remove(guarddDeathStatus)
	if fault != "" {
		daemonArgs = []string{
			filepath.Join(repositoryRootForLiveTest(t), "workers", "acp", "supervisor", "testdata", "guardd_fault_launcher.py"),
			"--config", configPath, "--control", faultControl,
		}
	}
	daemon := exec.Command("python3", daemonArgs...)
	daemon.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(guarddSource, "src"))
	daemon.Stdout = logFile
	daemon.Stderr = logFile
	daemon.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if daemon.Process != nil {
			_ = syscall.Kill(-daemon.Process.Pid, syscall.SIGKILL)
			_ = daemon.Wait()
		}
	}()
	waitForPath(t, socket, 10*time.Second)
	if fault != "" {
		waitForPath(t, faultControl, 10*time.Second)
	}
	if err := os.Mkdir(cgroupRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(cgroupRoot); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove live-test cgroup root: %v", err)
		}
	}()

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
	heartbeat := filepath.Join("/tmp", "orka-guardd-heartbeat-"+token)
	heartbeatTemp := heartbeat + ".tmp"
	defer os.Remove(heartbeat)
	defer os.Remove(heartbeatTemp)
	script := fmt.Sprintf("printf denied > %q; d=$?; printf allowed > %q; a=$?; printf '%%s %%s' \"$d\" \"$a\" > %q; sleep 300", deny, allow, status)
	if fault != "" {
		script = fmt.Sprintf(
			"printf denied > %s; d=$?; printf allowed > %s; a=$?; printf '%%s %%s' \"$d\" \"$a\" > %s; exec python3 -c %s",
			liveTestShellQuote(deny), liveTestShellQuote(allow), liveTestShellQuote(status),
			liveTestShellQuote(fmt.Sprintf("import pathlib,time\np=pathlib.Path(%q)\nt=pathlib.Path(%q)\ni=0\nwhile True:\n i+=1\n t.write_text(str(i))\n t.replace(p)\n time.sleep(0.01)", heartbeat, heartbeatTemp)),
		)
	}
	var activationReceipt *v2.AgentPolicyReceipt
	var heldPID int
	liveUID := unusedLiveTestIdentity(t)
	process, err := acp.StartProcess(acp.ProcessConfig{Command: "/bin/sh", Args: []string{"-c", script}, Environment: []string{"PATH=/usr/bin:/bin"}, Paths: acp.SessionPaths{Workspace: "/tmp"}, UID: liveUID, GID: liveUID, ExecHelperCommand: helper, ActivatePolicy: func(pid int) (io.Closer, error) {
		heldPID = pid
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
	if len(activationReceipt.Attachments) != 2 ||
		activationReceipt.Attachments[0].ProgramName != "agentpolicy_open" ||
		activationReceipt.Attachments[0].AttachType != "lsm/file_open" ||
		activationReceipt.Attachments[1].ProgramName != "agentpolicy_permission" ||
		activationReceipt.Attachments[1].AttachType != "lsm/file_permission" {
		t.Fatalf("verified guardd attachments = %#v", activationReceipt.Attachments)
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
	if fault != "" {
		cgroupPath := filepath.Join(cgroupRoot, "session-live-"+token)
		waitForPath(t, heartbeat, 5*time.Second)
		beforeStart, beforeEnd := requireHeartbeatProgress(t, heartbeat, 2*time.Second)
		evidence := prepareGuarddFault(t, faultControl, fault)
		if evidence.Fault != fault || evidence.GuarddPID != daemon.Process.Pid ||
			evidence.WorkerPID <= 1 || evidence.GuardianPID <= 1 ||
			evidence.WorkerPID == evidence.GuardianPID ||
			evidence.WorkerPID == evidence.GuarddPID || evidence.GuardianPID == evidence.GuarddPID {
			t.Fatalf("invalid fault evidence: %#v", evidence)
		}
		pidfds := make([]int, 0, 4)
		defer func() {
			for _, fd := range pidfds {
				_ = unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0)
			}
			if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.freeze"), []byte("0"), 0o600); err != nil && !os.IsNotExist(err) {
				t.Errorf("thaw test cgroup for cleanup: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, stopErr := process.Stop(ctx, time.Second); stopErr != nil {
				t.Errorf("stop fault-test process: %v", stopErr)
			}
			if daemon.Process != nil {
				_ = daemon.Process.Kill()
				_ = daemon.Wait()
			}
			for _, fd := range pidfds {
				_ = unix.Close(fd)
			}
			if removeErr := os.Remove(cgroupPath); removeErr != nil && !os.IsNotExist(removeErr) {
				t.Errorf("remove fault-test task cgroup: %v", removeErr)
			}
		}()
		for _, pid := range []int{heldPID, evidence.GuarddPID, evidence.WorkerPID, evidence.GuardianPID} {
			fd, openErr := unix.PidfdOpen(pid, 0)
			if openErr != nil {
				t.Fatalf("open pidfd for %d: %v", pid, openErr)
			}
			pidfds = append(pidfds, fd)
		}
		for index, name := range []string{"held workload", "guardd", "IG worker", "guardian"} {
			requirePidfdAlive(t, pidfds[index], name)
		}
		requireCgroupUnfrozen(t, cgroupPath)
		started := time.Now()
		deadline := started.Add(6 * time.Second)
		fired := fireGuarddFault(t, faultControl, fault, time.Until(deadline))
		if fired != evidence {
			t.Fatalf("fault identities changed between prepare and fire: prepare=%#v fire=%#v", evidence, fired)
		}
		if fault == "event_consumer" {
			waitForCgroupFrozenBeforePidExit(t, cgroupPath, pidfds[2], deadline)
		} else {
			waitForCgroupFrozen(t, cgroupPath, deadline)
		}
		elapsed := time.Since(started)
		frozenHeartbeat := requireHeartbeatStable(t, heartbeat, 500*time.Millisecond)
		guardianStatus := guarddGuardianStatus{}
		if fault != "guardd" && fault != "control" {
			guardianStatus = readFaultStatus(t, faultControl)
			expectedCause := "ig_worker_died"
			if fault == "event_consumer" {
				expectedCause = "event_consumer_died"
			}
			if guardianStatus.Cause != expectedCause || !guardianStatus.Frozen ||
				guardianStatus.Error != nil || (fault == "worker" && !guardianStatus.Alive) {
				t.Fatalf("unexpected guardian status for %s: %#v", fault, guardianStatus)
			}
		} else if fault == "guardd" {
			waitForPidfdExit(t, pidfds[1], "guardd", time.Now().Add(2*time.Second))
			waitForPidfdExit(t, pidfds[2], "IG worker", time.Now().Add(2*time.Second))
			waitForPath(t, guarddDeathStatus, 2*time.Second)
			rawStatus, readErr := os.ReadFile(guarddDeathStatus)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if err := json.Unmarshal(rawStatus, &guardianStatus); err != nil {
				t.Fatalf("decode terminal guardian status: %v", err)
			}
			if guardianStatus.Cause != "guardd_died" || !guardianStatus.Frozen ||
				guardianStatus.Error != nil {
				t.Fatalf("unexpected guardian status for guardd death: %#v", guardianStatus)
			}
			waitForPidfdExit(t, pidfds[3], "guardian", time.Now().Add(2*time.Second))
		} else {
			requirePidfdAlive(t, pidfds[1], "guardd after control loss freeze")
			waitForPidfdExit(t, pidfds[2], "IG worker", time.Now().Add(2*time.Second))
			waitForPidfdExit(t, pidfds[3], "guardian", time.Now().Add(2*time.Second))
			terminal := readFaultTerminal(t, faultControl)
			if terminal.GuardianReturncode == nil || *terminal.GuardianReturncode != 0 ||
				terminal.WorkerReturncode == nil || *terminal.WorkerReturncode >= 0 {
				t.Fatalf("unexpected control-loss terminal state: %#v", terminal)
			}
			requirePidfdAlive(t, pidfds[1], "guardd after guardian retirement")
		}
		if fault == "event_consumer" {
			waitForPidfdExit(t, pidfds[2], "IG worker", time.Now().Add(2*time.Second))
		}
		t.Logf(
			"fault=%s freeze_elapsed_ms=%d guardd_pid=%d worker_pid=%d guardian_pid=%d heartbeat_before=%d heartbeat_last=%d heartbeat_frozen=%d guardian_status=%v",
			fault, elapsed.Milliseconds(), evidence.GuarddPID, evidence.WorkerPID,
			evidence.GuardianPID, beforeStart, beforeEnd, frozenHeartbeat, guardianStatus,
		)
	}
}

func liveTestShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func repositoryRootForLiveTest(t *testing.T) string {
	t.Helper()
	return repoRoot(t)
}

func unusedLiveTestIdentity(t *testing.T) int {
	t.Helper()
	used := map[int]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			t.Fatalf("read process status for UID isolation: %v", err)
		}
		foundUID := false
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				t.Fatalf("malformed Uid line for process %s: %q", entry.Name(), line)
			}
			uid, parseErr := strconv.Atoi(fields[1])
			if parseErr != nil {
				t.Fatalf("parse Uid for process %s: %v", entry.Name(), parseErr)
			}
			used[uid] = true
			foundUID = true
			break
		}
		if !foundUID {
			t.Fatalf("process %s status has no Uid field", entry.Name())
		}
	}
	for uid := 61000; uid < 62000; uid++ {
		if !used[uid] {
			return uid
		}
	}
	t.Fatal("no unused live-test UID in [61000,62000)")
	return 0
}

type guarddFaultEvidence struct {
	Fault       string `json:"fault"`
	GuarddPID   int    `json:"guardd_pid"`
	WorkerPID   int    `json:"worker_pid"`
	GuardianPID int    `json:"guardian_pid"`
}

type guarddGuardianStatus struct {
	Alive  bool    `json:"alive"`
	Cause  string  `json:"cause"`
	Frozen bool    `json:"frozen"`
	Error  *string `json:"error"`
}

type guarddFaultTerminal struct {
	GuardianReturncode *int `json:"guardian_returncode"`
	WorkerReturncode   *int `json:"worker_returncode"`
}

func faultControlRequest(t *testing.T, socketPath, command string, timeout time.Duration, output any) {
	t.Helper()
	connection, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if timeout <= 0 {
		t.Fatal("fault-control deadline elapsed")
	}
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, command+"\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(line, output); err != nil {
		t.Fatal(err)
	}
}

func prepareGuarddFault(t *testing.T, socketPath, fault string) guarddFaultEvidence {
	t.Helper()
	var evidence guarddFaultEvidence
	faultControlRequest(t, socketPath, "prepare:"+fault, 2*time.Second, &evidence)
	return evidence
}

func fireGuarddFault(t *testing.T, socketPath, fault string, timeout time.Duration) guarddFaultEvidence {
	t.Helper()
	var evidence guarddFaultEvidence
	faultControlRequest(t, socketPath, "fire:"+fault, timeout, &evidence)
	if evidence.Fault != fault {
		t.Fatalf("fault fire mismatch: %#v", evidence)
	}
	return evidence
}

func readFaultStatus(t *testing.T, socketPath string) guarddGuardianStatus {
	t.Helper()
	status := guarddGuardianStatus{}
	faultControlRequest(t, socketPath, "status", 2*time.Second, &status)
	return status
}

func readFaultTerminal(t *testing.T, socketPath string) guarddFaultTerminal {
	t.Helper()
	terminal := guarddFaultTerminal{}
	faultControlRequest(t, socketPath, "terminal", 2*time.Second, &terminal)
	return terminal
}

func readHeartbeat(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || value <= 0 {
		t.Fatalf("invalid heartbeat %q: %v", raw, err)
	}
	return value
}

func requireHeartbeatProgress(t *testing.T, path string, maximum time.Duration) (int, int) {
	t.Helper()
	start := readHeartbeat(t, path)
	deadline := time.Now().Add(maximum)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		current := readHeartbeat(t, path)
		if current > start {
			return start, current
		}
		<-ticker.C
	}
	t.Fatalf("heartbeat did not advance from %d within %s", start, maximum)
	return 0, 0
}

func requireHeartbeatStable(t *testing.T, path string, duration time.Duration) int {
	t.Helper()
	expected := readHeartbeat(t, path)
	deadline := time.Now().Add(duration)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		<-ticker.C
		if current := readHeartbeat(t, path); current != expected {
			t.Fatalf("heartbeat advanced after confirmed freeze: before=%d after=%d", expected, current)
		}
	}
	return expected
}

func requirePidfdAlive(t *testing.T, pidfd int, name string) {
	t.Helper()
	pollfds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	if _, err := unix.Poll(pollfds, 0); err != nil {
		t.Fatalf("poll %s pidfd: %v", name, err)
	}
	if pollfds[0].Revents != 0 {
		t.Fatalf("%s exited before fault injection: pidfd events=%#x", name, pollfds[0].Revents)
	}
}

func waitForPidfdExit(t *testing.T, pidfd int, name string, deadline time.Time) {
	t.Helper()
	pollfds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	for time.Now().Before(deadline) {
		if _, err := unix.Poll(pollfds, 10); err != nil {
			t.Fatalf("poll %s pidfd: %v", name, err)
		}
		if pollfds[0].Revents != 0 {
			return
		}
	}
	t.Fatalf("%s did not exit before deadline", name)
}

func requireCgroupUnfrozen(t *testing.T, cgroupPath string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.events"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(raw))
	for index := 0; index+1 < len(fields); index += 2 {
		if fields[index] == "frozen" {
			if fields[index+1] != "0" {
				t.Fatalf("cgroup froze before fault injection: %q", raw)
			}
			return
		}
	}
	t.Fatalf("cgroup.events has no frozen field: %q", raw)
}

func waitForCgroupFrozenBeforePidExit(t *testing.T, cgroupPath string, pidfd int, deadline time.Time) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.events"))
		if err != nil {
			lastErr = err
		} else {
			fields := strings.Fields(string(raw))
			for index := 0; index+1 < len(fields); index += 2 {
				if fields[index] == "frozen" && fields[index+1] == "1" {
					return
				}
			}
			lastErr = fmt.Errorf("frozen field is not 1: %q", raw)
		}
		requirePidfdAlive(t, pidfd, "IG worker before confirmed freeze")
		<-ticker.C
	}
	t.Fatalf("cgroup did not freeze before deadline: %v", lastErr)
}

func waitForCgroupFrozen(t *testing.T, cgroupPath string, deadline time.Time) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.events"))
		if err != nil {
			lastErr = err
		} else {
			fields := strings.Fields(string(raw))
			for index := 0; index+1 < len(fields); index += 2 {
				if fields[index] == "frozen" && fields[index+1] == "1" {
					return
				}
			}
			lastErr = fmt.Errorf("frozen field is not 1: %q", raw)
		}
		<-ticker.C
	}
	t.Fatalf("cgroup did not freeze before deadline: %v", lastErr)
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
