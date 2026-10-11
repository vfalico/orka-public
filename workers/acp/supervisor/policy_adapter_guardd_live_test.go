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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	core "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/acp"
	"github.com/orka-agents/orka/internal/guarddclient"
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
	executableHeadline := os.Getenv("ORKA_LIVE_GUARDD_EXEC_HEADLINE") == "1"
	if fault != "" && fault != "worker" && fault != "event_consumer" &&
		fault != "guardd" && fault != "control" {
		t.Fatalf("unsupported ORKA_LIVE_GUARDD_FAULT %q", fault)
	}
	if executableHeadline && fault != "" {
		t.Fatal("executable headline and fault injection are separate live tests")
	}
	if guarddSource == "" || oci == "" || kmxBinary == "" || igBinary == "" || gadgetDigest == "" {
		t.Fatal("ORKA_LIVE_GUARDD_SOURCE, ORKA_LIVE_GUARDD_OCI, ORKA_LIVE_KMX_BIN, ORKA_LIVE_IG_BIN, and ORKA_LIVE_GADGET_DIGEST are required")
	}
	temp := t.TempDir()
	identities := unusedLiveTestIdentities(t, 3)
	liveUID := identities[0]
	coordinatorUID := identities[1]
	controlUID := identities[2]
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
	faultCoordinator := ""
	defer os.Remove(guarddDeathStatus)
	if fault != "" {
		faultAccessDir := filepath.Join("/tmp", "orka-guardd-fault-"+strconv.Itoa(os.Getpid()))
		if err := os.Mkdir(faultAccessDir, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(faultAccessDir)
		faultControl = filepath.Join(faultAccessDir, "fault-control.sock")
		guarddDeathStatus = faultControl + ".guardian-status"
		coordinatorSource := filepath.Join(
			repositoryRootForLiveTest(t),
			"workers", "acp", "supervisor", "testdata", "guardd_fault_coordinator.py",
		)
		coordinatorBytes, err := os.ReadFile(coordinatorSource)
		if err != nil {
			t.Fatal(err)
		}
		faultCoordinator = filepath.Join(faultAccessDir, "guardd_fault_coordinator.py")
		if err := os.WriteFile(faultCoordinator, coordinatorBytes, 0o555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(faultCoordinator, 0o555); err != nil {
			t.Fatal(err)
		}
		daemonArgs = []string{
			filepath.Join(repositoryRootForLiveTest(t), "workers", "acp", "supervisor", "testdata", "guardd_fault_launcher.py"),
			"--config", configPath, "--control", faultControl,
			"--coordinator-uid", strconv.Itoa(coordinatorUID),
			"--coordinator-gid", strconv.Itoa(coordinatorUID),
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
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- daemon.Wait() }()
	daemonReaped := false
	stopDaemon := func(processGroup bool) {
		if daemonReaped {
			return
		}
		if processGroup {
			_ = syscall.Kill(-daemon.Process.Pid, syscall.SIGKILL)
		} else {
			_ = daemon.Process.Kill()
		}
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-daemonDone:
			daemonReaped = true
		case <-timer.C:
			t.Errorf("guardd fixture process %d did not exit after SIGKILL", daemon.Process.Pid)
		}
	}
	defer func() { stopDaemon(true) }()
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
	headlineMarker := filepath.Join("/tmp", "orka-guardd-exec-marker-"+token)
	defer os.Remove(deny)
	defer os.Remove(allow)
	defer os.Remove(status)
	defer os.Remove(headlineMarker)
	policy := v2.AgentPolicyActivation{}
	if executableHeadline {
		source := filepath.Join(temp, "headline-helper.go")
		if err := os.WriteFile(source, []byte(`package main

import (
	"os"
	"path/filepath"
)

func main() {
	if err := os.WriteFile(os.Getenv("HEADLINE_MARKER"), []byte(filepath.Base(os.Args[0])+"\n"), 0o600); err != nil {
		panic(err)
	}
}
`), 0o600); err != nil {
			t.Fatal(err)
		}
		buildHeadline := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-o", deny, source)
		buildHeadline.Env = append(os.Environ(), "CGO_ENABLED=0")
		if output, err := buildHeadline.CombinedOutput(); err != nil {
			t.Fatalf("build executable headline helper: %v: %s", err, output)
		}
		helperBytes, err := os.ReadFile(deny)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(allow, helperBytes, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(deny, 0o755); err != nil {
			t.Fatal(err)
		}
	} else {
		policy = renderKMXActivation(t, kmxBinary, temp, deny)
	}
	metadata := v2.MutationMetadata{TaskUID: v2.TaskUID("task-live"), TaskAttempt: 1}
	guarddCfg := guarddRuntimeConfig{SocketPath: socket, AuthorizationIssuerID: "orka-production", AuthorizationPrivateKeyFile: authPrivate, ReceiptPublicKeyFile: public, ReceiptDirectory: receipts, GadgetDigest: gadgetDigest, NodeID: "node-orka-live", CgroupRoot: cgroupRoot}
	heartbeat := filepath.Join("/tmp", "orka-guardd-heartbeat-"+token)
	heartbeatTemp := heartbeat + ".tmp"
	defer os.Remove(heartbeat)
	defer os.Remove(heartbeatTemp)
	script := fmt.Sprintf("printf denied > %q; d=$?; printf allowed > %q; a=$?; printf '%%s %%s' \"$d\" \"$a\" > %q; sleep 300", deny, allow, status)
	if executableHeadline {
		script = fmt.Sprintf(
			"HEADLINE_MARKER=%s %s; d=$?; HEADLINE_MARKER=%s %s; a=$?; printf '%%s %%s' \"$d\" \"$a\" > %s; sleep 300",
			liveTestShellQuote(headlineMarker), liveTestShellQuote(deny),
			liveTestShellQuote(headlineMarker), liveTestShellQuote(allow),
			liveTestShellQuote(status),
		)
	}
	if fault != "" {
		script = fmt.Sprintf(
			"printf denied > %s; d=$?; printf allowed > %s; a=$?; printf '%%s %%s' \"$d\" \"$a\" > %s; exec python3 -c %s",
			liveTestShellQuote(deny), liveTestShellQuote(allow), liveTestShellQuote(status),
			liveTestShellQuote(fmt.Sprintf("import pathlib,time\np=pathlib.Path(%q)\nt=pathlib.Path(%q)\ni=0\nwhile True:\n i+=1\n t.write_text(str(i))\n t.replace(p)\n time.sleep(0.01)", heartbeat, heartbeatTemp)),
		)
	}
	var activationReceipt *v2.AgentPolicyReceipt
	var rawGuarddReceipt *guarddclient.Receipt
	var heldPID int
	var heldStartTicks uint64
	process, err := acp.StartProcess(acp.ProcessConfig{Command: "/bin/sh", Args: []string{"-c", script}, Environment: []string{"PATH=/usr/bin:/bin"}, Paths: acp.SessionPaths{Workspace: "/tmp"}, UID: liveUID, GID: liveUID, ExecHelperCommand: helper, ActivatePolicy: func(pid int) (io.Closer, error) {
		heldPID = pid
		heldStartTicks = processStartTicks(t, pid)
		stateBytes, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if readErr != nil {
			return nil, readErr
		}
		if !strings.Contains(string(stateBytes), "State:\tT") && !strings.Contains(string(stateBytes), "State:\tt") {
			return nil, fmt.Errorf("exec helper is not held: %s", stateBytes)
		}
		if _, statErr := os.Stat(status); !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("held workload produced status before release: %v", statErr)
		}
		if _, statErr := os.Stat(headlineMarker); !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("held workload produced side effect before release: %v", statErr)
		}
		if executableHeadline {
			lifetime, receipt, activateErr := activateExecutableHeadlinePolicy(
				context.Background(), guarddCfg, metadata, "session-live-"+token, pid, deny,
			)
			rawGuarddReceipt = receipt
			return lifetime, activateErr
		}
		lifetime, receipt, activateErr := activateAgentPolicy(
			context.Background(), guarddCfg, policy, metadata, "session-live-"+token, pid,
		)
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
	if len(fields) != 2 || fields[0] != "126" || fields[1] != "0" {
		logBytes, _ := os.ReadFile(filepath.Join(temp, "guardd.log"))
		t.Fatalf("deny/allow exits=%q\nverified receipt=%#v\nguardd log:\n%s", result, rawGuarddReceipt, logBytes)
	}
	if executableHeadline {
		marker, readErr := os.ReadFile(headlineMarker)
		if readErr != nil || string(marker) != filepath.Base(allow)+"\n" {
			t.Fatalf("executable headline marker=%q err=%v", marker, readErr)
		}
		if rawGuarddReceipt == nil || len(rawGuarddReceipt.Signed) == 0 ||
			len(rawGuarddReceipt.Attachments) != 1 ||
			rawGuarddReceipt.Attachments[0].ProgramName != "agentpolicy_exec" ||
			rawGuarddReceipt.Attachments[0].AttachType != "lsm/bprm_check_security" {
			t.Fatalf("verified executable guardd receipt = %#v", rawGuarddReceipt)
		}
		persisted, readDirErr := os.ReadDir(receipts)
		if readDirErr != nil {
			t.Fatal(readDirErr)
		}
		if len(persisted) != 1 || persisted[0].IsDir() {
			t.Fatalf("persisted executable receipt entries = %#v", persisted)
		}
		persistedReceipt, readErr := os.ReadFile(filepath.Join(receipts, persisted[0].Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(persistedReceipt, rawGuarddReceipt.Signed) {
			t.Fatal("persisted executable receipt does not match verified receipt")
		}
		exportExecutableHeadlineEvidence(
			t, os.Getenv("ORKA_LIVE_GUARDD_EVIDENCE_DIR"), persisted[0].Name(),
			persistedReceipt, map[string]any{
				"headline":       "held-executable",
				"held_start":     true,
				"denied_path":    deny,
				"allowed_path":   allow,
				"deny_exit":      fields[0],
				"allow_exit":     fields[1],
				"marker":         strings.TrimSpace(string(marker)),
				"program_name":   rawGuarddReceipt.Attachments[0].ProgramName,
				"attach_type":    rawGuarddReceipt.Attachments[0].AttachType,
				"program_id":     rawGuarddReceipt.Attachments[0].ProgramID,
				"link_id":        rawGuarddReceipt.Attachments[0].LinkID,
				"target":         rawGuarddReceipt.Attachments[0].Target,
				"receipt_sha256": fmt.Sprintf("%x", sha256.Sum256(persistedReceipt)),
				"receipt_file":   persisted[0].Name(),
			},
		)
		t.Logf(
			"headline=held-executable held_start=true deny_exit=%s allow_exit=%s marker=%s attachment=%s/%s receipt_sha256=%x receipt_file=%s",
			fields[0], fields[1], strings.TrimSpace(string(marker)),
			rawGuarddReceipt.Attachments[0].ProgramName,
			rawGuarddReceipt.Attachments[0].AttachType,
			sha256.Sum256(persistedReceipt), persisted[0].Name(),
		)
		return
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
		freezerPath := filepath.Join(cgroupPath, "cgroup.freeze")
		controlHeartbeat := startLiveControlHeartbeat(t, cgroupRoot, token, controlUID)
		defer controlHeartbeat.close(t)
		if filepath.Dir(controlHeartbeat.cgroupPath) != filepath.Dir(cgroupPath) ||
			controlHeartbeat.cgroupPath == cgroupPath ||
			strings.HasPrefix(controlHeartbeat.cgroupPath+string(os.PathSeparator), cgroupPath+string(os.PathSeparator)) ||
			strings.HasPrefix(cgroupPath+string(os.PathSeparator), controlHeartbeat.cgroupPath+string(os.PathSeparator)) {
			t.Fatalf("control heartbeat cgroup is not a distinct sibling: control=%q guarded=%q", controlHeartbeat.cgroupPath, cgroupPath)
		}
		waitForPath(t, heartbeat, 5*time.Second)
		beforeStart, beforeEnd := requireHeartbeatProgress(t, heartbeat, 2*time.Second)
		controlBeforeStart, controlBeforeEnd := requireControlHeartbeatProgress(t, controlHeartbeat.path, 2*time.Second)
		evidence := prepareGuarddFault(t, faultControl, fault)
		if heldPID <= 1 || heldStartTicks == 0 ||
			evidence.Fault != fault || evidence.GuarddPID != daemon.Process.Pid ||
			evidence.WorkerPID <= 1 || evidence.GuardianPID <= 1 ||
			evidence.WorkerPID == evidence.GuardianPID ||
			evidence.WorkerPID == evidence.GuarddPID || evidence.GuardianPID == evidence.GuarddPID ||
			evidence.GuarddStartTicks == 0 || evidence.WorkerStartTicks == 0 || evidence.GuardianStartTicks == 0 ||
			evidence.CoordinatorPID != 0 || evidence.CoordinatorStartTicks != 0 ||
			evidence.CoordinatorUID != 0 || evidence.CoordinatorGID != 0 {
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
			stopDaemon(false)
			for index, fd := range pidfds {
				if !pidfdExited(fd, time.Now().Add(2*time.Second)) {
					t.Errorf("%s did not exit during fault-test cleanup", []string{"held workload", "guardd", "IG worker", "guardian"}[index])
				}
				_ = unix.Close(fd)
			}
			waitForCgroupEmptyCleanup(t, cgroupPath, 2*time.Second)
			if removeErr := os.Remove(cgroupPath); removeErr != nil && !os.IsNotExist(removeErr) {
				t.Errorf("remove fault-test task cgroup: %v", removeErr)
			}
			if _, statErr := os.Stat(cgroupPath); !os.IsNotExist(statErr) {
				t.Errorf("fault-test task cgroup still exists after cleanup: %v", statErr)
			}
		}()
		for _, identity := range []struct {
			pid        int
			startTicks uint64
			name       string
		}{
			{heldPID, heldStartTicks, "held workload"},
			{evidence.GuarddPID, evidence.GuarddStartTicks, "guardd"},
			{evidence.WorkerPID, evidence.WorkerStartTicks, "IG worker"},
			{evidence.GuardianPID, evidence.GuardianStartTicks, "guardian"},
		} {
			pidfds = append(pidfds, openPidfdForIdentity(t, identity.pid, identity.startTicks, identity.name))
		}
		for index, name := range []string{"held workload", "guardd", "IG worker", "guardian"} {
			requirePidfdAlive(t, pidfds[index], name)
		}
		requireCgroupUnfrozen(t, cgroupPath)
		trace := startGuardianFreezeTrace(t, temp, evidence.GuardianPID, evidence.GuardianStartTicks)
		traceStopped := false
		defer func() {
			if !traceStopped {
				trace.stop(t)
			}
		}()
		trace.requireAttached(t)
		started := time.Now()
		startedNS := monotonicNowNS(t)
		deadline := started.Add(6 * time.Second)
		coordinator := fireGuarddFaultAsCoordinator(
			t, faultCoordinator, faultControl, freezerPath, fault, coordinatorUID, time.Until(deadline),
		)
		fired := coordinator.FaultEvidence
		if fired.Fault != evidence.Fault ||
			fired.GuarddPID != evidence.GuarddPID ||
			fired.GuarddStartTicks != evidence.GuarddStartTicks ||
			fired.WorkerPID != evidence.WorkerPID ||
			fired.WorkerStartTicks != evidence.WorkerStartTicks ||
			fired.GuardianPID != evidence.GuardianPID ||
			fired.GuardianStartTicks != evidence.GuardianStartTicks {
			t.Fatalf("fault identities changed between prepare and fire: prepare=%#v fire=%#v", evidence, fired)
		}
		if fault == "event_consumer" {
			waitForCgroupFrozenBeforePidExit(t, cgroupPath, pidfds[2], deadline)
		} else {
			waitForCgroupFrozen(t, cgroupPath, deadline)
		}
		frozenNS := monotonicNowNS(t)
		elapsed := time.Since(started)
		frozenHeartbeat := requireHeartbeatStable(t, heartbeat, 500*time.Millisecond)
		controlProof := requireControlHeartbeatContinuous(
			t, controlHeartbeat.path, startedNS, frozenNS, 250*time.Millisecond,
		)
		guardianStatus := guarddGuardianStatus{}
		terminal := guarddFaultTerminal{}
		guarddAliveAfterControl := false
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
			guarddAliveAfterControl = true
			waitForPidfdExit(t, pidfds[2], "IG worker", time.Now().Add(2*time.Second))
			waitForPidfdExit(t, pidfds[3], "guardian", time.Now().Add(2*time.Second))
			terminal = readFaultTerminal(t, faultControl)
			if terminal.GuardianReturncode == nil || *terminal.GuardianReturncode != 0 ||
				terminal.WorkerReturncode == nil || *terminal.WorkerReturncode >= 0 {
				t.Fatalf("unexpected control-loss terminal state: %#v", terminal)
			}
			requirePidfdAlive(t, pidfds[1], "guardd after guardian retirement")
		}
		if fault == "event_consumer" {
			waitForPidfdExit(t, pidfds[2], "IG worker", time.Now().Add(2*time.Second))
		}
		trace.stop(t)
		traceStopped = true
		writerTID, freezeWrite := trace.requireExactFreezeWrite(t, freezerPath)
		exportLiveFaultEvidence(t, os.Getenv("ORKA_LIVE_GUARDD_EVIDENCE_DIR"), liveFaultEvidenceExport{
			Fault:                   fault,
			FreezerPath:             freezerPath,
			FreezeElapsedMS:         elapsed.Milliseconds(),
			Prepared:                evidence,
			Coordinator:             coordinator,
			GuardianStatus:          guardianStatus,
			Terminal:                terminal,
			GuarddAliveAfterControl: guarddAliveAfterControl,
			FreezeWriterTID:         writerTID,
			FreezeWrite:             freezeWrite,
			GuardedHeartbeatBefore:  beforeStart,
			GuardedHeartbeatLast:    beforeEnd,
			GuardedHeartbeatFrozen:  frozenHeartbeat,
			ControlBefore:           controlBeforeStart,
			ControlLast:             controlBeforeEnd,
			ControlWindowFirst:      controlProof.first,
			ControlWindowLast:       controlProof.last,
			ControlMaxGapMS:         controlProof.maxGap.Milliseconds(),
		}, filepath.Join(temp, "guardd.log"), receipts, persisted[0].Name(),
			trace.prefix, heartbeat, controlHeartbeat.path)
		t.Logf(
			"fault=%s freeze_elapsed_ms=%d guardd_pid=%d guardd_start=%d worker_pid=%d worker_start=%d guardian_pid=%d guardian_start=%d coordinator_pid=%d coordinator_start=%d coordinator_uid=%d freezer_denial_stage=%s freezer_errno=%d freeze_writer_tid=%d heartbeat_before=%d heartbeat_last=%d heartbeat_frozen=%d control_before=%d control_last=%d control_window_first=%d control_window_last=%d control_max_gap_ms=%d guardian_status=%v freeze_write=%q",
			fault, elapsed.Milliseconds(), evidence.GuarddPID, evidence.GuarddStartTicks,
			evidence.WorkerPID, evidence.WorkerStartTicks, evidence.GuardianPID,
			evidence.GuardianStartTicks, coordinator.CoordinatorPID, coordinator.CoordinatorStartTicks,
			coordinator.UID, coordinator.FreezerDenialStage, coordinator.FreezerErrno,
			writerTID, beforeStart, beforeEnd, frozenHeartbeat,
			controlBeforeStart, controlBeforeEnd, controlProof.first, controlProof.last,
			controlProof.maxGap.Milliseconds(), guardianStatus, freezeWrite,
		)
	}
}

func activateExecutableHeadlinePolicy(ctx context.Context, cfg guarddRuntimeConfig, metadata v2.MutationMetadata, sessionID string, pid int, deniedExecutable string) (_ io.Closer, receipt *guarddclient.Receipt, retErr error) {
	if err := validateGuarddRuntimeConfig(cfg); err != nil {
		return nil, nil, err
	}
	component := safeCgroupComponent.ReplaceAllString(sessionID, "-")
	if err := os.MkdirAll(cfg.CgroupRoot, 0o755); err != nil {
		return nil, nil, err
	}
	cgroupPath := filepath.Join(cfg.CgroupRoot, component)
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		return nil, nil, err
	}
	lifetime := &policyActivationLifetime{cgroupPath: cgroupPath}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, lifetime.closeLocal())
		}
	}()
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return nil, nil, err
	}
	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return nil, nil, err
	}
	defer cgroup.Close()
	policySum := sha256.Sum256([]byte("exec-headline\x00" + deniedExecutable))
	document := guarddPolicyDocument{
		APIVersion: "agentpolicy.gadget/v1alpha1",
		Kind:       "AgentPolicy",
		Metadata: guarddPolicyMetadata{
			Name:   policyName(component),
			Digest: "sha256:" + hex.EncodeToString(policySum[:]),
		},
		Spec: guarddPolicySpec{
			Subject:         guarddPolicySubject{TaskUID: string(metadata.TaskUID), SessionID: sessionID},
			FailureMode:     "closed",
			DenyExecutables: []guarddPolicyRule{{ID: 1, Path: deniedExecutable}},
		},
	}
	policyTree := guarddPolicyMap(document)
	policyDigest, err := guarddclient.DigestCanonicalJSON(policyTree)
	if err != nil {
		return nil, nil, err
	}
	authorizationKey, err := guarddclient.LoadPrivateKey(cfg.AuthorizationPrivateKeyFile)
	if err != nil {
		return nil, nil, err
	}
	receiptKey, err := guarddclient.LoadPublicKey(cfg.ReceiptPublicKeyFile)
	if err != nil {
		return nil, nil, err
	}
	client, err := guarddclient.New(guarddclient.Config{
		SocketPath: cfg.SocketPath, AuthorizationPrivateKey: authorizationKey,
		AuthorizationIssuerID: cfg.AuthorizationIssuerID, BootID: kernelBootID(),
		ReceiptPublicKey: receiptKey, ReceiptDirectory: cfg.ReceiptDirectory,
		Timeout: 15 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	binding := guarddclient.Binding{
		SessionID: sessionID, Attempt: strconv.FormatUint(uint64(metadata.TaskAttempt), 10),
		Generation: 1, PolicyDigest: policyDigest, GadgetDigest: cfg.GadgetDigest, NodeID: cfg.NodeID,
	}
	receipt, err = client.Activate(ctx, binding, policyTree, cgroup)
	if err != nil {
		return nil, nil, err
	}
	lifetime.client = client
	lifetime.binding = binding
	return lifetime, receipt, nil
}

func exportExecutableHeadlineEvidence(t *testing.T, directory, receiptName string, receipt []byte, summary map[string]any) {
	t.Helper()
	if directory == "" {
		return
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatalf("ORKA_LIVE_GUARDD_EVIDENCE_DIR must be clean and absolute")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create executable headline evidence directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, receiptName), receipt, 0o600); err != nil {
		t.Fatalf("write executable headline receipt: %v", err)
	}
	summaryBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("encode executable headline summary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "summary.json"), append(summaryBytes, '\n'), 0o600); err != nil {
		t.Fatalf("write executable headline summary: %v", err)
	}
}

type liveFaultEvidenceExport struct {
	Fault                   string                       `json:"fault"`
	FreezerPath             string                       `json:"freezer_path"`
	FreezeElapsedMS         int64                        `json:"freeze_elapsed_ms"`
	Prepared                guarddFaultEvidence          `json:"prepared"`
	Coordinator             guarddFaultCoordinatorResult `json:"coordinator"`
	GuardianStatus          guarddGuardianStatus         `json:"guardian_status"`
	Terminal                guarddFaultTerminal          `json:"terminal"`
	GuarddAliveAfterControl bool                         `json:"guardd_alive_after_control"`
	FreezeWriterTID         int                          `json:"freeze_writer_tid"`
	FreezeWrite             string                       `json:"freeze_write"`
	GuardedHeartbeatBefore  int                          `json:"guarded_heartbeat_before"`
	GuardedHeartbeatLast    int                          `json:"guarded_heartbeat_last"`
	GuardedHeartbeatFrozen  int                          `json:"guarded_heartbeat_frozen"`
	ControlBefore           int64                        `json:"control_before"`
	ControlLast             int64                        `json:"control_last"`
	ControlWindowFirst      int64                        `json:"control_window_first"`
	ControlWindowLast       int64                        `json:"control_window_last"`
	ControlMaxGapMS         int64                        `json:"control_max_gap_ms"`
}

func exportLiveFaultEvidence(t *testing.T, directory string, summary liveFaultEvidenceExport, guarddLog, receipts, receiptName, tracePrefix, guardedHeartbeat, controlHeartbeat string) {
	t.Helper()
	if directory == "" {
		return
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatalf("ORKA_LIVE_GUARDD_EVIDENCE_DIR must be clean and absolute")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create live fault evidence directory: %v", err)
	}
	copyFile := func(source, name string) {
		t.Helper()
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read live fault evidence %s: %v", source, err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatalf("write live fault evidence %s: %v", name, err)
		}
	}
	copyFile(guarddLog, "guardd.log")
	copyFile(filepath.Join(receipts, receiptName), receiptName)
	copyFile(guardedHeartbeat, "guarded-heartbeat")
	copyFile(controlHeartbeat, "control-heartbeat")
	traceFiles, err := filepath.Glob(tracePrefix + ".*")
	if err != nil || len(traceFiles) == 0 {
		t.Fatalf("enumerate guardian trace files: files=%v err=%v", traceFiles, err)
	}
	sort.Strings(traceFiles)
	for _, traceFile := range traceFiles {
		copyFile(traceFile, filepath.Base(traceFile))
	}
	summaryBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("encode live fault evidence summary: %v", err)
	}
	summaryBytes = append(summaryBytes, '\n')
	if err := os.WriteFile(filepath.Join(directory, "summary.json"), summaryBytes, 0o600); err != nil {
		t.Fatalf("write live fault evidence summary: %v", err)
	}
}

func liveTestShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func repositoryRootForLiveTest(t *testing.T) string {
	t.Helper()
	return repoRoot(t)
}

func unusedLiveTestIdentities(t *testing.T, count int) []int {
	t.Helper()
	if count <= 0 {
		t.Fatal("positive unused identity count is required")
	}
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
	identities := make([]int, 0, count)
	for uid := 61000; uid < 62000 && len(identities) < count; uid++ {
		if !used[uid] {
			identities = append(identities, uid)
		}
	}
	if len(identities) != count {
		t.Fatalf("found %d unused live-test UIDs in [61000,62000), want %d", len(identities), count)
	}
	return identities
}

type guarddFaultEvidence struct {
	Fault                 string `json:"fault"`
	GuarddPID             int    `json:"guardd_pid"`
	GuarddStartTicks      uint64 `json:"guardd_start_ticks"`
	WorkerPID             int    `json:"worker_pid"`
	WorkerStartTicks      uint64 `json:"worker_start_ticks"`
	GuardianPID           int    `json:"guardian_pid"`
	GuardianStartTicks    uint64 `json:"guardian_start_ticks"`
	CoordinatorPID        int    `json:"coordinator_pid"`
	CoordinatorStartTicks uint64 `json:"coordinator_start_ticks"`
	CoordinatorUID        int    `json:"coordinator_uid"`
	CoordinatorGID        int    `json:"coordinator_gid"`
}

type guarddFaultCoordinatorResult struct {
	CoordinatorPID        int                 `json:"coordinator_pid"`
	CoordinatorStartTicks uint64              `json:"coordinator_start_ticks"`
	UID                   int                 `json:"uid"`
	GID                   int                 `json:"gid"`
	Groups                []int               `json:"groups"`
	Capabilities          map[string]uint64   `json:"capabilities"`
	FreezerPath           string              `json:"freezer_path"`
	FreezerDenialStage    string              `json:"freezer_denial_stage"`
	FreezerErrno          int                 `json:"freezer_errno"`
	CgroupFDs             []map[string]any    `json:"cgroup_fds"`
	FaultEvidence         guarddFaultEvidence `json:"fault_evidence"`
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

func fireGuarddFaultAsCoordinator(t *testing.T, coordinator, socketPath, freezerPath, fault string, uid int, timeout time.Duration) guarddFaultCoordinatorResult {
	t.Helper()
	if timeout <= 0 {
		t.Fatal("fault-control deadline elapsed")
	}
	command := exec.Command(
		"python3", coordinator,
		"--control", socketPath,
		"--freezer", freezerPath,
		"--fault", fault,
	)
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(uid),
			Groups: []uint32{},
		},
	}
	type commandResult struct {
		output []byte
		err    error
	}
	done := make(chan commandResult, 1)
	go func() {
		output, err := command.CombinedOutput()
		done <- commandResult{output: output, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var result commandResult
	select {
	case result = <-done:
	case <-timer.C:
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		reapTimer := time.NewTimer(2 * time.Second)
		defer reapTimer.Stop()
		select {
		case result = <-done:
			t.Fatalf("unprivileged fault coordinator exceeded %s: %v: %s", timeout, result.err, result.output)
		case <-reapTimer.C:
			t.Fatalf("unprivileged fault coordinator exceeded %s and did not exit after SIGKILL", timeout)
		}
	}
	if result.err != nil {
		t.Fatalf("unprivileged fault coordinator: %v: %s", result.err, result.output)
	}
	var observed guarddFaultCoordinatorResult
	if err := json.Unmarshal(result.output, &observed); err != nil {
		t.Fatalf("decode unprivileged fault coordinator: %v: %s", err, result.output)
	}
	if observed.FaultEvidence.Fault != fault ||
		observed.CoordinatorPID <= 1 ||
		observed.CoordinatorStartTicks == 0 ||
		observed.FaultEvidence.CoordinatorPID != observed.CoordinatorPID ||
		observed.FaultEvidence.CoordinatorStartTicks != observed.CoordinatorStartTicks ||
		observed.UID != uid || observed.GID != uid ||
		observed.FaultEvidence.CoordinatorUID != uid ||
		observed.FaultEvidence.CoordinatorGID != uid ||
		len(observed.Groups) != 0 ||
		len(observed.Capabilities) != 4 ||
		observed.Capabilities["CapInh"] != 0 ||
		observed.Capabilities["CapPrm"] != 0 ||
		observed.Capabilities["CapEff"] != 0 ||
		observed.Capabilities["CapAmb"] != 0 ||
		observed.FreezerPath != freezerPath ||
		(observed.FreezerDenialStage != "open" && observed.FreezerDenialStage != "write") ||
		(observed.FreezerErrno != int(syscall.EACCES) && observed.FreezerErrno != int(syscall.EPERM)) ||
		len(observed.CgroupFDs) != 0 {
		t.Fatalf("invalid unprivileged fault evidence: %#v", observed)
	}
	return observed
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

type liveControlHeartbeat struct {
	command    *exec.Cmd
	done       chan error
	pidfd      int
	path       string
	cgroupPath string
}

func startLiveControlHeartbeat(t *testing.T, cgroupRoot, token string, uid int) *liveControlHeartbeat {
	t.Helper()
	path := filepath.Join("/tmp", "orka-guardd-control-heartbeat-"+token)
	cgroupPath := filepath.Join(cgroupRoot, "control-live-"+token)
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(
		"import os,signal,time\nos.kill(os.getpid(), signal.SIGSTOP)\nwith open(%q, 'a', buffering=1) as out:\n while True:\n  out.write(str(time.monotonic_ns())+'\\n')\n  out.flush()\n  time.sleep(0.01)",
		path,
	)
	command := exec.Command("python3", "-c", script)
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(uid),
			Groups: []uint32{},
		},
	}
	if err := command.Start(); err != nil {
		_ = os.Remove(cgroupPath)
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	pidfd := -1
	ready := false
	defer func() {
		if ready {
			return
		}
		_ = command.Process.Kill()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			t.Errorf("control heartbeat setup process did not exit")
		}
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		_ = os.Remove(path)
		waitForCgroupEmptyCleanup(t, cgroupPath, 2*time.Second)
		if err := os.Remove(cgroupPath); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove failed control heartbeat setup cgroup: %v", err)
		}
	}()
	waitForProcessStopped(t, command.Process.Pid, 2*time.Second)
	if err := os.WriteFile(
		filepath.Join(cgroupPath, "cgroup.procs"),
		[]byte(strconv.Itoa(command.Process.Pid)),
		0o600,
	); err != nil {
		t.Fatalf("move control heartbeat into sibling cgroup: %v", err)
	}
	requireProcessInCgroup(t, command.Process.Pid, cgroupPath)
	openedPidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		t.Fatalf("open control-heartbeat pidfd: %v", err)
	}
	pidfd = openedPidfd
	if err := unix.PidfdSendSignal(pidfd, syscall.SIGCONT, nil, 0); err != nil {
		t.Fatalf("release control heartbeat: %v", err)
	}
	waitForPath(t, path, 2*time.Second)
	heartbeat := &liveControlHeartbeat{
		command: command, done: done, pidfd: pidfd, path: path, cgroupPath: cgroupPath,
	}
	ready = true
	return heartbeat
}

func (heartbeat *liveControlHeartbeat) close(t *testing.T) {
	t.Helper()
	if heartbeat == nil {
		return
	}
	if heartbeat.pidfd >= 0 {
		_ = unix.PidfdSendSignal(heartbeat.pidfd, syscall.SIGKILL, nil, 0)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-heartbeat.done:
	case <-timer.C:
		t.Errorf("control heartbeat process did not exit")
	}
	if heartbeat.pidfd >= 0 {
		if !pidfdExited(heartbeat.pidfd, time.Now().Add(2*time.Second)) {
			t.Errorf("control heartbeat pidfd did not report exit")
		}
		_ = unix.Close(heartbeat.pidfd)
		heartbeat.pidfd = -1
	}
	_ = os.Remove(heartbeat.path)
	waitForCgroupEmptyCleanup(t, heartbeat.cgroupPath, 2*time.Second)
	if err := os.Remove(heartbeat.cgroupPath); err != nil && !os.IsNotExist(err) {
		t.Errorf("remove control heartbeat cgroup: %v", err)
	}
	if _, err := os.Stat(heartbeat.cgroupPath); !os.IsNotExist(err) {
		t.Errorf("control heartbeat cgroup still exists after cleanup: %v", err)
	}
}

func waitForProcessStopped(t *testing.T, pid int, maximum time.Duration) {
	t.Helper()
	deadline := time.Now().Add(maximum)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil && (bytes.Contains(raw, []byte("State:\tT")) || bytes.Contains(raw, []byte("State:\tt"))) {
			return
		}
		<-ticker.C
	}
	t.Fatalf("process %d did not enter a stopped state", pid)
}

func requireProcessInCgroup(t *testing.T, pid int, cgroupPath string) {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		t.Fatal(err)
	}
	relative := strings.TrimPrefix(filepath.Clean(cgroupPath), "/sys/fs/cgroup")
	if relative == "" {
		relative = "/"
	}
	if strings.TrimSpace(string(raw)) != "0::"+relative {
		t.Fatalf("process %d cgroup=%q, want %q", pid, raw, "0::"+relative)
	}
}

func readControlHeartbeatSamples(t *testing.T, path string) []int64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(raw))
	samples := make([]int64, 0, len(lines))
	for _, line := range lines {
		sample, err := strconv.ParseInt(line, 10, 64)
		if err != nil || sample <= 0 {
			t.Fatalf("invalid control heartbeat sample %q: %v", line, err)
		}
		samples = append(samples, sample)
	}
	if len(samples) == 0 || !sort.SliceIsSorted(samples, func(i, j int) bool { return samples[i] < samples[j] }) {
		t.Fatalf("control heartbeat samples are empty or non-monotonic: %v", samples)
	}
	return samples
}

func requireControlHeartbeatProgress(t *testing.T, path string, maximum time.Duration) (int64, int64) {
	t.Helper()
	startSamples := readControlHeartbeatSamples(t, path)
	start := startSamples[len(startSamples)-1]
	deadline := time.Now().Add(maximum)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		samples := readControlHeartbeatSamples(t, path)
		current := samples[len(samples)-1]
		if current > start {
			return start, current
		}
		<-ticker.C
	}
	t.Fatalf("control heartbeat did not advance from %d within %s", start, maximum)
	return 0, 0
}

type controlHeartbeatProof struct {
	first  int64
	last   int64
	maxGap time.Duration
}

func requireControlHeartbeatContinuous(t *testing.T, path string, faultStartNS, frozenNS int64, maximumGap time.Duration) controlHeartbeatProof {
	t.Helper()
	if faultStartNS <= 0 || frozenNS < faultStartNS || maximumGap <= 0 {
		t.Fatalf("invalid control heartbeat window: start=%d frozen=%d max_gap=%s", faultStartNS, frozenNS, maximumGap)
	}
	target := frozenNS + int64(300*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var samples []int64
	for time.Now().Before(deadline) {
		samples = readControlHeartbeatSamples(t, path)
		if samples[len(samples)-1] >= target {
			break
		}
		<-ticker.C
	}
	if len(samples) == 0 || samples[len(samples)-1] < target {
		t.Fatalf("control heartbeat did not continue after guarded freeze: last=%v target=%d", samples, target)
	}
	startIndex := -1
	endIndex := -1
	for index, sample := range samples {
		if sample <= faultStartNS {
			startIndex = index
		}
		if endIndex < 0 && sample >= target {
			endIndex = index
		}
	}
	if startIndex < 0 || endIndex <= startIndex {
		t.Fatalf("control heartbeat does not span fault/freeze window: start=%d frozen=%d samples=%v", faultStartNS, frozenNS, samples)
	}
	var maxGap time.Duration
	for index := startIndex + 1; index <= endIndex; index++ {
		gap := time.Duration(samples[index] - samples[index-1])
		if gap > maxGap {
			maxGap = gap
		}
		if gap > maximumGap {
			t.Fatalf("control heartbeat gap %s exceeds %s between %d and %d", gap, maximumGap, samples[index-1], samples[index])
		}
	}
	return controlHeartbeatProof{
		first: samples[startIndex], last: samples[endIndex], maxGap: maxGap,
	}
}

func monotonicNowNS(t *testing.T) int64 {
	t.Helper()
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	return now.Nano()
}

type guardianFreezeTrace struct {
	command       *exec.Cmd
	done          chan error
	prefix        string
	tracerPID     int
	guardianPID   int
	guardianStart uint64
	threadIDs     map[int]bool
}

func startGuardianFreezeTrace(t *testing.T, temp string, guardianPID int, expectedStart uint64) *guardianFreezeTrace {
	t.Helper()
	if _, err := exec.LookPath("strace"); err != nil {
		t.Fatalf("strace is required for guardian freezer attribution: %v", err)
	}
	start := processStartTicks(t, guardianPID)
	if start != expectedStart {
		t.Fatalf("guardian identity changed before tracing: pid=%d start=%d want=%d", guardianPID, start, expectedStart)
	}
	prefix := filepath.Join(temp, "guardian-freeze.trace")
	command := exec.Command(
		"strace", "-ff", "-yy",
		"-e", "trace=openat,openat2,write",
		"-o", prefix,
		"-p", strconv.Itoa(guardianPID),
	)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	trace := &guardianFreezeTrace{
		command: command, done: make(chan error, 1), prefix: prefix,
		tracerPID: command.Process.Pid, guardianPID: guardianPID,
		guardianStart: start, threadIDs: map[int]bool{},
	}
	go func() { trace.done <- command.Wait() }()
	attached := false
	defer func() {
		if !attached {
			trace.stop(t)
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		select {
		case err := <-trace.done:
			trace.command = nil
			t.Fatalf("strace exited before attachment: %v: %s", err, diagnostics.String())
		default:
		}
		if trace.tryRequireAttached() {
			attached = true
			return trace
		}
		<-ticker.C
	}
	t.Fatalf("strace %d did not attach to guardian %d and all threads: %s", trace.tracerPID, guardianPID, diagnostics.String())
	return nil
}

func (trace *guardianFreezeTrace) tryRequireAttached() bool {
	if processStartTicksRaw(trace.guardianPID) != trace.guardianStart {
		return false
	}
	threads, err := processThreadIDs(trace.guardianPID)
	if err != nil || len(threads) == 0 {
		return false
	}
	for _, tid := range threads {
		tracerPID, err := processTracerPID(tid)
		if err != nil || tracerPID != trace.tracerPID {
			return false
		}
	}
	for _, tid := range threads {
		trace.threadIDs[tid] = true
	}
	return true
}

func (trace *guardianFreezeTrace) requireAttached(t *testing.T) {
	t.Helper()
	if !trace.tryRequireAttached() {
		t.Fatalf("strace %d is not attached to guardian %d and every current thread", trace.tracerPID, trace.guardianPID)
	}
}

func (trace *guardianFreezeTrace) stop(t *testing.T) {
	t.Helper()
	if trace == nil || trace.command == nil {
		return
	}
	select {
	case <-trace.done:
		trace.command = nil
		return
	default:
	}
	_ = trace.command.Process.Signal(os.Interrupt)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-trace.done:
	case <-timer.C:
		_ = trace.command.Process.Kill()
		killTimer := time.NewTimer(2 * time.Second)
		defer killTimer.Stop()
		select {
		case <-trace.done:
			t.Errorf("strace required SIGKILL after interrupt")
		case <-killTimer.C:
			t.Errorf("strace did not exit after SIGKILL")
		}
	}
	trace.command = nil
}

func (trace *guardianFreezeTrace) requireExactFreezeWrite(t *testing.T, freezerPath string) (int, string) {
	t.Helper()
	files, err := filepath.Glob(trace.prefix + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("guardian trace produced no files")
	}
	type match struct {
		tid  int
		line string
	}
	var matches []match
	for _, path := range files {
		suffix := strings.TrimPrefix(path, trace.prefix+".")
		tid, err := strconv.Atoi(suffix)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "write(") &&
				strings.Contains(trimmed, "<"+freezerPath+">") &&
				strings.Contains(trimmed, `"1\n", 2)`) &&
				strings.HasSuffix(trimmed, "= 2") {
				matches = append(matches, match{tid: tid, line: trimmed})
			}
		}
	}
	if len(matches) != 1 {
		t.Fatalf("guardian exact freezer writes=%#v, want exactly one", matches)
	}
	if !trace.threadIDs[matches[0].tid] {
		t.Fatalf("freezer writer TID %d was not an attached guardian thread: %#v", matches[0].tid, trace.threadIDs)
	}
	return matches[0].tid, matches[0].line
}

func processStartTicks(t *testing.T, pid int) uint64 {
	t.Helper()
	start := processStartTicksRaw(pid)
	if start == 0 {
		t.Fatalf("read process %d start time", pid)
	}
	return start
}

func processStartTicksRaw(pid int) uint64 {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	closeParen := bytes.LastIndexByte(raw, ')')
	if closeParen < 0 || closeParen+2 >= len(raw) {
		return 0
	}
	fields := strings.Fields(string(raw[closeParen+2:]))
	if len(fields) <= 19 {
		return 0
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return start
}

func processThreadIDs(pid int) ([]int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	threads := make([]int, 0, len(entries))
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err == nil {
			threads = append(threads, tid)
		}
	}
	sort.Ints(threads)
	return threads, nil
}

func processTracerPID(tid int) (int, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return 0, fmt.Errorf("malformed TracerPid line %q", line)
			}
			return strconv.Atoi(fields[1])
		}
	}
	return 0, errors.New("process status has no TracerPid")
}

func openPidfdForIdentity(t *testing.T, pid int, expectedStart uint64, name string) int {
	t.Helper()
	before := processStartTicks(t, pid)
	if before != expectedStart {
		t.Fatalf("%s identity changed before pidfd open: pid=%d start=%d want=%d", name, pid, before, expectedStart)
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatalf("open %s pidfd for %d: %v", name, pid, err)
	}
	after := processStartTicksRaw(pid)
	if after != expectedStart {
		_ = unix.Close(pidfd)
		t.Fatalf("%s identity changed across pidfd open: pid=%d start=%d want=%d", name, pid, after, expectedStart)
	}
	return pidfd
}

func requirePidfdAlive(t *testing.T, pidfd int, name string) {
	t.Helper()
	exited, err := pollPidfd(pidfd, 0)
	if err != nil {
		t.Fatalf("poll %s pidfd: %v", name, err)
	}
	if exited {
		t.Fatalf("%s exited before fault injection", name)
	}
}

func pollPidfd(pidfd, timeoutMS int) (bool, error) {
	for attempts := 0; attempts < 16; attempts++ {
		pollfds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		_, err := unix.Poll(pollfds, timeoutMS)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return pollfds[0].Revents != 0, err
	}
	return false, errors.New("pidfd poll repeatedly interrupted")
}

func pidfdExited(pidfd int, deadline time.Time) bool {
	for time.Now().Before(deadline) {
		exited, err := pollPidfd(pidfd, 10)
		if err != nil {
			return false
		}
		if exited {
			return true
		}
	}
	return false
}

func waitForPidfdExit(t *testing.T, pidfd int, name string, deadline time.Time) {
	t.Helper()
	if pidfdExited(pidfd, deadline) {
		return
	}
	t.Fatalf("%s did not exit before deadline", name)
}

func waitForCgroupEmptyCleanup(t *testing.T, cgroupPath string, maximum time.Duration) {
	t.Helper()
	deadline := time.Now().Add(maximum)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var last []byte
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.events"))
		if os.IsNotExist(err) {
			return
		}
		if err == nil {
			last = raw
			fields := strings.Fields(string(raw))
			for index := 0; index+1 < len(fields); index += 2 {
				if fields[index] == "populated" && fields[index+1] == "0" {
					return
				}
			}
		}
		<-ticker.C
	}
	t.Errorf("cgroup %q did not become empty during cleanup: %q", cgroupPath, last)
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
