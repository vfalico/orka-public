//go:build linux

/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/orka-agents/orka/internal/guarddclient"
	"github.com/orka-agents/orka/internal/harness/v2"
)

var safeCgroupComponent = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

type policyActivationLifetime struct {
	client     *guarddclient.Client
	binding    guarddclient.Binding
	cgroupPath string
}

type guarddPolicyRule struct {
	ID   uint32 `json:"id"`
	Path string `json:"path"`
}
type guarddPolicySubject struct {
	TaskUID   string `json:"taskUID"`
	SessionID string `json:"sessionID"`
}
type guarddPolicySpec struct {
	Subject         guarddPolicySubject `json:"subject"`
	FailureMode     string              `json:"failureMode"`
	DenyExecutables []guarddPolicyRule  `json:"denyExecutables,omitempty"`
	DenyWrites      []guarddPolicyRule  `json:"denyWrites,omitempty"`
}
type guarddPolicyMetadata struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type guarddPolicyDocument struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Metadata   guarddPolicyMetadata `json:"metadata"`
	Spec       guarddPolicySpec     `json:"spec"`
}

func buildGuarddPolicyDocument(policy v2.AgentPolicyActivation, metadata v2.MutationMetadata, sessionID, component string) guarddPolicyDocument {
	document := guarddPolicyDocument{
		APIVersion: "agentpolicy.gadget/v1alpha1",
		Kind:       "AgentPolicy",
		Metadata:   guarddPolicyMetadata{Name: policyName(component), Digest: policy.Digest},
		Spec: guarddPolicySpec{
			Subject:     guarddPolicySubject{TaskUID: string(metadata.TaskUID), SessionID: sessionID},
			FailureMode: "closed",
		},
	}
	for index, rule := range policy.DenyFiles {
		document.Spec.DenyWrites = append(document.Spec.DenyWrites, guarddPolicyRule{ID: uint32(index + 1), Path: rule.Path})
	}
	return document
}

type guarddRuntimeConfig struct {
	SocketPath                  string
	AuthorizationIssuerID       string
	AuthorizationPrivateKeyFile string
	ReceiptPublicKeyFile        string
	ReceiptDirectory            string
	GadgetDigest                string
	NodeID                      string
	CgroupRoot                  string
}

func kernelBootID() string {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func activateAgentPolicy(ctx context.Context, cfg guarddRuntimeConfig, policy v2.AgentPolicyActivation, metadata v2.MutationMetadata, sessionID string, pid int) (_ io.Closer, receipt *v2.AgentPolicyReceipt, retErr error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("AgentPolicy activation requires a root runtime supervisor")
	}
	if err := validateGuarddRuntimeConfig(cfg); err != nil {
		return nil, nil, err
	}
	if err := policy.Validate(); err != nil {
		return nil, nil, err
	}
	component := safeCgroupComponent.ReplaceAllString(sessionID, "-")
	if component == "" || component == "." || component == ".." {
		return nil, nil, errors.New("runtime session ID cannot identify a policy cgroup")
	}
	if err := os.MkdirAll(cfg.CgroupRoot, 0o755); err != nil {
		return nil, nil, fmt.Errorf("create AgentPolicy cgroup root: %w", err)
	}
	path := filepath.Join(cfg.CgroupRoot, component)
	if err := os.Mkdir(path, 0o755); err != nil {
		return nil, nil, fmt.Errorf("create exact task cgroup: %w", err)
	}
	lifetime := &policyActivationLifetime{cgroupPath: path}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, lifetime.closeLocal())
		}
	}()
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return nil, nil, fmt.Errorf("move held provider into exact task cgroup: %w", err)
	}
	cgroup, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open exact task cgroup: %w", err)
	}
	defer cgroup.Close()
	cgroupID, err := cgroupIdentity(path)
	if err != nil {
		return nil, nil, err
	}

	document := buildGuarddPolicyDocument(policy, metadata, sessionID, component)
	policyTree := guarddPolicyMap(document)
	guarddDigest, err := guarddclient.DigestCanonicalJSON(policyTree)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize guardd AgentPolicy: %w", err)
	}
	authorizationKey, err := guarddclient.LoadPrivateKey(cfg.AuthorizationPrivateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read guardd authorization private key: %w", err)
	}
	publicKey, err := guarddclient.LoadPublicKey(cfg.ReceiptPublicKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read guardd receipt public key: %w", err)
	}
	client, err := guarddclient.New(guarddclient.Config{
		SocketPath: cfg.SocketPath, AuthorizationPrivateKey: authorizationKey,
		AuthorizationIssuerID: cfg.AuthorizationIssuerID, BootID: kernelBootID(),
		ReceiptPublicKey: publicKey, ReceiptDirectory: cfg.ReceiptDirectory,
		Timeout: 15 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	binding := guarddclient.Binding{
		SessionID: sessionID, Attempt: strconv.FormatUint(uint64(metadata.TaskAttempt), 10),
		Generation: 1, PolicyDigest: guarddDigest, GadgetDigest: cfg.GadgetDigest, NodeID: cfg.NodeID,
	}
	guarddReceipt, err := client.Activate(ctx, binding, policyTree, cgroup)
	if err != nil {
		return nil, nil, fmt.Errorf("activate held provider through guardd: %w", err)
	}
	lifetime.client = client
	lifetime.binding = binding

	receiptBytes := []byte(guarddReceipt)
	receiptSum := sha256.Sum256(receiptBytes)
	compatibilityReceipt := &v2.AgentPolicyReceipt{
		Version: v2.AgentPolicyReceiptVersion, PolicyDigest: policy.Digest,
		TaskUID: string(metadata.TaskUID), TaskAttempt: metadata.TaskAttempt,
		RuntimeSessionID: sessionID, CgroupID: cgroupID,
		GuarddPolicyDigest: guarddDigest, GuarddReceipt: json.RawMessage(strconv.Quote(base64.StdEncoding.EncodeToString(receiptBytes))),
		GuarddReceiptDigest: "sha256:" + hex.EncodeToString(receiptSum[:]),
	}
	compatibilityReceipt.Digest, err = compatibilityReceiptDigest(compatibilityReceipt)
	if err != nil {
		return nil, nil, err
	}
	if err := compatibilityReceipt.ValidateFor(policy, string(metadata.TaskUID), metadata.TaskAttempt, sessionID, cgroupID); err != nil {
		return nil, nil, fmt.Errorf("validate persisted guardd activation evidence: %w", err)
	}
	return lifetime, compatibilityReceipt, nil
}

func validateGuarddRuntimeConfig(cfg guarddRuntimeConfig) error {
	for name, value := range map[string]string{
		"socket": cfg.SocketPath, "authorization private key": cfg.AuthorizationPrivateKeyFile,
		"receipt public key": cfg.ReceiptPublicKeyFile, "receipt directory": cfg.ReceiptDirectory,
		"cgroup root": cfg.CgroupRoot,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("guardd %s path must be clean and absolute", name)
		}
	}
	if cfg.AuthorizationIssuerID == "" || strings.TrimSpace(cfg.AuthorizationIssuerID) != cfg.AuthorizationIssuerID ||
		len(cfg.AuthorizationIssuerID) > 128 || strings.ContainsAny(cfg.AuthorizationIssuerID, "\x00\r\n") {
		return errors.New("guardd authorization issuer ID is invalid")
	}
	if cfg.NodeID == "" || strings.ContainsAny(cfg.NodeID, "/\\\x00") {
		return errors.New("guardd node ID is invalid")
	}
	if len(cfg.GadgetDigest) != 71 || !strings.HasPrefix(cfg.GadgetDigest, "sha256:") {
		return errors.New("guardd gadget digest is invalid")
	}
	if _, err := hex.DecodeString(cfg.GadgetDigest[7:]); err != nil {
		return errors.New("guardd gadget digest is invalid")
	}
	return nil
}

func validateAgentPolicyStartup(cfg Config) error {
	if cfg.AgentPolicyGuarddSocket == "" {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("AgentPolicy guardd requires a root runtime supervisor")
	}
	return validateAgentPolicyRuntimeFiles(cfg, 0)
}

func validateAgentPolicyRuntimeFiles(cfg Config, owner uint32) error {
	socket, err := os.Lstat(cfg.AgentPolicyGuarddSocket)
	if err != nil {
		return fmt.Errorf("stat AgentPolicy guardd socket: %w", err)
	}
	if socket.Mode()&os.ModeSocket == 0 {
		return errors.New("AgentPolicy guardd socket must be a Unix socket, not a symlink or regular file")
	}
	privateKey, err := readOwnedRegularFile(cfg.AgentPolicyAuthorizationPrivateKeyFile, owner, true)
	if err != nil {
		return fmt.Errorf("validate AgentPolicy authorization private key: %w", err)
	}
	if _, err := guarddclient.ParsePrivateKeyPEM(privateKey); err != nil {
		return fmt.Errorf("parse AgentPolicy authorization private key: %w", err)
	}
	receiptKey, err := readOwnedRegularFile(cfg.AgentPolicyReceiptPublicKeyFile, owner, false)
	if err != nil {
		return fmt.Errorf("validate AgentPolicy receipt public key: %w", err)
	}
	if _, err := guarddclient.ParsePublicKeyPEM(receiptKey); err != nil {
		return fmt.Errorf("parse AgentPolicy receipt public key: %w", err)
	}
	if err := validatePrivateDirectory(cfg.AgentPolicyReceiptDirectory, owner); err != nil {
		return fmt.Errorf("validate AgentPolicy receipt directory: %w", err)
	}
	probe, err := os.CreateTemp(cfg.AgentPolicyReceiptDirectory, ".orka-startup-*")
	if err != nil {
		return fmt.Errorf("probe AgentPolicy receipt directory: %w", err)
	}
	probeName := probe.Name()
	if err := probe.Chmod(0o600); err == nil {
		err = probe.Sync()
	}
	closeErr := probe.Close()
	removeErr := os.Remove(probeName)
	if err != nil {
		return fmt.Errorf("probe AgentPolicy receipt directory: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close AgentPolicy receipt probe: %w", closeErr)
	}
	if removeErr != nil {
		return fmt.Errorf("remove AgentPolicy receipt probe: %w", removeErr)
	}
	directory, err := os.Open(cfg.AgentPolicyReceiptDirectory)
	if err != nil {
		return fmt.Errorf("open AgentPolicy receipt directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync AgentPolicy receipt directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close AgentPolicy receipt directory: %w", closeErr)
	}
	return nil
}

func readOwnedRegularFile(path string, owner uint32, private bool) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open returned an invalid file descriptor")
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Uid != owner {
		return nil, errors.New("must be a regular file owned by the runtime supervisor")
	}
	mode := os.FileMode(stat.Mode).Perm()
	if private {
		if mode&0o077 != 0 {
			return nil, errors.New("must not grant group or other permissions")
		}
	} else if mode&0o022 != 0 {
		return nil, errors.New("must not grant group or other write permissions")
	}
	return io.ReadAll(file)
}

func validatePrivateDirectory(path string, owner uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != owner {
		return errors.New("must be a directory owned by the runtime supervisor")
	}
	if info.Mode().Perm() != 0o700 {
		return errors.New("must have mode 0700")
	}
	return nil
}

func policyName(component string) string {
	name := "orka-" + component
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return "orka-" + hex.EncodeToString(sum[:16])
}

func guarddPolicyMap(document guarddPolicyDocument) map[string]any {
	spec := map[string]any{
		"subject": map[string]any{
			"taskUID":   document.Spec.Subject.TaskUID,
			"sessionID": document.Spec.Subject.SessionID,
		},
		"failureMode": document.Spec.FailureMode,
	}
	if len(document.Spec.DenyExecutables) > 0 {
		rules := make([]any, 0, len(document.Spec.DenyExecutables))
		for _, rule := range document.Spec.DenyExecutables {
			rules = append(rules, map[string]any{"id": rule.ID, "path": rule.Path})
		}
		spec["denyExecutables"] = rules
	}
	if len(document.Spec.DenyWrites) > 0 {
		rules := make([]any, 0, len(document.Spec.DenyWrites))
		for _, rule := range document.Spec.DenyWrites {
			rules = append(rules, map[string]any{"id": rule.ID, "path": rule.Path})
		}
		spec["denyWrites"] = rules
	}
	return map[string]any{
		"apiVersion": document.APIVersion,
		"kind":       document.Kind,
		"metadata": map[string]any{
			"name":   document.Metadata.Name,
			"digest": document.Metadata.Digest,
		},
		"spec": spec,
	}
}

func compatibilityReceiptDigest(receipt *v2.AgentPolicyReceipt) (string, error) {
	copy := *receipt
	copy.Digest = ""
	payload, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(v2.AgentPolicyReceiptVersion+"\n"), payload...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func cgroupIdentity(path string) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, err
	}
	if stat.Ino == 0 {
		return 0, errors.New("exact task cgroup has no stable identity")
	}
	return stat.Ino, nil
}

func (l *policyActivationLifetime) Close() error {
	if l == nil {
		return nil
	}
	var result error
	if l.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result = errors.Join(result, l.client.Action(ctx, "terminate_handoff", l.binding))
		cancel()
	}
	if result == nil && l.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result = errors.Join(result, l.client.Action(ctx, "deactivate", l.binding))
		cancel()
	}
	if result == nil {
		result = errors.Join(result, l.closeLocal())
	}
	return result
}

func (l *policyActivationLifetime) closeLocal() error {
	if l == nil || l.cgroupPath == "" {
		return nil
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := os.Remove(l.cgroupPath)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			l.cgroupPath = ""
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}
