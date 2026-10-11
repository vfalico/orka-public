//go:build linux

/* Copyright (c) 2026. MIT License - see LICENSE file for details. */
package supervisor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestValidateAgentPolicyRuntimeFilesParsesKeysAndProbesReceiptDirectory(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "guardd.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "authorization-private.pem")
	publicPath := filepath.Join(dir, "receipt-public.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	receipts := filepath.Join(dir, "receipts")
	if err := os.Mkdir(receipts, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		AgentPolicyGuarddSocket:                socketPath,
		AgentPolicyAuthorizationPrivateKeyFile: privatePath,
		AgentPolicyReceiptPublicKeyFile:        publicPath,
		AgentPolicyReceiptDirectory:            receipts,
	}
	if err := validateAgentPolicyRuntimeFiles(cfg, uint32(os.Geteuid())); err != nil {
		t.Fatalf("validate AgentPolicy runtime files: %v", err)
	}
	entries, err := os.ReadDir(receipts)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("receipt startup probe was not removed: %#v", entries)
	}
}

func TestReadOwnedRegularFileRejectsUnsafePrivateKeyMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorization-private.pem")
	if err := os.WriteFile(path, []byte("private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Geteuid())
	if value, err := readOwnedRegularFile(path, owner, true); err != nil || string(value) != "private-key" {
		t.Fatalf("read safe private key = %q, %v", value, err)
	}
	if _, err := readOwnedRegularFile(path, owner+1, true); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("wrong-owner private key error = %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedRegularFile(path, owner, true); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("permissive private key error = %v", err)
	}
	link := filepath.Join(dir, "authorization-private-link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedRegularFile(link, owner, true); err == nil {
		t.Fatal("symlinked private key was accepted")
	}
}

func TestValidatePrivateDirectoryRequiresExactOwnerAndMode(t *testing.T) {
	dir := t.TempDir()
	owner := uint32(os.Geteuid())
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateDirectory(dir, owner); err != nil {
		t.Fatalf("validate safe receipt directory: %v", err)
	}
	if err := validatePrivateDirectory(dir, owner+1); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("wrong-owner receipt directory error = %v", err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateDirectory(dir, owner); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("permissive receipt directory error = %v", err)
	}
	link := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+"-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateDirectory(link, owner); err == nil {
		t.Fatal("symlinked receipt directory was accepted")
	}
}

func TestReadOwnedRegularFileAllowsReadOnlyPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt-public.pem")
	if err := os.WriteFile(path, []byte("public-key"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedRegularFile(path, stat.Uid, false); err != nil {
		t.Fatalf("read safe public key: %v", err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedRegularFile(path, stat.Uid, false); err == nil {
		t.Fatal("group-writable public key was accepted")
	}
}
