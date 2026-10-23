//go:build linux

package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/orka-agents/orka/internal/acp"

	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	guarddbackend "github.com/orka-agents/orka/workers/acp/supervisor/guardd"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRealSuiteNetworkSupervisor(t *testing.T) {
	root := os.Getenv("ORKA_REAL_NETWORK_ROOT")
	if root == "" {
		t.Skip("requires disposable privileged qualification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	backend, err := guarddbackend.ReadBackend(filepath.Join(root, "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(backend.CgroupRoot, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(backend.CgroupRoot)
	raw, err := os.ReadFile(os.Getenv("ORKA_NETWORK_REQUIREMENT"))
	if err != nil {
		t.Fatal(err)
	}
	var requirement harnessv2.ExecutionRequirement
	if err = json.Unmarshal(raw, &requirement); err != nil {
		t.Fatal(err)
	}
	var requests int
	listener, err := net.Listen("tcp4", "127.0.0.1:28181")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		requests++
		t.Logf("native inference request %d bytes=%d", requests, len(raw))
		w.Header().Set("Content-Type", "text/event-stream")
		emit := func(v map[string]any) {
			encoded, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", v["type"], encoded)
		}
		if requests == 1 {
			var request struct {
				Tools []struct {
					Name   string `json:"name"`
					Type   string `json:"type"`
					Format struct {
						Syntax string `json:"syntax"`
					} `json:"format"`
				} `json:"tools"`
			}
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Error(err)
				return
			}
			toolName := ""
			custom := false
			for _, tool := range request.Tools {
				t.Logf("tool=%s type=%s", tool.Name, tool.Type)
				if tool.Name == "exec_command" || tool.Name == "shell_command" || tool.Name == "shell" {
					toolName = tool.Name
					custom = tool.Type == "custom"
					break
				}
			}
			if toolName == "" {
				t.Error("native command tool missing")
				http.Error(w, "command tool missing", 422)
				return
			}
			command := `python3 - <<'PROBE'
import socket,pathlib,json
p=pathlib.Path('network-probes.json')
results={}
for label,port in [('allowed',28182),('denied',28183)]:
 s=socket.socket();s.settimeout(3)
 try:
  s.connect(('127.0.0.1',port));s.sendall(b'network-probe');results[label]='connected'
 except OSError as e:results[label]=str(e)
 finally:s.close()
for label,family,kind in [('ipv6',socket.AF_INET6,socket.SOCK_STREAM),('udp',socket.AF_INET,socket.SOCK_DGRAM),('packet',socket.AF_PACKET,socket.SOCK_RAW)]:
 try:s=socket.socket(family,kind);s.close();results[label]='CREATED'
 except OSError as e:results[label]=str(e)
p.write_text(json.dumps(results,sort_keys=True));print(results)
PROBE`
			args, _ := json.Marshal(map[string]any{"command": command, "cmd": command, "yield_time_ms": 10000, "max_output_tokens": 2000})
			if custom {
				t.Error("native command unexpectedly custom")
				return
			}
			item := map[string]any{"type": "function_call", "id": "network-tool", "call_id": "network-call", "name": toolName, "arguments": string(args)}
			emit(map[string]any{"type": "response.created", "response": map[string]any{"id": "network-tool-response"}})
			added := map[string]any{"type": "function_call", "id": "network-tool", "call_id": "network-call", "name": toolName, "arguments": ""}
			emit(map[string]any{"type": "response.output_item.added", "output_index": 0, "item": added})
			emit(map[string]any{"type": "response.output_item.done", "output_index": 0, "item": item})
			emit(map[string]any{"type": "response.completed", "response": map[string]any{"id": "network-tool-response", "output": []any{item}, "usage": map[string]any{"input_tokens": 10, "output_tokens": 10, "total_tokens": 20}}})
			return
		}
		emit(map[string]any{"type": "response.created", "response": map[string]any{"id": "network-real"}})
		item := map[string]any{"type": "message", "role": "assistant", "id": "network-message", "content": []any{map[string]any{"type": "output_text", "text": "NETWORK_NATIVE_OK"}}}
		emit(map[string]any{"type": "response.output_item.added", "output_index": 0, "item": item})
		emit(map[string]any{"type": "response.output_text.delta", "item_id": "network-message", "output_index": 0, "content_index": 0, "delta": "NETWORK_NATIVE_OK"})
		emit(map[string]any{"type": "response.output_item.done", "output_index": 0, "item": item})
		emit(map[string]any{"type": "response.completed", "response": map[string]any{"id": "network-real", "usage": map[string]any{"input_tokens": 10, "output_tokens": 10, "total_tokens": 20}}})
	})}
	go upstream.Serve(listener)
	defer upstream.Close()
	allowedListener, err := net.Listen("tcp4", "127.0.0.1:28182")
	if err != nil {
		t.Fatal(err)
	}
	defer allowedListener.Close()
	deniedListener, err := net.Listen("tcp4", "127.0.0.1:28183")
	if err != nil {
		t.Fatal(err)
	}
	defer deniedListener.Close()
	allowedHit := make(chan string, 1)
	deniedHit := make(chan bool, 1)
	go func() {
		c, err := allowedListener.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 64)
			n, _ := c.Read(buf)
			allowedHit <- string(buf[:n])
		}
	}()
	go func() {
		c, err := deniedListener.Accept()
		if err == nil {
			c.Close()
			deniedHit <- true
		}
	}()

	const model = "gpt-4.1"
	cfg, _ := newTestConfigWithUpstream(t, "unused", "http://127.0.0.1:28181/v1", "local-test-only")
	cfg.ProviderProxy.ListenAddress = "127.0.0.1:28184"
	// Exact policy is extended by the Suite resolver to include this proxy, not
	// mutated by the supervisor. Upstream is intentionally also listed so the
	// leaf qualification and this test consume the identical frozen descriptor.
	cfg.ExecHelperCommand = "/tmp/suite-policy-implementation/native/orka-acp-exec-helper"
	cfg.RequirementBackends = []RequirementBackend{backend}
	projection := testProviderProjectionRequest(t, "codex", model, "Use native commands for the probe.", "high", nil, nil, true)
	projection.Profile.WorkspaceIntent = harnessv2.WorkspaceIntentWrite
	provider, err := providerProfile("codex", model, harnessv2.WorkspaceIntentWrite)
	if err != nil {
		t.Fatal(err)
	}
	provider.Command = "/usr/bin/node"
	provider.Args = []string{"/tmp/suite-policy-implementation/native/acp-source/dist/index.js"}
	originalEnvironment := provider.EnvironmentForSession
	provider.EnvironmentForSession = func(r harnessv2.CreateRuntimeSessionRequest, paths acp.SessionPaths, proxy ProviderProxyBinding) (map[string]string, error) {
		env, err := originalEnvironment(r, paths, proxy)
		if err == nil {
			env["CODEX_PATH"] = "/tmp/suite-policy-implementation/native/codex/bin/codex"
		}
		return env, err
	}
	provider.Environment = map[string]string{"PATH": "/tmp/suite-policy-implementation/native/codex/bin:/usr/bin:/bin"}
	profile := projection.Profile
	profile.AdapterDigests = map[string]string{provider.AdapterName: provider.AdapterDigest}
	digest, err := harnessv2.CanonicalProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Provider = provider
	cfg.ProviderProxy.Model = model
	cfg.Fence.RuntimeProfileDigest = digest
	cfg.Capabilities.RuntimeProfileDigest = digest
	cfg.Capabilities.AdapterDigests = profile.AdapterDigests
	cfg.Capabilities.Provider.Models = []string{model}
	cfg.InitializeTimeout = time.Minute
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := server.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	create := testCreateSessionRequest(t, cfg, profile)
	create.Workspace.Intent = harnessv2.WorkspaceIntentWrite
	create.Requirement = requirement.Clone()
	create.AgentConfiguration = projection.AgentConfiguration
	create.MCPConfiguration = projection.MCPConfiguration
	create.Metadata.ExpiresAt = time.Now().UTC().Add(3 * time.Minute)
	sealRequest(t, &create.Metadata.RequestDigest, create)
	response := performMutation(t, server.Handler(), http.MethodPut, "/v2/runtime-sessions/session-1", create, cfg)
	if response.Code != http.StatusCreated {
		t.Fatalf("real governed create: %d %s", response.Code, response.Body.String())
	}
	t.Log("authenticated supervisor create traversed whole-policy support, target preparation, activation, release and native initialize")
	var created harnessv2.CreateRuntimeSessionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	selected := created.Session.Enforcement
	if selected == nil || selected.Backend != backend.Identity() || selected.RequirementIdentity != requirement.Identity || selected.Phase != "active" || selected.TargetGeneration == 0 || selected.TargetIdentity == "" {
		t.Fatalf("native create association: %+v", selected)
	}
	current := readPromptTestStatus(t, server, cfg).Sessions[0].Enforcement
	if current == nil || *current != *selected {
		t.Fatalf("authenticated native status differs from create association: %+v %+v", current, selected)
	}
	t.Logf("authenticated native status after initialization context retired: backend=%s requirement=%s targetGeneration=%d targetIdentity=%s phase=%s", current.Backend, current.RequirementIdentity, current.TargetGeneration, current.TargetIdentity, current.Phase)

	if os.Getenv("ORKA_TEST_DAEMON_LOSS") == "1" {
		if err = os.WriteFile(filepath.Join(root, "ready-for-loss"), []byte("held activation already released"), 0600); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err = os.Stat(filepath.Join(root, "loss-completed")); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		t.Log("required Guardd process killed and restarted; pre-existing pinned restrictions must still hold for native commands")
	}

	server.mu.Lock()
	workspace := server.sessions[create.RuntimeSessionID].paths.Workspace
	server.mu.Unlock()
	prompt := testStartPromptRequest(t, cfg, create.Metadata.Fence)
	prompt.MCPAuthorization.ToolPolicyDigest = create.MCPConfiguration.ToolPolicyDigest
	prompt.MCPAuthorization.ApprovalPolicyDigest = create.MCPConfiguration.ApprovalPolicyDigest
	prompt.MCPAuthorization.MCPConfigurationDigest = create.MCPConfiguration.MCPConfigurationDigest
	prompt.MCPAuthorization.ToolPolicy = create.MCPConfiguration.ToolPolicy
	prompt.MCPAuthorization.ApprovalPolicy = create.MCPConfiguration.ApprovalPolicy
	prompt.MCPAuthorization.ExpiresAt = prompt.Metadata.ExpiresAt
	prompt.Input.Content[0].Text = "Run the network probes then say NETWORK_NATIVE_OK"
	sealRequest(t, &prompt.Metadata.RequestDigest, prompt)
	response = performMutation(t, server.Handler(), http.MethodPut, "/v2/runtime-sessions/session-1/prompts/prompt-1", prompt, cfg)
	if response.Code != http.StatusOK {
		t.Fatalf("real governed prompt: %d %s", response.Code, response.Body.String())
	}
	if requests < 2 {
		t.Fatal("native command never completed")
	}
	probe, err := os.ReadFile(filepath.Join(workspace, "network-probes.json"))
	if err != nil {
		t.Fatalf("native probe entrypoint missing: %v; diagnostics=%s", err, "supervisor diagnostics in response")
	}
	t.Logf("native tool effects: %s", probe)
	var effects map[string]string
	if err = json.Unmarshal(probe, &effects); err != nil {
		t.Fatal(err)
	}
	if effects["allowed"] != "connected" || effects["denied"] == "connected" || effects["ipv6"] == "CREATED" || effects["udp"] == "CREATED" || effects["packet"] == "CREATED" {
		t.Fatalf("network bypass: %s", probe)
	}
	select {
	case got := <-allowedHit:
		if got != "network-probe" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("independent allowed endpoint saw no probe")
	}
	select {
	case <-deniedHit:
		t.Fatal("prohibited endpoint accepted traffic")
	default:
	}
	if err = os.WriteFile(filepath.Join(root, "verified-native-probes.json"), probe, 0600); err != nil {
		t.Fatal(err)
	}

	// The native probe file is ephemeral test output, not a publication. Remove
	// it before the ordinary no-change workspace validation path; never fake the
	// supervisor state to bypass its publication/deletion preconditions.
	if err = os.Remove(filepath.Join(workspace, "network-probes.json")); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	settlementDigest := server.sessions[create.RuntimeSessionID].prompt.settlementDigest
	server.mu.Unlock()
	delta := harnessv2.CreateWorkspaceDeltaRequest{Protocol: harnessv2.ProtocolVersion, Metadata: testMetadata(create.Metadata.Fence, "network-delta", true), DeltaID: "network-delta", Intent: create.Workspace.Intent, VerifiedBaseline: create.Workspace.Baseline, PromptSettlementDigest: settlementDigest, Limits: harnessv2.WorkspaceDeltaLimits{MaxBytes: 1 << 20, MaxEntries: 100}}
	sealRequest(t, &delta.Metadata.RequestDigest, delta)
	response = performMutation(t, server.Handler(), http.MethodPut, "/v2/runtime-sessions/session-1/workspace-deltas/network-delta", delta, cfg)
	if response.Code != http.StatusOK {
		t.Fatalf("governed workspace validation: %d %s", response.Code, response.Body.String())
	}
	var validated harnessv2.CreateWorkspaceDeltaResponse
	if err = json.Unmarshal(response.Body.Bytes(), &validated); err != nil {
		t.Fatal(err)
	}
	if validated.Delta.State != harnessv2.WorkspaceDeltaNoChange {
		t.Fatalf("unexpected native delta %+v", validated)
	}
	deletion := harnessv2.DeleteRuntimeSessionRequest{Protocol: harnessv2.ProtocolVersion, Metadata: testMetadata(create.Metadata.Fence, "delete-governed", false)}
	sealRequest(t, &deletion.Metadata.RequestDigest, deletion)
	response = performMutation(t, server.Handler(), http.MethodDelete, "/v2/runtime-sessions/session-1", deletion, cfg)
	if response.Code != http.StatusOK {
		t.Fatalf("governed deletion: %d %s", response.Code, response.Body.String())
	}
	entries, err := os.ReadDir(backend.StateRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("activation residue: %v %v", entries, err)
	}
	t.Log("authenticated session deletion independently proved empty cgroup, kernel restriction removal and no local association residue")
}
