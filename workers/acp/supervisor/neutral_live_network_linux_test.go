//go:build linux

package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/orka-agents/orka/internal/acp"
	v2 "github.com/orka-agents/orka/internal/harness/v2"
	guarddbackend "github.com/orka-agents/orka/workers/acp/supervisor/enforcementunix"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNeutralLiveNativeNetworkRuntime(t *testing.T) {
	root := os.Getenv("ORKA_LIVE_ROOT")
	if root == "" {
		t.Skip("explicit live qualification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	var startup struct {
		Profile v2.RuntimeProfile
		Fence   v2.Fence
	}
	for {
		raw, e := os.ReadFile(filepath.Join(root, "runtime-plan.json"))
		if e == nil {
			if e = json.Unmarshal(raw, &startup); e != nil {
				t.Fatal(e)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	backend, err := guarddbackend.ReadBackend(filepath.Join(root, "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(backend.CgroupRoot, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(backend.CgroupRoot)
	if err = backend.RetireUnfinished(ctx); err != nil {
		t.Fatal("startup retirement", err)
	}
	var requests int
	probeVerified := make(chan map[string]string, 1)
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
print(json.dumps(results,sort_keys=True))
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
		// Read the actual native function result, not a fabricated model verdict.
		var next struct {
			Input []struct {
				Type   string `json:"type"`
				Output string `json:"output"`
			} `json:"input"`
		}
		if err := json.Unmarshal(raw, &next); err != nil {
			t.Error(err)
			http.Error(w, "invalid subsequent request", 422)
			return
		}
		verified := false
		for _, input := range next.Input {
			if input.Type != "function_call_output" {
				continue
			}
			for _, line := range strings.Split(input.Output, "\n") {
				start := strings.Index(line, "{\"allowed\"")
				if start < 0 {
					continue
				}
				var result map[string]string
				if e := json.Unmarshal([]byte(line[start:]), &result); e != nil {
					continue
				}
				if result["allowed"] != "connected" {
					t.Errorf("allowed native result: %v", result)
					continue
				}
				for _, label := range []string{"denied", "udp", "ipv6", "packet"} {
					if !strings.Contains(result[label], "Operation not permitted") {
						t.Errorf("native denial %s: %v", label, result)
						http.Error(w, "native denial absent", 422)
						return
					}
				}
				evidence, e := json.MarshalIndent(result, "", "  ")
				if e != nil {
					t.Error(e)
					return
				}
				if e = os.WriteFile(filepath.Join(root, "native-probes.json"), evidence, 0600); e != nil {
					t.Error(e)
					return
				}
				probeVerified <- result
				verified = true
			}
		}
		if !verified {
			t.Error("native function output lacks verified probe result")
			http.Error(w, "native probe evidence missing", 422)
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

	cfg, _ := newTestConfigWithUpstream(t, "unused", "http://127.0.0.1:28181/v1", "local-test-only")
	cfg.UIDAllocator, err = acp.NewUIDAllocator(41000, 41100, 41000)
	if err != nil {
		t.Fatal(err)
	}
	cfg.InitializeTimeout = acp.DefaultInitializeTimeout
	cfg.ProviderProxy.Model = startup.Profile.Model
	cfg.Capabilities.Provider.Models = []string{startup.Profile.Model}
	cfg.Fence = startup.Fence
	cfg.Capabilities.RuntimeProfileDigest = startup.Fence.RuntimeProfileDigest
	cfg.Capabilities.AdapterDigests = startup.Profile.AdapterDigests
	cfg.ExecHelperCommand = os.Getenv("ORKA_NEUTRAL_EXEC_HELPER")
	cfg.RequirementBackends = []RequirementBackend{backend}
	mode := os.Getenv("ORKA_LIVE_MODE")
	if mode == "missing" {
		cfg.RequirementBackends = nil
	}

	cfg.ProviderProxy.ListenAddress = "127.0.0.1:28184"
	provider, err := providerProfile("codex", startup.Profile.Model, startup.Profile.WorkspaceIntent)
	if err != nil {
		t.Fatal(err)
	}
	markerDir := filepath.Join(root, "entrypoint-markers")
	if err = os.MkdirAll(markerDir, 0733); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(markerDir, 0733); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(root, "adapter-entrypoint.sh")
	script := "#!/bin/sh\nprintf entered > '" + filepath.Join(markerDir, "entered") + "'\nexec /usr/bin/node /tmp/suite-policy-implementation/native/acp-source/dist/index.js\n"
	if err = os.WriteFile(wrapper, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	provider.Command = wrapper
	provider.Args = nil
	original := provider.EnvironmentForSession
	provider.EnvironmentForSession = func(r v2.CreateRuntimeSessionRequest, p acp.SessionPaths, b ProviderProxyBinding) (map[string]string, error) {
		env, e := original(r, p, b)
		if e == nil {
			env["CODEX_PATH"] = "/tmp/suite-policy-implementation/native/codex/bin/codex"
		}
		return env, e
	}
	provider.Environment = map[string]string{"PATH": "/tmp/suite-policy-implementation/native/codex/bin:/usr/bin:/bin"}
	cfg.Provider = provider
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	listener, err = net.Listen("tcp", "127.0.0.1:28285")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: server.Handler()}
	go httpServer.Serve(listener)
	defer httpServer.Close()
	t.Log("real supervisor is ready for the actual controller request")
	for {
		if _, e := os.Stat(filepath.Join(root, "live-terminal-task.json")); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if mode != "" {
		if _, e := os.Stat(filepath.Join(markerDir, "entered")); !os.IsNotExist(e) {
			t.Fatalf("entrypoint marker exists or uncertain: %v", e)
		}
		if requests != 0 {
			t.Fatalf("failed activation still made native inference: %d", requests)
		}
		server.mu.Lock()
		remaining := len(server.sessions)
		server.mu.Unlock()
		if remaining != 0 {
			t.Fatalf("failed session retained: %d", remaining)
		}
		entries, e := os.ReadDir(backend.StateRoot)
		if !os.IsNotExist(e) && (e != nil || len(entries) != 0) {
			t.Fatalf("failed activation cleanup: %v %v", entries, e)
		}
		t.Logf("live %s: no adapter entrypoint marker, no inference, no session or activation residue", mode)
		return
	}
	if _, e := os.Stat(filepath.Join(markerDir, "entered")); e != nil {
		t.Fatal("success entrypoint marker missing", e)
	}
	select {
	case result := <-probeVerified:
		t.Logf("native function result independently parsed: %v", result)
	default:
		t.Fatal("native output unverified")
	}
	select {
	case hit := <-allowedHit:
		if hit != "network-probe" {
			t.Fatal(hit)
		}
	case <-time.After(time.Second):
		t.Fatal("allowed listener never hit")
	}
	select {
	case <-deniedHit:
		t.Fatal("denied endpoint reached")
	default:
	}
	server.mu.Lock()
	remaining := len(server.sessions)
	server.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("runtime session residue: %d", remaining)
	}
	entries, e := os.ReadDir(backend.StateRoot)
	if e != nil || len(entries) != 0 {
		t.Fatalf("activation residue: %v %v", entries, e)
	}
	t.Log("actual controller session completed; independent allowed arrival and denied absence verified, native session and activation fully cleaned")
}
