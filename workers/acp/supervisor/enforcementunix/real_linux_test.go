//go:build linux

package enforcementunix

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealNetworkHeldTarget(t *testing.T) {
	root := os.Getenv("ORKA_REAL_NETWORK_ROOT")
	if root == "" {
		t.Skip("requires disposable privileged qualification")
	}
	b, err := ReadBackend(filepath.Join(root, "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(b.CgroupRoot, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(b.CgroupRoot)
	requirementFile := os.Getenv("ORKA_NETWORK_REQUIREMENT")
	var r harnessv2.ExecutionRequirement
	raw, err := os.ReadFile(requirementFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if err = r.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	yes, err := b.Support(ctx, &r, "linux-amd64-acp-v1")
	if err != nil || !yes {
		t.Fatalf("support %v %v", yes, err)
	}
	req := harnessv2.CreateRuntimeSessionRequest{RuntimeSessionID: "real-network", Requirement: &r, Metadata: harnessv2.MutationMetadata{OperationID: "real-network-create", RequestDigest: harnessv2.RequestDigest("sha256:" + strings.Repeat("1", 64))}}
	e, err := b.Launch(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	sessionRoot := filepath.Join(root, "session")
	if err = os.MkdirAll(sessionRoot, 0711); err != nil {
		t.Fatal(err)
	}
	paths := acp.SessionPaths{Root: sessionRoot, Workspace: filepath.Join(sessionRoot, "workspace"), Home: filepath.Join(sessionRoot, "home"), Temp: filepath.Join(sessionRoot, "tmp")}
	for _, p := range []string{paths.Workspace, paths.Home, paths.Temp} {
		os.MkdirAll(p, 0700)
		os.Chown(p, 24001, 24001)
	}
	var requests int
	listener, err := net.Listen("tcp4", "127.0.0.1:28281")
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
for label,port in [('allowed',28282),('denied',28283)]:
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
	_ = upstream
	// First qualify the actual held helper and native Codex initialization; native
	// tool probes are added only after this executable baseline works.
	environment := []string{"PATH=/tmp/suite-policy-implementation/native/codex/bin:/usr/bin:/bin", "HOME=" + paths.Home, "TMPDIR=" + paths.Temp, "CODEX_API_KEY=local-test-only", "CODEX_CONFIG=" + `{"model":"gpt-4.1","model_provider":"orka","check_for_update_on_startup":false,"model_providers":{"orka":{"name":"local-scripted","base_url":"http://127.0.0.1:28281/v1","wire_api":"responses","env_key":"CODEX_API_KEY","supports_websockets":false}}}`}
	allowedListener, err := net.Listen("tcp4", "127.0.0.1:28282")
	if err != nil {
		t.Fatal(err)
	}
	defer allowedListener.Close()
	deniedListener, err := net.Listen("tcp4", "127.0.0.1:28283")
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
	cfg := acp.ProcessConfig{Command: "/usr/bin/node", Args: []string{"/tmp/suite-policy-implementation/native/acp-source/dist/index.js"}, Environment: environment, Paths: paths, UID: 24001, GID: 24001, ExecHelperCommand: os.Getenv("ORKA_NEUTRAL_EXEC_HELPER"), ClientOptions: acp.Options{RequestHandler: func(ctx context.Context, req acp.IncomingRequest) (any, *acp.RPCError) {
		if req.Method == "session/request_permission" {
			var p acp.RequestPermissionRequest
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, &acp.RPCError{Code: -32602, Message: err.Error()}
			}
			for _, o := range p.Options {
				if o.Kind == "allow_once" {
					return acp.RequestPermissionResponse{Outcome: acp.SelectedPermissionOutcome(o.OptionID)}, nil
				}
			}
		}
		return nil, &acp.RPCError{Code: -32601, Message: "unsupported client request"}
	}}}
	if err = e.Prepare(ctx, &cfg); err != nil {
		t.Fatal(err)
	}
	process, err := acp.StartProcess(cfg)
	if process != nil {
		defer func() {
			status, err := process.Stop(context.Background(), time.Second)
			t.Logf("cleanup: %+v %v", status, err)
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Log("activation verified before release")
	if err = process.Release(); err != nil {
		t.Fatal(err)
	}
	_, err = process.Client().Initialize(ctx, acp.InitializeRequest{ProtocolVersion: 1, ClientInfo: &acp.Implementation{Name: "network-test", Version: "1"}})
	if err != nil {
		t.Fatalf("native init: %v; stderr=%s", err, process.Diagnostics())
	}
	t.Log("real pinned Codex ACP initialization succeeded")
	if err = process.Client().Authenticate(ctx, "api-key"); err != nil {
		t.Fatal(err)
	}
	session, err := process.Client().NewSession(ctx, acp.NewSessionRequest{CWD: paths.Workspace, MCPServers: []acp.MCPServer{}})
	if err != nil {
		t.Fatalf("native session: %v; %s", err, process.Diagnostics())
	}
	if err = process.Client().Call(ctx, "session/set_mode", map[string]any{"sessionId": session.SessionID, "modeId": "orka-external"}, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	answer, err := process.Client().Prompt(ctx, acp.PromptRequest{SessionID: session.SessionID, Prompt: []acp.ContentBlock{acp.Text("Run the network probes, then say NETWORK_NATIVE_OK")}})
	if err != nil {
		t.Fatalf("native prompt: %v; %s", err, process.Diagnostics())
	}
	if requests == 0 || answer.StopReason != acp.StopReasonEndTurn {
		t.Fatalf("no actual inference completion: %+v requests=%d", answer, requests)
	}
	t.Log("real pinned Codex completed local inference")
	probe, err := os.ReadFile(filepath.Join(paths.Workspace, "network-probes.json"))
	if err != nil {
		t.Fatalf("native probe entrypoint missing: %v; diagnostics=%s", err, process.Diagnostics())
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
}
