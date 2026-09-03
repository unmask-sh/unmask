package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// mcpRoundTrip feeds newline-delimited JSON-RPC requests to a server with no
// DB behind it (protocol-level tests never touch storage) and returns the
// decoded responses in order.
func mcpRoundTrip(t *testing.T, lines ...string) []rpcResponse {
	t.Helper()
	srv := &mcpServer{logw: &bytes.Buffer{}}
	var out bytes.Buffer
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	if err := srv.serve(in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var resps []rpcResponse
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r rpcResponse
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		resps = append(resps, r)
	}
	return resps
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	resps := mcpRoundTrip(t,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
	)
	// The notification must not produce a response: 3 replies for 4 lines.
	if len(resps) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(resps))
	}
	init, ok := resps[0].Result.(map[string]any)
	if !ok {
		t.Fatalf("initialize result is %T", resps[0].Result)
	}
	if init["protocolVersion"] != mcpProtocolVersion {
		t.Errorf("protocolVersion = %v", init["protocolVersion"])
	}
	si, _ := init["serverInfo"].(map[string]any)
	if si["name"] != "unmask" {
		t.Errorf("serverInfo.name = %v", si["name"])
	}

	list, _ := resps[1].Result.(map[string]any)
	tools, _ := list["tools"].([]any)
	if len(tools) != 6 {
		t.Fatalf("expected 6 tools, got %d", len(tools))
	}
	// Every tool must carry the three fields clients require.
	for _, raw := range tools {
		tool := raw.(map[string]any)
		for _, k := range []string{"name", "description", "inputSchema"} {
			if _, ok := tool[k]; !ok {
				t.Errorf("tool %v lacks %s", tool["name"], k)
			}
		}
	}
}

func TestMCPUnknownMethodAndTool(t *testing.T) {
	resps := mcpRoundTrip(t,
		`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}`,
	)
	if len(resps) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(resps))
	}
	if resps[0].Error == nil || resps[0].Error.Code != -32601 {
		t.Errorf("unknown method should be -32601, got %+v", resps[0].Error)
	}
	// An unknown TOOL is a tool-level error (isError result), not an RPC error.
	if resps[1].Error != nil {
		t.Fatalf("unknown tool must not be an RPC error: %+v", resps[1].Error)
	}
	res, _ := resps[1].Result.(map[string]any)
	if res["isError"] != true {
		t.Errorf("unknown tool should set isError, got %v", res)
	}
}

// TestMCPSettingsSummaryRedaction proves the summary is an allowlist: seed
// every secret-carrying field with a marker and require the marshalled output
// to be free of it.
func TestMCPSettingsSummaryRedaction(t *testing.T) {
	const marker = "SECRET-MARKER-3f9c"
	var s settings.Settings
	s.Secret.BVSecret = marker
	s.Secret.CaptchaSecretBase = marker
	s.DB.MariaDB.Password = marker
	s.SMTP.Password = marker
	s.CommunityBans.Token = marker
	s.DB.Driver = "sqlite"
	s.Nginx.BypassIPEnabledPresets = []string{"google-common"}

	body, err := json.Marshal(mcpSettingsSummary(s))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), marker) {
		t.Fatalf("settings summary leaked a secret: %s", body)
	}
	if !strings.Contains(string(body), `"driver":"sqlite"`) {
		t.Errorf("expected db driver in summary: %s", body)
	}
	if !strings.Contains(string(body), "google-common") {
		t.Errorf("expected preset names in summary: %s", body)
	}
}
