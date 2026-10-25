package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSavedBannersOnTheGateway: the gateway container reloads its nginx by
// itself, so the banners that otherwise hand the operator the reload command
// (settings saved, hunt rule added and its dialogs, the dashboard's upgrade
// review, the ask page's rule modal) say so instead; a native install keeps
// the command.
func TestSavedBannersOnTheGateway(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	pages := []struct {
		name, target, tab string
		serve             func(http.ResponseWriter, *http.Request)
		native, gateway   string
	}{
		{"settings", "/unmask/admin/settings/ai-advisor/?saved=1&reload=1", "ai-advisor", h.AdminSettingsIndex,
			`✓ 保存しました。<code class="cmd">`, "✓ 保存しました。コンテナ内の nginx が数秒以内に自分で reload して反映します。"},
		{"hunt", "/unmask/admin/hunt/?saved=1&reload=1", "", h.AdminHuntIndex,
			`✓ ルールを追加しました。<strong><code class="cmd">`, "✓ ルールを追加しました。コンテナ内の nginx が数秒以内に自分で reload して反映します。"},
		{"hunt dialog note", "/unmask/admin/hunt/", "", h.AdminHuntIndex,
			`まで反映されません</strong> (gateway コンテナは数秒で自動的に反映)`, "設定ファイルは書き換わり、コンテナ内の nginx が数秒以内に自分で reload して反映します。"},
		{"overview", "/unmask/admin/?upgrade_applied=1&reload=1", "", h.AdminTopOverview,
			`で反映してください (gateway コンテナは自動で反映)`, "コンテナ内の nginx が数秒以内に自分で reload して反映します。"},
		{"ask", "/unmask/admin/ask/", "", h.AdminAsk,
			`✓ ルールを追加しました。<strong><code class="cmd">`, "✓ ルールを追加しました。コンテナ内の nginx が数秒以内に自分で reload して反映します。"},
	}
	for _, gw := range []bool{false, true} {
		s := h.snapshotSettings()
		s.Gateway.Upstream = ""
		if gw {
			s.Gateway.Upstream = "http://127.0.0.1:8080"
		}
		h.SetSettings(s)
		for _, p := range pages {
			req := askReq("GET", p.target, "", "admin")
			if p.tab != "" {
				req.SetPathValue("tab", p.tab)
			}
			rec := httptest.NewRecorder()
			p.serve(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("gateway=%v %s: HTTP %d", gw, p.name, rec.Code)
			}
			body := rec.Body.String()
			if gw && (!strings.Contains(body, p.gateway) || strings.Contains(body, p.native)) {
				t.Errorf("gateway=%v %s: the banner must say the container reloads itself, with no command (twin=%v native=%v)", gw, p.name, strings.Contains(body, p.gateway), strings.Contains(body, p.native))
			}
			if !gw && (strings.Contains(body, p.gateway) || !strings.Contains(body, p.native)) {
				t.Errorf("gateway=%v %s: the banner must hand over the reload command (twin=%v native=%v)", gw, p.name, strings.Contains(body, p.gateway), strings.Contains(body, p.native))
			}
		}
	}
}
