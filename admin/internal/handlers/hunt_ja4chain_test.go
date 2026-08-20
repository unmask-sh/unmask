package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The ⇄ badge's click detail: the session's recorded JA4/verdict history.
func TestHuntJA4Chain(t *testing.T) {
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "h.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	const bt = "dktun7afejnh.2j37j0fp4u34u.05fcfc94f54aa001"
	if _, err := conn.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
		 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('s','h','https',443,x'7f000001','ua','t13x','herd',0,'serve',0,0,'','','{"bt":"` + bt + `"}',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: conn, UserRepo: &user.Repository{DB: conn}}
	h.SetSettings(settings.Settings{})

	get := func(q string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/ja4chain"+q, nil)
		w := httptest.NewRecorder()
		h.AdminHuntJA4Chain(w, r)
		return w
	}

	// The bt alphabet doubles as the LIKE-safety guarantee: reject anything else.
	for _, bad := range []string{"", "short", "has%wild.card1", "UPPER.case.token", strings.Repeat("a", 70)} {
		if w := get("?bt=" + bad); w.Code != http.StatusBadRequest {
			t.Errorf("bt=%q accepted with %d, want 400", bad, w.Code)
		}
	}

	w := get("?bt=" + bt)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Rows []struct {
			P string `json:"p"`
			J string `json:"j"`
			V string `json:"v"`
			T int64  `json:"t"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Rows) != 1 || body.Rows[0].J != "t13x" || body.Rows[0].V != "herd" || body.Rows[0].T == 0 {
		t.Errorf("rows = %+v, want the recorded serve with its verdict and timestamp", body.Rows)
	}
}

// The partial has to actually wire the fetch, or the endpoint is dead code and
// the badge silently degrades to the static note.
func TestJA4ChainPopoverWiring(t *testing.T) {
	raw, err := assets.Templates.ReadFile("templates/partial_events_table.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(raw)
	for _, want := range []string{
		`/admin/hunt/ja4chain?bt=`,
		`table.events [data-info]`, // the hover handler that also revives the ⚠ badge
		`hunt.ja4chain_title`,
	} {
		if !strings.Contains(tpl, want) {
			t.Errorf("partial lost %q", want)
		}
	}
}
