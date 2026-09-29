package events

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The ⇄ popover's history is server truth: each event's own connection JA4
// and the verdict recorded at the time.  These pin the window, the ordering,
// the bt isolation, and the cap.
func TestJA4Chain(t *testing.T) {
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "c.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ins := func(at time.Time, phase, ja4, verdict, bt string) {
		t.Helper()
		if _, err := conn.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('s','h','https',443,x'7f000001','ua',?,?,0,?,0,0,'','',?,?)`,
			ja4, verdict, phase, `{"bt":"`+bt+`"}`, at.Format("2006-01-02 15:04:05.000")); err != nil {
			t.Fatal(err)
		}
	}
	const bt = "dktun7afejnh.2j37j0fp4u34u.05fcfc94f54aa001"
	ins(now.Add(-3*time.Minute), "serve", "t13d1516h2_x_a", "bot_residential_herd", bt)
	ins(now.Add(-2*time.Minute), "load", "q13d0311h3_x_b", "", bt)
	ins(now.Add(-1*time.Minute), "abandon", "t13d1517h2_x_c", "", bt)
	ins(now.Add(-90*time.Second), "serve", "zzz", "", "othertoken.aaaa.bbbb") // other session
	ins(now.Add(-3*time.Hour), "serve", "old", "", bt)                        // outside the ±2h window

	rows, truncated, err := JA4Chain(context.Background(), conn, bt, now.Unix(), 60)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("5 rows must not report truncation at a 60 cap")
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want the session's 3 (window + bt isolation)", len(rows))
	}
	if rows[0].Phase != "serve" || rows[0].JA4 != "t13d1516h2_x_a" || rows[0].Verdict != "bot_residential_herd" {
		t.Errorf("first row = %+v, want the serve with its recorded verdict", rows[0])
	}
	if rows[2].JA4 != "t13d1517h2_x_c" {
		t.Errorf("order broken: last = %+v", rows[2])
	}

	// Cap: ask for 2, expect truncation.
	rows, truncated, err = JA4Chain(context.Background(), conn, bt, now.Unix(), 2)
	if err != nil || len(rows) != 2 || !truncated {
		t.Errorf("cap: rows=%d truncated=%v err=%v, want 2/true/nil", len(rows), truncated, err)
	}
}

// Where the visitor came from is recorded on the serve and nowhere else, so a
// hunt view filtered to the passes cannot show it -- this read is how it gets
// there.  The value has to come back as the URL the browser sent: the writer
// stores "&" as \u0026, and handing that to the operator would turn a search
// URL into something that is not a URL.
func TestJA4ChainCarriesReferer(t *testing.T) {
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "r.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	const bt = "dlredzas37ho.2m96go7sr073g.01edbd1db622214b"
	const from = "https://www.example.com/search?q=unmask&hl=ja"
	now := time.Now().UTC()
	ins := func(at time.Time, phase string, payload map[string]any) {
		t.Helper()
		// Through json.Marshal, the way the writer serializes a payload, so the
		// stored text carries the same escapes a recorded row does.
		buf, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('s','h','https',443,x'7f000001','ua','t13x','',0,?,0,0,'','',?,?)`,
			phase, string(buf), at.Format("2006-01-02 15:04:05.000")); err != nil {
			t.Fatal(err)
		}
	}
	ins(now.Add(-3*time.Minute), "serve", map[string]any{"bt": bt, "referer": from, "ch_mode": "pow_only"})
	ins(now.Add(-2*time.Minute), "load", map[string]any{"bt": bt})
	ins(now.Add(-1*time.Minute), "bv_pow_only", map[string]any{"bt": bt})

	// Asked for the way the hunt page asks: with the pass row's own time.
	rows, _, err := JA4Chain(context.Background(), conn, bt, now.Add(-1*time.Minute).Unix(), 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].Phase != "serve" || rows[0].Referer != from {
		t.Errorf("serve row = %+v, want referer %q as the browser sent it", rows[0], from)
	}
	for _, r := range rows[1:] {
		if r.Referer != "" {
			t.Errorf("%s carries referer %q; only the challenged request records one", r.Phase, r.Referer)
		}
	}
}

// A payload the decoder cannot read must cost the row its referer, not the
// chain: the phases and fingerprints are columns and are still true.
func TestChainRefererToleratesBadPayload(t *testing.T) {
	for _, payload := range []string{"", "{", `{"_truncated":true}`, `{"referer":42}`, `[1,2]`} {
		if got := chainReferer(payload); got != "" {
			t.Errorf("chainReferer(%q) = %q, want empty", payload, got)
		}
	}
	if got := chainReferer(`{"bt":"x","referer":"https://example.com/"}`); got != "https://example.com/" {
		t.Errorf("chainReferer = %q", got)
	}
}
