package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// observeHandler builds a handler on a migrated DB with n observed judgements
// already recorded, so the landing page has something to count.
//
// The payload matches what AuthCheck actually writes in observe mode: the event
// is recorded BEFORE the monitor-mode override, so "action" holds the verdict
// unmask would have enforced and observe_only marks that it did not. Sampled
// from a live install rather than assumed -- an earlier version of this fixture
// wrote "action":"pass", which no monitor-mode install ever produces.
func observeHandler(t *testing.T, observe bool, judged int) *Handler {
	t.Helper()
	conn, err := db.Open(settings.DB{
		Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "o.sqlite"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < judged; i++ {
		if _, err := conn.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,x'7f000001','','','',0,'check',0,0,'','',
			 '{"action":"challenge","observe_only":1,"would_be_action":"challenge","would_be_reason":"ua:target:http-library"}',
			 datetime('now'))`); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handler{DB: conn, UserRepo: &user.Repository{DB: conn}}
	var s settings.Settings
	s.Secret.BVSecret = "test-secret"
	if observe {
		s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
	}
	h.SetSettings(s)
	return h
}

func renderOverview(t *testing.T, h *Handler) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
	r.AddCookie(issueSessionCookie(h.cfg().Secret.BVSecret, 1, "superadmin", false, false))
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("overview status %d", rr.Code)
	}
	return rr.Body.String()
}

// heroHasObserveClass reports whether the hero DIV carries the observe class.
// Scoped to the element: the stylesheet in the same document defines
// .hero-observe, so a substring search over the page matches either way.
func heroHasObserveClass(body string) bool {
	m := regexp.MustCompile(`<div class="hero([^"]*)"`).FindStringSubmatch(body)
	return m != nil && strings.Contains(m[1], "hero-observe")
}

// heroValue reads the big number out of the hero card.
func heroValue(body string) string {
	m := regexp.MustCompile(`(?s)<div class="value">(.*?)</div>`).FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(m[1], ""))
}

// TestObserveModeDoesNotClaimQuiet: in observe mode no challenge is ever fired,
// so "challenges fired minus challenges passed" is structurally zero -- and the
// card then announced "all quiet, no attacks" to an install being scanned
// continuously.  On the host where this surfaced, the headline read 0 while the
// judgement log held tens of thousands of bot verdicts.
func TestObserveModeDoesNotClaimQuiet(t *testing.T) {
	h := observeHandler(t, true, 12)
	body := renderOverview(t, h)

	if strings.Contains(body, "攻撃はゼロ") || strings.Contains(body, "no attacks") {
		t.Error("observe mode still tells the operator there are no attacks")
	}
	if got := heroValue(body); got != "12件" {
		t.Errorf("hero value = %q, want the 12 judgements it would have stopped", got)
	}
	// The card must say the stopping is switched off, or the number reads as
	// though unmask acted on it.
	if !strings.Contains(body, "監視モード") {
		t.Error("the card does not say observe mode is on")
	}
	if !heroHasObserveClass(body) {
		t.Error("the card keeps the defending-red styling while defence is off")
	}
}

// TestLiveModeKeepsTheOriginalHeadline: with observe mode off the card answers
// its original question, and an install with genuinely no blocks may still say
// so.
func TestLiveModeKeepsTheOriginalHeadline(t *testing.T) {
	h := observeHandler(t, false, 0)
	body := renderOverview(t, h)

	if strings.Contains(body, "監視モード") {
		t.Error("a live install is labelled observe mode")
	}
	if heroHasObserveClass(body) {
		t.Error("a live install got the observe styling")
	}
	if got := heroValue(body); got != "0件" {
		t.Errorf("hero value = %q, want 0 for an install with no blocks", got)
	}
}

// TestObserveCountIgnoresPassVerdicts: only judgements that would have stopped
// someone belong in the number.  Counting every observed request would report
// total traffic and overstate what going live would change.
func TestObserveCountIgnoresPassVerdicts(t *testing.T) {
	h := observeHandler(t, true, 3)
	// Three more observed requests that unmask would have let through anyway.
	for i := 0; i < 5; i++ {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,x'7f000001','','','',0,'check',0,0,'','',
			 '{"action":"pass","observe_only":1,"would_be_action":"pass"}', datetime('now'))`); err != nil {
			t.Fatal(err)
		}
	}
	if got := heroValue(renderOverview(t, h)); got != "3件" {
		t.Errorf("hero value = %q, want only the 3 that would have been stopped", got)
	}
}
