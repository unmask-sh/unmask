package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/notice"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// noticeHandler: an installed handler with a notification store holding an
// hour of two bans, a burst and a cleared over-block.
func noticeHandler(t *testing.T) *Handler {
	t.Helper()
	h := installedHandler(t)
	st := *h.cfg()
	st.Server.BasePath = "/unmask"
	st.NoticeRetentionDays = 90
	h.SetSettings(st)
	h.Notices = notice.New(h.DB)
	now := time.Now().Unix()
	hour := now/3600*3600 + 10
	h.Notices.Add(notice.KindBan, map[string]any{"event": notice.KindBan, "ip": "203.0.113.7", "ja4": "t13d", "source": "honeypot", "reason": "hit /wp-login.php", "banned_by": "", "site": "blog", "ts": hour})
	h.Notices.Add(notice.KindBan, map[string]any{"event": notice.KindBan, "ip": "203.0.113.8", "source": "manual", "reason": "scraper", "banned_by": "alice", "site": "blog", "ts": hour + 1})
	h.Notices.Add(notice.KindBurst, map[string]any{"event": notice.KindBurst, "count_per_5m": int64(600), "threshold": int64(600), "baseline_per_5m": int64(60), "site": "blog", "ts": hour + 2})
	h.Notices.Add(notice.KindOverBlock, map[string]any{"event": notice.KindOverBlock, "tripped": false, "window_minutes": 10, "stuck": 1, "ran_challenge": 40, "stuck_percent": 2, "min_stuck": 3, "min_percent": 50, "site": "", "ts": hour + 3})
	return h
}

func asUser(r *http.Request, id int64, role string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, &SessionPayload{UserID: id, Role: role}))
}

// TestNoticeBellOnEveryPage: every signed-in page carries the bell for an
// administrator, with the count of what the account has not read; a viewer
// has no bell.  Opening the panel lists the rows in the reader's language,
// marks them read, and the bell then shows no count.
func TestNoticeBellOnEveryPage(t *testing.T) {
	h := noticeHandler(t)
	for path, fn := range pagesWithTheHeader(h) {
		body := renderAs(t, fn, path, user.RoleAdmin, "en")
		if !strings.Contains(body, `id="nbell"`) || !strings.Contains(body, `id="nbell-badge">3<`) {
			t.Errorf("%s: the bell with 3 unread is missing", path)
		}
		if strings.Contains(renderAs(t, fn, path, user.RoleViewer, "en"), `id="nbell"`) {
			t.Errorf("%s: a viewer has a bell", path)
		}
	}

	req := asRole(httptest.NewRequest(http.MethodPost, "/unmask/admin/notices/panel", nil), user.RoleAdmin)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "ja"})
	rr := httptest.NewRecorder()
	h.AdminNoticesPanel(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("panel: %d %s", rr.Code, rr.Body.String())
	}
	panel := rr.Body.String()
	for _, want := range []string{
		`class="nbell-item sev-info unread"`,
		"challenge を通れるようになりました", // the over-block clearing, in Japanese
		"5 分間に challenge 600 回", "直前 1 時間は 5 分あたり平均 60 回でした。",
		"BAN 2 件", "honeypot 1 / manual 1 · 最新 203.0.113.8 (scraper)",
		`data-ts="`, " · BAN · blog",
	} {
		if !strings.Contains(panel, want) {
			t.Errorf("panel lacks %q:\n%s", want, panel)
		}
	}
	if strings.Count(panel, `class="nbell-item`) != 3 {
		t.Errorf("panel rows: %d, want 3", strings.Count(panel, `class="nbell-item`))
	}
	if n, _ := h.Notices.Unread(context.Background(), 1); n != 0 {
		t.Errorf("unread after the panel: %d", n)
	}
	after := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleAdmin, "en")
	if !strings.Contains(after, `id="nbell"`) || strings.Contains(after, `id="nbell-badge"`) {
		t.Error("after opening the panel the bell still shows a count, or is gone")
	}
	// A new alert: unread again, for this account.
	h.Notices.Add(notice.KindAdvisor, map[string]any{"event": notice.KindAdvisor, "new_candidates": 2, "total_candidates": 5})
	again := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleAdmin, "en")
	if !strings.Contains(again, `id="nbell-badge">1<`) {
		t.Error("a new alert did not light the bell")
	}
}

// TestNoticesPage: the page lists everything the account may see, newest
// first, narrows by kind, says what is new and what is for this account
// alone, and opening it reads the list.
func TestNoticesPage(t *testing.T) {
	h := noticeHandler(t)
	me, other := int64(1), int64(2)
	if err := h.Notices.Put(context.Background(), notice.Entry{Kind: notice.KindOverBlock, Severity: notice.SeverityCrit, UserID: &me, Detail: map[string]any{"tripped": true, "window_minutes": 10, "stuck": 5, "ran_challenge": 6, "stuck_percent": 83, "auto_passthrough": true}}); err != nil {
		t.Fatal(err)
	}
	if err := h.Notices.Put(context.Background(), notice.Entry{Kind: notice.KindBurst, UserID: &other, Detail: map[string]any{"count_per_5m": 999, "threshold": 1}}); err != nil {
		t.Fatal(err)
	}

	page := renderAs(t, h.AdminNoticesIndex, "/unmask/admin/notices/", user.RoleAdmin, "en")
	for _, want := range []string{
		"<h1>Notifications</h1>", "Kept for 90 days (Settings → Log management).",
		"Visitors may be stuck at the challenge", "To you", ">New<",
		"2 bans", "honeypot 1 / manual 1 · latest 203.0.113.8 (scraper)",
		"600 challenges in 5 minutes", "The hour before averaged 60 per 5 minutes.",
		`href="/unmask/admin/hunt/?range=1h"`, `href="/unmask/admin/bans/"`,
		`href="/unmask/admin/notices/?kind=over_block"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(page, "999 challenges") {
		t.Error("another account's row is on the page")
	}
	if strings.Count(page, "<tr data-id=") != 4 {
		t.Errorf("rows: %d, want 4", strings.Count(page, "<tr data-id="))
	}
	if n, _ := h.Notices.Unread(context.Background(), me); n != 0 {
		t.Errorf("unread after the page: %d", n)
	}
	if n, _ := h.Notices.Unread(context.Background(), other); n != 4 {
		t.Errorf("the other account's unread moved: %d, want 4", n)
	}

	only := renderAs(t, h.AdminNoticesIndex, "/unmask/admin/notices/?kind=challenge_burst", user.RoleAdmin, "ja")
	if strings.Count(only, "<tr data-id=") != 1 || !strings.Contains(only, "5 分間に challenge 600 回") || strings.Contains(only, ">新着<") {
		t.Errorf("the kind filter, read: %d rows", strings.Count(only, "<tr data-id="))
	}
	if !strings.Contains(only, `class="active">challenge の急増</a>`) {
		t.Error("the active filter is not marked")
	}

	// The other account sees its own row and the shared ones, not mine.
	req := asUser(httptest.NewRequest(http.MethodGet, "/unmask/admin/notices/", nil), other, user.RoleAdmin)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminNoticesIndex(rr, req)
	theirs := rr.Body.String()
	if !strings.Contains(theirs, "999 challenges") || strings.Contains(theirs, "Visitors may be stuck") {
		t.Error("the other account's page shows the wrong personal rows")
	}

	// A viewer is refused.
	rr = httptest.NewRecorder()
	h.RequireRole(user.RoleAdmin, h.AdminNoticesIndex)(rr, asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/notices/", nil), user.RoleViewer))
	if rr.Code != http.StatusForbidden {
		t.Errorf("viewer: %d", rr.Code)
	}
}

// TestNoticesWithoutAStore: a handler with no store (no database) renders
// its pages without a bell and answers the list with an error, not a panic.
func TestNoticesWithoutAStore(t *testing.T) {
	h := installedHandler(t)
	body := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleAdmin, "en")
	if strings.Contains(body, `id="nbell-badge"`) || !strings.Contains(body, `id="nbell"`) {
		t.Error("without a store the bell shows a count, or is gone")
	}
	rr := httptest.NewRecorder()
	h.AdminNoticesIndex(rr, asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/notices/", nil), user.RoleAdmin))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("no store: %d", rr.Code)
	}
}

// TestNoticeTextBurstBeforeTheHour: a burst row from before bursts were
// measured against the hour before has only the threshold it passed, and
// says that rather than an average of nothing.
func TestNoticeTextBurstBeforeTheHour(t *testing.T) {
	e := notice.Entry{Kind: notice.KindBurst, Detail: map[string]any{"count_per_5m": int64(50), "threshold": int64(50)}}
	if title, body, _ := noticeText(e, "ja", "/unmask"); title != "5 分間に challenge 50 回" || body != "しきい値 (50 回) を超えました。" {
		t.Errorf("title %q, body %q", title, body)
	}
}
