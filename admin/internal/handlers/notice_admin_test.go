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
		`data-ts="`, ` · BAN · <span class="nbell-site">blog</span>`, // the site, in the span the ghost colouring hangs on
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
	// Every row stood above the read mark, so each carries the "new" tag of
	// an unread row; opened again, the same rows sit back as read.
	if n := strings.Count(panel, `nbell-tag-new`); n != 3 {
		t.Errorf("new tags on the first opening: %d, want 3", n)
	}
	rr = httptest.NewRecorder()
	h.AdminNoticesPanel(rr, asRole(httptest.NewRequest(http.MethodPost, "/unmask/admin/notices/panel", nil), user.RoleAdmin))
	if reopened := rr.Body.String(); strings.Contains(reopened, ` unread"`) || strings.Contains(reopened, `nbell-tag-new`) {
		t.Error("opened again, the rows still read as unread")
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

// TestNoticeTextLetFault: a row of requests let through on no ground says how
// many, names the busiest sites and counts the rest, and links to that
// ground in the list of what was let through -- in the day's window while
// the row's hour is inside it, in the week's after.
func TestNoticeTextLetFault(t *testing.T) {
	hour := time.Now().Unix()/3600*3600 - 2*3600
	e := notice.Entry{Kind: notice.KindLetFault, Events: 12, Detail: map[string]any{
		"hour":  float64(hour),
		"sites": map[string]any{"a.example": float64(7), "b.example": float64(3), "c.example": float64(1), "d.example": float64(1)},
		"more":  float64(0),
	}}
	title, body, href := noticeText(e, "en", "/unmask")
	if title != "Requests are getting through on no ground unmask can name (12 this hour)" {
		t.Errorf("title %q", title)
	}
	if !strings.HasPrefix(body, "a.example 7 / b.example 3 / c.example 1 / 1 elsewhere · Judged a challenge") ||
		!strings.Contains(body, `under "No ground found" in BAN > Let through.`) {
		t.Errorf("body %q", body)
	}
	if href != "/unmask/admin/let-through/?window=24#let-none" {
		t.Errorf("href %q", href)
	}
	title, body, _ = noticeText(e, "ja", "/unmask")
	if title != "理由不明で通ったリクエストがあります (この 1 時間で 12 件)" || !strings.HasPrefix(body, "a.example 7 / b.example 3 / c.example 1 / ほか 1 件 · ") {
		t.Errorf("ja: title %q, body %q", title, body)
	}

	// The sites the row could not name are counted with the ones the line
	// does not.
	e.Detail["more"] = float64(30)
	if _, body, _ = noticeText(e, "en", "/unmask"); !strings.HasPrefix(body, "a.example 7 / b.example 3 / c.example 1 / 31 elsewhere · ") {
		t.Errorf("with unnamed sites: body %q", body)
	}

	// A row older than the day's window links to the week's.
	e.Detail["hour"] = float64(hour - 3*86400)
	if _, _, href = noticeText(e, "en", "/unmask"); href != "/unmask/admin/let-through/?window=168#let-none" {
		t.Errorf("an old row's href %q", href)
	}
	// The day's window reads whole hours, back to the one a day before now
	// began in: that hour's row is still in it, the hour before is not.
	now := time.Date(2026, 11, 25, 12, 30, 0, 0, time.UTC).Unix()
	for _, c := range []struct {
		ago  int64 // hours before the current one
		want string
	}{{0, "24"}, {1, "24"}, {24, "24"}, {25, "168"}, {167, "168"}} {
		if got := letFaultWindow(now/3600*3600-c.ago*3600, now); got != c.want {
			t.Errorf("a row of %d hours ago links to the window %s, want %s", c.ago, got, c.want)
		}
	}
	if got := letFaultWindow(0, now); got != "24" {
		t.Errorf("a row with no hour links to the window %s, want 24", got)
	}

	// A row with no site to name still says what it is.
	bare := notice.Entry{Kind: notice.KindLetFault, Events: 1, Detail: map[string]any{}}
	if _, body, href = noticeText(bare, "en", "/unmask"); !strings.HasPrefix(body, "Judged a challenge") || href != "/unmask/admin/let-through/?window=24#let-none" {
		t.Errorf("bare row: body %q, href %q", body, href)
	}
}

// TestNoticesPageListsALetFault: what the access log's flush reports reaches
// the page as a warning of its own kind, folded by hour, with the kind in the
// filter and a link to the ground.
func TestNoticesPageListsALetFault(t *testing.T) {
	h := noticeHandler(t)
	now := time.Now().Unix()
	hour := now / 3600 * 3600
	for _, n := range []int64{4, 2} {
		h.Notices.Add(notice.KindLetFault, map[string]any{
			"event": notice.KindLetFault, "count": n, "hour": hour, "more": int64(0),
			"sites": map[string]any{"shop.example": n}, "site": "blog", "ts": now, "severity": notice.SeverityWarn,
		})
	}
	page := renderAs(t, h.AdminNoticesIndex, "/unmask/admin/notices/?kind=let_through_fault", user.RoleAdmin, "en")
	if n := strings.Count(page, "<tr data-id="); n != 1 {
		t.Fatalf("%d rows for one hour's two flushes, want 1", n)
	}
	for _, want := range []string{
		"Requests are getting through on no ground unmask can name (6 this hour)",
		"shop.example 6 · Judged a challenge",
		`href="/unmask/admin/let-through/?window=24#let-none"`,
		`class="active">Passed on no ground</a>`,
		`class="sev sev-warn"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	ja := renderAs(t, h.AdminNoticesIndex, "/unmask/admin/notices/?kind=let_through_fault", user.RoleAdmin, "ja")
	if !strings.Contains(ja, `class="active">理由不明の通過</a>`) || !strings.Contains(ja, "理由不明で通ったリクエストがあります (この 1 時間で 6 件)") {
		t.Error("the page in Japanese lacks the kind or the title")
	}
}
