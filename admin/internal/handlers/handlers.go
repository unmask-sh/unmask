// Package handlers: net/http handler 集.  app.go から ServeMux に bind される.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/captcha"
	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const (
	challengePlaceholder = "/*__JA4_HIT__*/0"
	challengeProbe       = "<!--__SUBFILTER_PROBE__-->"
	defaultSite          = "default"
)

type Handler struct {
	DB       *db.DB
	Settings settings.Settings
}

// site name の許容文字: lowercase alnum + dash, 1〜32 文字, 先頭/末尾 dash 不可.
var siteIDRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

// pickSite は r.PathValue("site") を読んで validate する. 空 / 不正 → "default".
// 不正値が来たら ok=false を返して呼び出し側で 400 を返せる.
func pickSite(r *http.Request) (site string, ok bool) {
	s := r.PathValue("site")
	if s == "" {
		return defaultSite, true
	}
	if !siteIDRE.MatchString(s) {
		return "", false
	}
	return s, true
}

// loadChallengeHTML returns the challenge.html bytes.  Order:
//
//   - settings.challenge.challenge_html_path (override for ops)
//   - /usr/share/unmask/challenge/challenge.html (RPM/deb)
//   - embedded assets/static/challenge.html (default)
//
// 互換のため bot-challenge.html (= 旧 file 名) も fallback で見る.
func (h *Handler) loadChallengeHTML() ([]byte, error) {
	if p := h.Settings.Challenge.ChallengeHTMLPath; p != "" {
		return os.ReadFile(p)
	}
	for _, p := range []string{
		"/usr/share/unmask/challenge/challenge.html",
		"/usr/share/unmask/challenge/bot-challenge.html",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b, nil
		}
	}
	if b, err := assets.Static.ReadFile(filepath.ToSlash("static/challenge.html")); err == nil {
		return b, nil
	}
	return assets.Static.ReadFile(filepath.ToSlash("static/bot-challenge.html"))
}

// ServeChallenge: GET {base}/challenge/ (legacy: {base}/challenge.html)
func (h *Handler) ServeChallenge(w http.ResponseWriter, r *http.Request) {
	site, ok := pickSite(r)
	if !ok {
		http.Error(w, "invalid site id", http.StatusBadRequest)
		return
	}
	verdict := strings.TrimSpace(r.Header.Get("X-JA4-Verdict"))
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	hit := "0"
	if strings.HasPrefix(verdict, "bot_") {
		hit = "1"
	}
	rl := "0"
	test := "0"
	if r.URL.Query().Get("_rl") == "1" {
		rl = "1"
		hit = "1"
	}
	if r.URL.Query().Get("_test_ja4") == "1" {
		test = "1"
		hit = "1"
	}

	body, err := h.loadChallengeHTML()
	if err != nil {
		log.Printf("challenge.html load failed: %v", err)
		http.Error(w, "challenge unavailable", http.StatusInternalServerError)
		return
	}
	body = bytes.ReplaceAll(body, []byte(challengePlaceholder),
		[]byte("/*__JA4_HIT__*/"+hit))
	body = bytes.ReplaceAll(body, []byte(challengeProbe),
		[]byte("<!--probe=ON ja4_hit_flag="+hit+"-->"))

	ip := clientIP(r)
	if pkt := events.PackIP(ip); pkt != nil {
		hitInt, _ := strconv.Atoi(hit)
		rlInt, _ := strconv.Atoi(rl)
		testInt, _ := strconv.Atoi(test)
		// 原 path (= rate-limit ヒット時の原 URL): nginx の internal rewrite では
		// $request_uri が原 URI のままなので proxy_set_header X-Original-URI で
		// 渡してもらう. 無ければ Referer を fallback.
		origURI := r.Header.Get("X-Original-URI")
		if origURI == "" {
			origURI = r.Header.Get("Referer")
		}
		// query string 除去 + ?_rl=1 のような unmask 内部 query を捨てる
		origPath := stripQuery(origURI)
		payload := map[string]any{
			"hit": hitInt, "rl": rlInt, "test": testInt,
		}
		if origPath != "" {
			payload["orig_path"] = origPath
		}
		_ = events.Insert(r.Context(), h.DB, &events.Event{
			Site:       site,
			IPPacked:   pkt,
			UserAgent:  r.Header.Get("User-Agent"),
			JA4:        safeJA4(ja4),
			JA4Verdict: verdict,
			Phase:      string(events.PhaseServe),
			Payload:    payload,
		})
	}

	// Cloudflare 互換: challenge は 403.
	// 5xx だとアップタイム監視に紐付くサイト健全性メトリクスに悪影響.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Retry-After", "600")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)
}

// VerifyJSON: POST {base}/api/verify
//
// 受信 payload:
//   - 新方式 (behavioral):  { token, sig: { mouseTrail, ... } }
//   - 旧方式 (math 加算):   { token, answer }
func (h *Handler) VerifyJSON(w http.ResponseWriter, r *http.Request) {
	site, ok := pickSite(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_site"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "read"})
		return
	}
	var payload struct {
		Token  string          `json:"token"`
		Answer json.RawMessage `json:"answer"`
		Sig    *captcha.Signal `json:"sig"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_json"})
		return
	}

	ip := clientIP(r)
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	// kind は cookie の HMAC 入力に site を埋め込む形にする (= cross-site replay 対策).
	// "default" の場合は従来通り "captcha" のみで back compat 維持.
	kind := "captcha"
	if site != defaultSite {
		kind = "captcha-" + site
	}

	if payload.Sig != nil {
		if payload.Token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "no_token"})
			return
		}
		score := captcha.Score(payload.Sig)
		Metrics.ObserveScore(score)
		if score >= h.Settings.Challenge.CaptchaScoreThreshold {
			val := cookies.IssueValue(h.Settings.Secret.BVSecret, ip, ja4, kind)
			h.setBVCookie(w, val)
			writeJSON(w, http.StatusOK, map[string]any{"ok": 1, "score": round3(score)})
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": 0, "error": "low_score", "score": round3(score),
		})
		return
	}

	// 旧方式: math 加算
	var ans string
	if len(payload.Answer) > 0 {
		// answer は string でも number でも JSON で来るので両対応
		var s string
		if err := json.Unmarshal(payload.Answer, &s); err != nil {
			var n json.Number
			if err2 := json.Unmarshal(payload.Answer, &n); err2 == nil {
				s = string(n)
			}
		}
		ans = strings.TrimSpace(s)
	}
	if ans == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid"})
		return
	}
	if captcha.VerifyMath(ans, payload.Token, h.Settings.Secret.CaptchaSecretBase) {
		val := cookies.IssueValue(h.Settings.Secret.BVSecret, ip, ja4, kind)
		h.setBVCookie(w, val)
		writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "wrong"})
}

// CaptchaNew: GET {base}/api/captcha/new
func (h *Handler) CaptchaNew(w http.ResponseWriter, r *http.Request) {
	a, b, token := captcha.MathChallenge(h.Settings.Secret.CaptchaSecretBase)
	writeJSON(w, http.StatusOK, map[string]any{"a": a, "b": b, "token": token})
}

// DebugBeacon: POST {base}/api/debug — challenge HTML 内 JS が phase ビーコン送信
func (h *Handler) DebugBeacon(w http.ResponseWriter, r *http.Request) {
	site, ok := pickSite(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_site"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0})
		return
	}
	var p struct {
		Phase       string `json:"phase"`
		Flags       int    `json:"flags"`
		ReloadCount int    `json:"reload_count"`
	}
	// raw も保持して payload に保存する.
	if err := json.Unmarshal(body, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_json"})
		return
	}
	if !events.IsValidPhase(p.Phase) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_phase"})
		return
	}

	ip := clientIP(r)
	pkt := events.PackIP(ip)
	if pkt == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_ip"})
		return
	}

	// per-IP rate limit (default 5min/20件).
	cnt, err := events.CountRecentByIP(r.Context(), h.DB, pkt, 5)
	if err == nil && cnt >= h.Settings.Challenge.DebugRateLimitPer5Min {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": 0, "error": "rate_limit"})
		return
	}

	cookieBV := readCookieMax(r, "_bv", 80)
	cookieBR := readCookieMax(r, "_br", 8)
	ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
	verdict := strings.TrimSpace(r.Header.Get("X-JA4-Verdict"))

	// payload も保存. raw JSON を map に decode (= 大量フィールドそのまま).
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)

	_ = events.Insert(r.Context(), h.DB, &events.Event{
		Site:        site,
		IPPacked:    pkt,
		UserAgent:   r.Header.Get("User-Agent"),
		JA4:         ja4,
		JA4Verdict:  verdict,
		Phase:       p.Phase,
		Flags:       p.Flags,
		ReloadCount: p.ReloadCount,
		CookieBV:    cookieBV,
		CookieBR:    cookieBR,
		Payload:     raw,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

// BVCheck: GET {base}/api/bv-check — auth_request 用 (= legacy).
//
//	204  _bv 有効 (= challenge skip OK)
//	403  cookie 無 or 改竄/期限切れ
//
// 推奨: ngx_http_ja4_module の $unmask_bv_valid 変数を使う inline 検証
// (= 0 RTT, 0 サブリクエスト). この endpoint は ja4 module を load できない
// 環境 (= 静的 build の標準 nginx 等) のための fallback として残す.
func (h *Handler) BVCheck(w http.ResponseWriter, r *http.Request) {
	bv := readCookieMax(r, "_bv", 80)
	ip := clientIP(r)
	ja4 := strings.TrimSpace(r.Header.Get("X-Client-JA4"))
	if cookies.Verify(bv, h.Settings.Secret.BVSecret, ip, ja4, h.Settings.Challenge.CookieDays) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusForbidden)
}

func (h *Handler) setBVCookie(w http.ResponseWriter, val string) {
	c := &http.Cookie{
		Name:     "_bv",
		Value:    val,
		Path:     "/",
		MaxAge:   86400 * h.Settings.Challenge.CookieDays,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

// --------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// 一番左 (= original client) を採用. ここまで来る経路は信頼前提.
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

func readCookieMax(r *http.Request, name string, maxlen int) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	v := c.Value
	if len(v) > maxlen {
		v = v[:maxlen]
	}
	return v
}

// stripQuery returns the path portion of a URL/URI (= drops `?...` and `#...`).
func stripQuery(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	// Referer の場合 protocol+host も含むので、 path だけに削る.
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		// 3 個目の "/" 以降が path
		idx := strings.IndexByte(s[8:], '/')
		if idx >= 0 {
			s = s[8+idx:]
		}
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

var safeJA4RE = regexp.MustCompile(`^[a-zA-Z0-9_]{8,40}$`)

// safeJA4 returns s if it looks like a valid JA4 fingerprint, else "".
func safeJA4(s string) string {
	if safeJA4RE.MatchString(s) {
		return s
	}
	return ""
}

func round3(x float64) float64 {
	return float64(int(x*1000+0.5)) / 1000
}

// MethodOnly wraps `h` so requests with a different method get 405.
func MethodOnly(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, fmt.Sprintf("method %s not allowed", r.Method), http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}
