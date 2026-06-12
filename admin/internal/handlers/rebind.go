// Silent roaming rebind: re-bind a solved client's _bv to its new IP without a
// challenge.
//
// _bv entries are IP-bound (replay defense), so a mobile client whose address
// changes at every cell handoff re-challenges once per network -- the multi-IP
// "~"-list absorbs a stable wifi/office/home set but not a 5G address churn.
// The _bvj companion cookie (package cookies) carries a host-bound, signed
// proof of the original solve plus the solve-time JA4/UA fingerprints and ASN;
// when its holder lands on the challenge route from a new IP, tryRebind
// re-issues a fresh _bv entry and bounces straight back, gated by:
//
//   - _bvj signature + solve window (host-bound)
//   - JA4 + UA fingerprint match (same client stack that solved)
//   - ASN veto when an ASN db is loaded (same carrier/network as the solve;
//     kills datacenter replay of a residential solve)
//   - a per-lineage cap in the DB (lifetime + hourly, atomic; the only bound
//     left when no ASN db is present)
//
// Anubis dropped IP binding entirely after it broke roaming clients (their PR
// #365), trading replay resistance for UX.  This keeps the binding and narrows
// the re-challenge to genuinely new clients instead.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// rebindWindowSeconds: the _bvj validity window for site -- the larger of the
// two _bv solve windows, so a _bvj lives exactly as long as the longest-lived
// solve it could vouch for.
func (h *Handler) rebindWindowSeconds(site string) int {
	ch := h.cfg().Challenge.Resolve(site)
	p, c := ch.PowCookieValidSecondsResolved(), ch.CaptchaCookieValidSecondsResolved()
	if p > c {
		return p
	}
	return c
}

// validBVJ returns the claims of the first _bvj cookie on r that verifies for
// host; ok=false when none do.  Iterates duplicates the same way pickValidBV
// does for _bv (a stale cookie at another path/domain can shadow the fresh one).
func (h *Handler) validBVJ(r *http.Request, host, site string) (cookies.JClaims, bool) {
	window := h.rebindWindowSeconds(site)
	for _, c := range r.Cookies() {
		if c.Name != "_bvj" || c.Value == "" || len(c.Value) > 160 {
			continue
		}
		if cl, ok := cookies.ParseJValue(c.Value, h.cfg().Secret.BVSecret, host, window); ok {
			return cl, true
		}
	}
	return cookies.JClaims{}, false
}

// mintBVJ issues a fresh-lineage _bvj for the solving client and sets it on w.
// Solve paths only (VerifyJSON, and IssueBVJ for the JS PoW path): a fresh
// lineage is a fresh rebind budget, so it must always be paid for by a real
// solve.
func (h *Handler) mintBVJ(w http.ResponseWriter, r *http.Request, ip, host string) {
	lineage, err := cookies.NewLineage()
	if err != nil {
		return // no entropy; the solve itself already passed, just skip the rebind credential
	}
	var asn uint
	if h.IPGeo != nil {
		asn = h.IPGeo.LookupInfo(ip).ASN
	}
	ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
	val := cookies.IssueJValue(h.cfg().Secret.BVSecret,
		cookies.FingerprintHash(ja4),
		cookies.FingerprintHash(r.Header.Get("User-Agent")),
		lineage, asn, host, "captcha")
	http.SetCookie(w, &http.Cookie{
		Name:   "_bvj",
		Value:  val,
		Path:   "/",
		MaxAge: h.cfg().Challenge.Default.CookieMaxAgeSeconds(),
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		// Unlike _bv (which challenge.js must read/write), no JS ever touches
		// _bvj -- keep it out of XSS reach.
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// IssueBVJ: POST {base}/api/bvj
//
// Companion endpoint for the JS PoW path, which mints its _bv client-side and
// never passes through VerifyJSON: after setting _bv, challenge.js calls here
// once so the solve also yields a _bvj.  Gated on a _bv that verifies for the
// CURRENT ip+host (only a client that is passed right now can obtain one) and
// on that entry being a real solve: a kind="rebind" entry must not seed a
// fresh lineage, or every rebound hop would refill its own budget and the cap
// would never accumulate.
func (h *Handler) IssueBVJ(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg()
	if !cfg.Rebind.RebindEnabled() {
		writeJSON(w, http.StatusOK, map[string]any{"ok": 0, "skip": "disabled"})
		return
	}
	ip := clientIP(r)
	host := requestHost(r)
	site := siteFromRequest(r, *cfg)
	ch := cfg.Challenge.Resolve(site)
	kind, ok := "", false
	for _, c := range r.Cookies() {
		if c.Name != "_bv" || c.Value == "" || len(c.Value) > 512 {
			continue
		}
		if k, m := cookies.MatchingEntryKind(c.Value, cfg.Secret.BVSecret, ip, host,
			ch.PowCookieValidSecondsResolved(),
			ch.CaptchaCookieValidSecondsResolved(),
			ch.ResolvedPowDifficulty()); m {
			kind, ok = k, true
			break
		}
	}
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": 0, "error": "no_valid_bv"})
		return
	}
	if kind == "rebind" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": 0, "skip": "rebound_entry"})
		return
	}
	if _, has := h.validBVJ(r, host, site); has {
		// Re-POSTing with a still-valid _bvj is a no-op, so the endpoint can't
		// be looped to farm fresh lineages off one solve.
		writeJSON(w, http.StatusOK, map[string]any{"ok": 0, "skip": "present"})
		return
	}
	h.mintBVJ(w, r, ip, host)
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
}

// tryRebind: attempt the silent rebind on the challenge route.  Returns true
// when it handled the response (cookie + bounce page written).  The caller
// must skip it for every forced path (ja4_bot / honeypot / banned / protected
// / rate-limit / test): those are deliberate challenges, not roaming.
func (h *Handler) tryRebind(w http.ResponseWriter, r *http.Request, site string) bool {
	cfg := h.cfg()
	if !cfg.Rebind.RebindEnabled() {
		return false
	}
	ip := clientIP(r)
	host := requestHost(r)
	if ip == "" {
		return false
	}
	claims, ok := h.validBVJ(r, host, site)
	if !ok {
		return false
	}
	ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
	if ja4 == "" && !cfg.Rebind.AllowNoJA4 {
		// No JA4 reaches this deployment (pure forward-auth without the
		// X-Client-JA4 wiring): the fingerprint gate would degenerate to
		// empty==empty, so refuse unless the operator opted in.
		return false
	}
	if cookies.FingerprintHash(ja4) != claims.JA4Hash {
		return false
	}
	if cookies.FingerprintHash(r.Header.Get("User-Agent")) != claims.UAHash {
		return false
	}
	asnVeto := cfg.Rebind.ASNVetoResolved() == "auto" && h.IPGeo != nil && h.IPGeo.ASNLoaded()
	var curASN uint
	if asnVeto {
		curASN = h.IPGeo.LookupInfo(ip).ASN
		// An unmappable side (private range, db gap, pre-ASN-db solve) fails
		// closed: "unknown" must not read as "same network".
		if curASN == 0 || claims.ASN == 0 || curASN != claims.ASN {
			return false
		}
	}
	allowed, err := db.RebindAllow(r.Context(), h.DB, claims.Lineage, host,
		cfg.Rebind.MaxRebindsResolved(), cfg.Rebind.MaxRebindsPerHourResolved(), time.Now().Unix())
	if err != nil || !allowed {
		return false
	}

	// Mint the new per-IP entry as kind "rebind", NOT "captcha".  Both verify
	// identically everywhere (the kind segment is free-form and HMAC-bound;
	// the C plugin recomputes it verbatim), but IssueBVJ refuses to seed a
	// fresh lineage off a rebound entry.
	h.setBVCookie(w, r, cookies.IssueValue(cfg.Secret.BVSecret, ip, host, "rebind"))

	origPath := truncateAt(r.URL.Query().Get("_orig"), 200)
	if !isLocalRedirect(origPath) {
		origPath = "" // client-supplied; never bounce off-site
	}

	if pkt := events.PackIP(ip); pkt != nil {
		verdict := strings.TrimSpace(r.Header.Get("X-JA4-Verdict"))
		events.InsertAsync(h.DB, &events.Event{
			Site:         site,
			Host:         h.HostID,
			Scheme:       schemeFromRequest(r),
			Port:         portFromRequest(r),
			IPPacked:     pkt,
			UserAgent:    r.Header.Get("User-Agent"),
			JA4:          ja4,
			JA4Verdict:   verdict,
			JA4VerdictID: h.VerdictNameToID(verdict),
			Phase:        string(events.PhaseBVRebind),
			CookieBV:     readCookieMax(r, "_bv", 320),
			Payload: map[string]any{
				"lineage":   claims.Lineage,
				"solve_asn": claims.ASN,
				"cur_asn":   curASN,
				"asn_veto":  asnVeto,
				"orig_path": origPath,
			},
		})
	}

	h.serveRebindRedirect(w, origPath)
	return true
}

// serveRebindRedirect bounces the just-rebound client back to its original
// page.  Forward-auth arrivals carry ?_orig= (the browser sits on the
// challenge URL); native arrivals carry nothing (the plugin rewrote the
// request internally, the browser still shows the original URL), so the script
// falls back to re-requesting the browser's own location -- and to "/" when
// the browser really is parked on a challenge/test URL (direct access), which
// would otherwise re-enter this handler in a loop.  Mirrors challenge.js
// passAndRedirect; same two-tier meta-refresh + location.replace shape as the
// observe-only bounce.
func (h *Handler) serveRebindRedirect(w http.ResponseWriter, origPath string) {
	base := h.basePath()
	origJSON, _ := json.Marshal(origPath)
	baseJSON, _ := json.Marshal(base)
	meta := `<meta http-equiv="refresh" content="0">` // no orig: reload in place (native rewrite)
	if origPath != "" {
		meta = `<meta http-equiv="refresh" content="0; url=` + htmlEscape(origPath) + `">`
	}
	body := []byte(`<!doctype html><meta charset=utf-8>` +
		`<title>unmask: rebind</title>` + meta +
		`<script>(function(){var o=` + string(origJSON) + `,b=` + string(baseJSON) + `,t;` +
		`if(o){t=o}` +
		`else if(location.pathname.indexOf(b+"/challenge")===0||` +
		`location.pathname.indexOf(b+"/test/")===0||` +
		`location.pathname.indexOf(b+"/admin/test/")===0){t="/"}` +
		`else{t=location.pathname+location.search}` +
		`try{location.replace(t)}catch(e){}})()</script>` +
		`<noscript>redirecting...</noscript>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("X-Unmask-Mode", "rebind")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
