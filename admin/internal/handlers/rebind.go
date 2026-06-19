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

// maxBVJJA4Hashes caps how many fingerprint hashes one _bvj accumulates.  A
// device needs at most two for the h2/h3 transport pair; the small headroom
// covers a mid-life browser update, while the tight cap denies a stolen-cookie
// attacker an open-ended set of TLS stacks.
const maxBVJJA4Hashes = 3

// writeBVJ signs and sets the _bvj cookie.  ja4Set is the "~"-joined fingerprint
// set (see cookies.JClaims); a single hash is the common case.
func (h *Handler) writeBVJ(w http.ResponseWriter, r *http.Request, host, ja4Set, uaHash, lineage string, asn uint) {
	val := cookies.IssueJValue(h.cfg().Secret.BVSecret, ja4Set, uaHash, lineage, asn, host, "captcha")
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

// mintBVJ issues a FRESH-lineage _bvj for the solving client and sets it on w.
// Solve paths only (VerifyJSON, and IssueBVJ's first-time path): a fresh lineage
// is a fresh rebind budget, so it must always be paid for by a real solve.  The
// stored JA4 set starts as the single fingerprint seen at this solve; a re-solve
// under a new transport extends it via remintBVJAppend (keeping the lineage).
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
	h.writeBVJ(w, r, host, cookies.FingerprintHash(ja4),
		cookies.FingerprintHash(r.Header.Get("User-Agent")), lineage, asn)
}

// remintBVJAppend re-issues the _bvj for the SAME lineage as prior, adding this
// connection's JA4 to the stored set (capped) and refreshing the UA hash.  Used
// on the IssueBVJ re-solve path so a device that re-solves under a new transport
// (h2 vs h3 produce different JA4s) keeps every fingerprint it has proven AND
// its existing rebind budget, instead of spawning a fresh lineage each time its
// JA4 changes.
func (h *Handler) remintBVJAppend(w http.ResponseWriter, r *http.Request, ip, host string, prior cookies.JClaims) {
	var asn uint
	if h.IPGeo != nil {
		asn = h.IPGeo.LookupInfo(ip).ASN
	}
	ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
	set := cookies.AppendJA4Hash(prior.JA4Hash, cookies.FingerprintHash(ja4), maxBVJJA4Hashes)
	h.writeBVJ(w, r, host, set,
		cookies.FingerprintHash(r.Header.Get("User-Agent")), prior.Lineage, asn)
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
		if c.Name != "_bv" || c.Value == "" || len(c.Value) > 1024 {
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
	if claims, has := h.validBVJ(r, host, site); has {
		// Re-POSTing with a still-valid _bvj is normally a no-op, so the endpoint
		// can't be looped to farm fresh lineages off one solve.  But "valid"
		// (signature + host + window) does NOT mean "usable for rebind": tryRebind
		// also matches JA4 + UA, so a credential whose stored set lacks THIS
		// connection's fingerprint (a new transport, or an older match rule)
		// verifies here yet is rejected on every roam.  Skip only when the
		// fingerprint is already in the set AND the UA still matches; otherwise
		// extend the SAME lineage with the new JA4 (keeping the rebind budget)
		// so the device rebinds silently on this transport too.
		ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
		if claims.JA4Matches(cookies.FingerprintHash(ja4)) &&
			cookies.FingerprintHash(r.Header.Get("User-Agent")) == claims.UAHash {
			writeJSON(w, http.StatusOK, map[string]any{"ok": 0, "skip": "present"})
			return
		}
		h.remintBVJAppend(w, r, ip, host, claims)
		writeJSON(w, http.StatusOK, map[string]any{"ok": 1})
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
	// Extract JA4 up front so a reject logged before the _bvj check (no_bvj /
	// bvj_invalid) still records the fingerprint -- the request carries
	// X-Client-JA4 regardless of whether a valid _bvj accompanied it.
	ja4 := safeJA4(strings.TrimSpace(r.Header.Get("X-Client-JA4")))
	claims, ok := h.validBVJ(r, host, site)
	if !ok {
		// A roaming visitor still carries a (now stale) _bv; a first-time visitor
		// carries neither.  Only the former is a rebind miss worth recording -- and
		// split "sent a _bvj that didn't verify" from "sent no _bvj at all" so the
		// operator can tell a broken/expired/blocked credential from one that never
		// got stored on the client (the latter points at the issuance path).
		if bvc, _ := r.Cookie("_bv"); bvc != nil && bvc.Value != "" {
			reason := "no_bvj"
			if jc, _ := r.Cookie("_bvj"); jc != nil && jc.Value != "" {
				reason = "bvj_invalid"
			}
			h.logRebindReject(r, site, ip, ja4, reason, "", 0, 0)
		}
		return false
	}
	if ja4 == "" && !cfg.Rebind.AllowNoJA4 {
		// No JA4 reaches this deployment (pure forward-auth without the
		// X-Client-JA4 wiring): the fingerprint gate would degenerate to
		// empty==empty, so refuse unless the operator opted in.
		h.logRebindReject(r, site, ip, ja4, "no_ja4", claims.Lineage, claims.ASN, 0)
		return false
	}
	verdict := strings.TrimSpace(r.Header.Get("X-JA4-Verdict"))
	// Match the JA4 against the SET the _bvj accumulated.  A device legitimately
	// presents several -- HTTP/2 over TCP and HTTP/3 over QUIC differ in every
	// JA4 field -- and the _bvj remembers each transport it has solved under.  A
	// fingerprint outside the set is usually a transport the device hasn't
	// re-solved under yet, so veto only when it looks bot-like (a foreign TLS
	// stack replaying the cookie); a clean fingerprint is let through -- still
	// gated by UA + ASN + per-lineage cap + the _bvj HMAC -- and flagged so the
	// operator keeps visibility into JA4-drift passes.
	ja4Relaxed := false
	if !claims.JA4Matches(cookies.FingerprintHash(ja4)) {
		if h.verdictIsBot(verdict) {
			h.logRebindReject(r, site, ip, ja4, "ja4_mismatch", claims.Lineage, claims.ASN, 0)
			return false
		}
		ja4Relaxed = true
	}
	if cookies.FingerprintHash(r.Header.Get("User-Agent")) != claims.UAHash {
		h.logRebindReject(r, site, ip, ja4, "ua_mismatch", claims.Lineage, claims.ASN, 0)
		return false
	}
	asnVeto := cfg.Rebind.ASNVetoResolved() == "auto" && h.IPGeo != nil && h.IPGeo.ASNLoaded()
	var curASN uint
	if asnVeto {
		curASN = h.IPGeo.LookupInfo(ip).ASN
		// An unmappable side (private range, db gap, pre-ASN-db solve) fails
		// closed: "unknown" must not read as "same network".
		if curASN == 0 || claims.ASN == 0 || curASN != claims.ASN {
			// Surface the genuine cross-AS block (both sides known, differ) so the
			// operator can SEE the asn gate refusing a _bv replayed from another
			// carrier.  An unmappable side is a data gap, not a block, so it stays
			// quiet to keep the signal high-value.
			if curASN != 0 && claims.ASN != 0 {
				h.logRebindReject(r, site, ip, ja4, "asn_mismatch", claims.Lineage, claims.ASN, curASN)
			}
			return false
		}
	}
	allowed, err := db.RebindAllow(r.Context(), h.DB, claims.Lineage, host,
		cfg.Rebind.MaxRebindsResolved(), cfg.Rebind.MaxRebindsPerHourResolved(), time.Now().Unix())
	if err != nil || !allowed {
		// nil err + !allowed is the per-lineage cap (lifetime or hourly); a non-nil
		// err is a DB fault, not a policy decision, so don't log it as a reject.
		if err == nil {
			h.logRebindReject(r, site, ip, ja4, "cap", claims.Lineage, claims.ASN, curASN)
		}
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
		payload := map[string]any{
			"lineage":   claims.Lineage,
			"solve_asn": claims.ASN,
			"cur_asn":   curASN,
			"asn_veto":  asnVeto,
			"orig_path": origPath,
		}
		// Record when the rebind passed despite the JA4 not being in the _bvj's
		// set (A): a non-bot fingerprint drift, kept visible for abuse-watching.
		if ja4Relaxed {
			payload["ja4_relaxed"] = true
		}
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
			CookieBV:     readCookieMax(r, "_bv", 1024),
			Payload:      payload,
		})
	}

	h.serveRebindRedirect(w, origPath)
	return true
}

// logRebindReject records a silent rebind refusal under PhaseBVRebindReject with a
// reason so the operator can see WHY a roaming client fell through to a real
// challenge instead of being re-bound -- otherwise every miss is invisible and
// indistinguishable from a fresh visitor.  reason is one of: asn_mismatch (new
// IP's ASN != solve ASN), bvj_invalid (_bvj sent but failed to verify), no_bvj
// (carries a stale _bv but no _bvj at all), ja4_mismatch, ua_mismatch, cap
// (per-lineage rebind budget exhausted).  Kept off PhaseBVRebind so it never
// inflates the "successfully re-bound" count.  Best-effort: an unpackable IP
// skips the row (the refusal already happened at the call site).
func (h *Handler) logRebindReject(r *http.Request, site, ip, ja4, reason, lineage string, solveASN, curASN uint) {
	pkt := events.PackIP(ip)
	if pkt == nil {
		return
	}
	// Record the original URL too (the _orig that protect.inc's challenge rewrite
	// carries, or the forward-auth _orig query) so the hunt log shows WHERE the
	// roaming client was headed when the rebind was refused -- otherwise the path
	// column is blank for every reject row.
	origPath := truncateAt(r.URL.Query().Get("_orig"), 200)
	if !isLocalRedirect(origPath) {
		origPath = ""
	}
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
		Phase:        string(events.PhaseBVRebindReject),
		CookieBV:     readCookieMax(r, "_bv", 1024),
		Payload: map[string]any{
			"lineage":   lineage,
			"solve_asn": solveASN,
			"cur_asn":   curASN,
			"reason":    reason,
			"orig_path": origPath,
		},
	})
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
