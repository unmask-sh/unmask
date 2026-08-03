// JA4 playground (= a page that answers "what verdict do we get for this JA4 / UA?").
//
// The real judgement runs in nginx's map directives, but here we re-run the
// same rules on the Go side and surface the result.  From the user's view:
//   - check whether a JA4 verdict pattern you wrote actually matches
//   - test whether a search-bot UA is really "bypassed" or "challenged"
//   - easy to demo "this is how unmask makes its judgement" in a blog / demo
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// AdminPlayground: GET {base}/admin/playground/  — render the UI.
func (h *Handler) AdminPlayground(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"TZ":       resolveTZ(r),
		"BasePath": h.cfg().Server.BasePath,
		"Version":  h.Version,
	}
	h.addMeToData(r, data)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "playground.html", data); err != nil {
		log.Printf("playground render: %v", err)
	}
}

// playgroundJA4Match: the JA4-hit portion of the eval API response.
type playgroundJA4Match struct {
	Pattern string `json:"pattern"`
	Verdict string `json:"verdict"`
	Action  string `json:"action"`
	Source  string `json:"source"` // "preset:<group_id>" or "extra"
}

// AdminPlaygroundEval: POST {base}/admin/api/playground/eval — evaluate one record via JSON.
//
// Input:  { ja4, ua, ip }
// Output: { ja4_match: {pattern, verdict, action, source}, classify: "human"|...,
//
//	bypass_ip: bool, summary: "..." }
func (h *Handler) AdminPlaygroundEval(w http.ResponseWriter, r *http.Request) {
	var in struct {
		JA4 string `json:"ja4"`
		UA  string `json:"ua"`
		IP  string `json:"ip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_json"})
		return
	}
	in.JA4 = strings.TrimSpace(in.JA4)
	in.UA = strings.TrimSpace(in.UA)
	in.IP = strings.TrimSpace(in.IP)

	cur := h.snapshotSettings().Nginx

	// 1. Match against the JA4 verdicts (= preset → extra, first match wins).
	var match *playgroundJA4Match
	if in.JA4 != "" {
		disabled := map[string]bool{}
		for _, id := range cur.JA4Verdicts.DisabledPresets {
			disabled[strings.TrimSpace(id)] = true
		}
		for _, g := range nginxconf.JA4VerdictGroups {
			if disabled[g.ID] {
				continue
			}
			for _, rule := range g.Rules {
				if matchedRegex(rule.Pattern, in.JA4) {
					match = &playgroundJA4Match{
						Pattern: rule.Pattern,
						Verdict: rule.Verdict,
						Action:  rule.Action,
						Source:  "preset:" + g.ID,
					}
					break
				}
			}
			if match != nil {
				break
			}
		}
		if match == nil {
			for i, p := range cur.JA4Verdicts.Extra {
				if i < len(cur.JA4Verdicts.ExtraDisabled) && cur.JA4Verdicts.ExtraDisabled[i] {
					continue
				}
				if !matchedRegex(p.Pattern, in.JA4) {
					continue
				}
				match = &playgroundJA4Match{
					Pattern: p.Pattern,
					Verdict: p.Verdict,
					Action:  p.Action,
					Source:  "extra",
				}
				break
			}
		}
	}

	// 2. Classify the UA (= rescue search / AI bots / challenge user_dev).
	verdictForClassify := ""
	if match != nil {
		verdictForClassify = match.Action // "bot" / "suspect" / "ok"
	}
	cat := classify.IsBot(in.UA, verdictForClassify).String()

	// 2b. Range-backed crawler UAs with UA-string rescue off (uarange.go)
	// are not rescued by the UA string alone; the playground can't run the
	// geo CIDR check on the IP field (see the bypass-IP note below), so
	// surface the conditional instead of promising a pass a spoof would not
	// get.
	rangeVerified := false
	if cat == "search_ai" {
		if pats := nginxconf.SortedUpstreamUAOff(cur); len(pats) > 0 {
			if re := compileCachedRe("(?i)(?:" + strings.Join(pats, ")|(?:") + ")"); re != nil && re.MatchString(in.UA) {
				rangeVerified = true
			}
		}
	}

	// 3. bypass-IP check (= simplified.  CIDR comparison runs in nginx's geo
	//    directive, so here we only do exact match against custom bypass_ips.
	//    Presets (Googlebot etc. IP ranges) require reading the CIDRs
	//    expanded on the nginxconf side for an accurate judgement, so omit.
	bypassIP := false
	for _, ip := range cur.BypassIPs {
		if strings.TrimSpace(ip) == in.IP && in.IP != "" {
			bypassIP = true
			break
		}
	}

	// 4. summary: the final behavior to surface to the user.
	summary := summarize(match, cat, bypassIP, rangeVerified)

	out := map[string]any{
		"ok":             1,
		"ja4_match":      match,
		"classify":       cat,
		"bypass_ip":      bypassIP,
		"range_verified": rangeVerified,
		"summary":        summary,
	}
	writeJSON(w, http.StatusOK, out)
}

// matchedRegex: nginx regex carries a "~*" prefix.  For Go's regex, strip
// "~*", compile the pure pattern case-insensitive, and match.  On a bad
// pattern, return false (= log only).
func matchedRegex(pat, s string) bool {
	// A literal pattern means itself; resolve it to the expression that says
	// so.  Single point on the Go side -- lookupUAListed, lookupJA4Verdict and
	// the playground all arrive here -- so the admin and the rendered nginx
	// map cannot disagree about what a pattern means.
	pat = settings.PatternRegex(pat)
	pat = strings.TrimPrefix(pat, "~*")
	pat = strings.TrimPrefix(pat, "~")
	// compileCachedRe memoizes by pattern string: lookupJA4Verdict /
	// lookupUAListed call this on ~40-100 preset patterns per /api/check, which
	// used to recompile every time (CPU-DoS).  Cached compile = a cheap lookup.
	re := compileCachedRe("(?i)" + pat)
	if re == nil {
		return false
	}
	return re.MatchString(s)
}

// summarize: a one-line "what actually happens" from the user's perspective.
func summarize(match *playgroundJA4Match, cat string, bypassIP, rangeVerified bool) string {
	if bypassIP {
		return "[OK] matches bypass IP: skip every check (= neither challenge nor honeypot fires)"
	}
	if match != nil {
		switch match.Action {
		case "bot":
			return "[BLOCK] JA4 verdict=bot: skip PoW → straight to CAPTCHA (= judged as a browser-impersonating bot)"
		case "suspect":
			return "[WARN] JA4 verdict=suspect: pass via the normal challenge (PoW + behavioral); observed in the log"
		case "ok":
			return "[OK] JA4 verdict=ok: not a challenge target"
		}
	}
	switch cat {
	case "search_ai":
		if rangeVerified {
			return "[COND] range-verified crawler UA: passes only from the vendor's official IP ranges (enabled bypass-IP presets); from any other address the UA is treated as a spoof and challenged"
		}
		return "[OK] search / AI bot UA: passes via the UA-string rescue (no published IP range to verify against, or UA rescue explicitly enabled)"
	case "user_dev":
		return "[BLOCK] user_dev (curl / library) UA: straight to challenge (= reject non-browser clients)"
	case "old_ua":
		return "[BLOCK] old browser (e.g. Chrome below 30): a classic impersonation tell → challenge"
	case "service":
		return "[WARN] service (scanner / SEO / monitoring etc.) UA: challenge"
	case "human":
		return "[HUMAN] judged as human: passes via the normal PoW.  Once the _bv cookie is set, pass through for 3 days"
	}
	return ""
}
