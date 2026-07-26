package handlers

import (
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// maxSuggestTokens caps how many space-separated terms one query fans out into,
// so a pathological "a b c d ..." can't kick off an unbounded scan.  Well past
// any realistic multi-word query.
const maxSuggestTokens = 8

// resolveSuggestTokens splits a query on whitespace and resolves each token:
//   - a token that names EXACTLY ONE catalog provider (by id/label/alias) becomes
//     that provider's PRIMARY OrgPattern -- so "azure" -> "Microsoft" and "china"
//     stays literal, letting "azure china" AND-narrow to "Microsoft (China)…";
//   - an ambiguous or unknown token is kept literal (org substring / AS number).
//
// Tokens shorter than 2 chars are dropped (they match most of the DB).
func resolveSuggestTokens(q string) []string {
	tokens := strings.Fields(q)
	if len(tokens) > maxSuggestTokens {
		tokens = tokens[:maxSuggestTokens]
	}
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if len([]rune(tok)) < 2 {
			continue
		}
		if m := settings.ProvidersMatchingQuery(tok); len(m) == 1 && len(m[0].OrgPatterns) > 0 {
			out = append(out, m[0].OrgPatterns[0])
			continue
		}
		out = append(out, tok)
	}
	return out
}

// AdminASNSuggest powers the autocomplete on the ASN settings tab's custom-rule
// input.  It searches the *installed* ASN mmdb (not a curated list), so coverage
// is whatever the DB knows:
//   - one text token ("microsoft") -> matching organizations ranked by IPv4
//     space, each carrying its member AS numbers (elided);
//   - one numeric token ("16509"/"AS16509") -> that exact AS number pinpointed
//     to its org, plus numeric-prefix siblings;
//   - space-separated tokens ("amazon data") -> AND: orgs containing ALL of them
//     (a brand token is bridged first, so "azure china" -> Microsoft's China org).
//
// Read-only; auth-gated (any signed-in admin user) by the route wiring.
func (h *Handler) AdminASNSuggest(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	loaded := h.IPGeo != nil && h.IPGeo.ASNLoaded()
	items := []ipgeo.ASNSuggestion{}
	// 2-char floor: a single character matches most of the DB and is never a
	// useful autocomplete.
	if loaded && len([]rune(q)) >= 2 {
		switch tokens := resolveSuggestTokens(q); len(tokens) {
		case 0:
			// nothing searchable
		case 1:
			// single token keeps AS-number pinpoint + numeric-prefix behaviour
			items = h.IPGeo.SuggestASN(tokens[0], 10)
		default:
			// AND across tokens (org-name substrings)
			items = h.IPGeo.SuggestASNAnd(tokens, 10)
		}
		if items == nil {
			items = []ipgeo.ASNSuggestion{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"loaded": loaded,
		"items":  items,
	})
}
