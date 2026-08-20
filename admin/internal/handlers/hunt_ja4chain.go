package handlers

import (
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

// btTokenRE: the beacon token's own alphabet (lowercase base36 segments joined
// by dots).  Doubles as the LIKE-safety guarantee in events.JA4Chain -- no
// wildcard survives this.
var btTokenRE = regexp.MustCompile(`^[a-z0-9.]{8,64}$`)

// AdminHuntJA4Chain: GET {base}/admin/hunt/ja4chain?bt=<token>&ts=<unix> — the
// on-demand backing for the events table's ⇄ badge.  Returns the session's
// recorded fingerprint history (phase / JA4 / verdict per event), server
// truth as opposed to the client-echoed field that triggers the badge.
// On-demand because the sibling rows are exactly what a filtered hunt view
// (phase=abandon) does not have on screen, and joining at page render would
// LIKE-scan per row.
func (h *Handler) AdminHuntJA4Chain(w http.ResponseWriter, r *http.Request) {
	bt := r.URL.Query().Get("bt")
	if !btTokenRE.MatchString(bt) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_bt"})
		return
	}
	ts, _ := strconv.ParseInt(r.URL.Query().Get("ts"), 10, 64)
	if ts <= 0 {
		ts = time.Now().Unix()
	}
	rows, truncated, err := events.JA4Chain(r.Context(), h.DB, bt, ts, 60)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": 0})
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{"t": c.AtMs, "p": c.Phase, "j": c.JA4, "v": c.Verdict})
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": out, "truncated": truncated})
}
