package handlers

import "net/http"

// Readyz: GET {base}/readyz -- whether the daemon has its database, and with
// it everything but the challenge pages: the log receiver, the ban manager,
// the event writer, the statistics and the admin UI.  200 "ok" when it has,
// 503 "database unavailable" when it runs without one.
//
// It reports what the daemon started with and does not ask the database
// anything.  A database that stops answering later is reconnected to by the
// pool, with no restart, and a probe that pinged it would take every node
// sharing that database out of a load balancer at the same moment -- each of
// them still able to serve the challenge.  /metrics has the same reading as
// unmask_db_up, for an alert.
func (h *Handler) Readyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	if h == nil || h.DB == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("database unavailable\n"))
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}
