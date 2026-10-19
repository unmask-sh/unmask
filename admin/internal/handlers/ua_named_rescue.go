package handlers

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/hll"
)

// namedRescueClaim reports whether nginx passed this request on a crawler's
// name alone (server.inc forwards http.inc's $is_search_bot as
// X-Unmask-Named-Rescue).  A request that reaches the daemon with the claim
// set was caught by something the name does not clear -- a trap, a rule, a
// protected path, the budget -- and the serve event says so.
func namedRescueClaim(r *http.Request) bool {
	return r.Header.Get("X-Unmask-Named-Rescue") == "1"
}

// fillNamedRescue adds to each crawler row what the last 24 hours let through
// on its name alone: the request count and an estimate of the addresses, from
// unmask_crawler_named_hourly (the access-log reader's hourly aggregate).  Best
// effort: a read failure leaves the rows at zero and is logged once per page.
func (h *Handler) fillNamedRescue(ctx context.Context, v *upstreamView) {
	if h == nil || h.DB == nil || v == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	since := time.Now().Unix()/3600 - 24
	rows, err := h.DB.QueryContext(ctx,
		`SELECT crawler, cnt, ips FROM unmask_crawler_named_hourly WHERE bucket_hour >= ?`, since)
	if err != nil {
		log.Printf("ua-filter: named rescue counts: %v", err)
		return
	}
	defer rows.Close()
	type agg struct {
		cnt int
		ips hll.Sketch
	}
	byName := map[string]*agg{}
	for rows.Next() {
		var name string
		var cnt int
		var sketch []byte
		if err := rows.Scan(&name, &cnt, &sketch); err != nil {
			continue
		}
		a := byName[name]
		if a == nil {
			a = &agg{}
			byName[name] = a
		}
		a.cnt += cnt
		if len(sketch) > 0 {
			a.ips.Merge(hll.Load(sketch))
		}
	}
	for gi := range v.Groups {
		for ri := range v.Groups[gi].Rows {
			row := &v.Groups[gi].Rows[ri]
			if a := byName[row.Name]; a != nil && a.cnt > 0 {
				row.NamedDay = a.cnt
				row.NamedIPs = a.ips.Estimate()
			}
		}
	}
}
