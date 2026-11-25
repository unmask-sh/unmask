package notifier

import "sort"

// EventLetThroughFault: the site answered requests on no ground the
// configuration can name -- judged a challenge and served by a file or a
// backend all the same, or let through with no row of the configuration to
// account for it (the access log's why=none, nginxlog/let_through.go).  The
// list of what was let through (BAN > Let through) shows them, to whoever
// opens it; a ground that should hold nothing is not a page an operator
// keeps open, so the admin's notification list says when it stops being
// empty, with the sites, and links there.
//
// The list alone: no webhook, no mail.  The ground is new, and what it
// catches on a configuration nobody has seen yet is not known well enough to
// page a person with.
const (
	EventLetThroughFault = "let_through_fault"

	// LetFaultSitesKept: the sites a call names, and the list's row of an
	// hour after it folded the calls; the rest are a count.
	LetFaultSitesKept = 8
)

// LetThroughFault: the access log's flush calls it with what it has just
// written under the reason "none" (nginxlog.Reader.SetLetFaultObserver): the
// clock hour (unix seconds / 3600) the requests are counted in, how many, and
// how many by site.  The list folds an hour's calls into one row.
func (n *Notifier) LetThroughFault(hour int64, count int, sites map[string]int) {
	if n == nil || count <= 0 {
		return
	}
	cfg := n.currentCfg()
	named, more := topSites(sites, LetFaultSitesKept)
	fields := map[string]any{
		"event": EventLetThroughFault,
		"count": int64(count),
		"hour":  hour * 3600,
		"sites": named,
		"more":  int64(more),
		"site":  cfg.Sites,
		"ts":    n.clock().Unix(),
	}
	fields["severity"] = Severity(EventLetThroughFault, fields)
	n.toInbox(EventLetThroughFault, fields)
}

// topSites keeps the keep busiest sites by name -- a Host is the client's to
// write on a catch-all server, so the names are bounded like any other field
// a visitor wrote -- and sums the requests of the rest.
func topSites(sites map[string]int, keep int) (named map[string]any, more int) {
	names := make([]string, 0, len(sites))
	for name := range sites {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if sites[names[i]] != sites[names[j]] {
			return sites[names[i]] > sites[names[j]]
		}
		return names[i] < names[j]
	})
	named = make(map[string]any, keep)
	for i, name := range names {
		if i >= keep {
			more += sites[name]
			continue
		}
		key := untrusted(name, fieldMax)
		prev, _ := named[key].(int64)
		named[key] = prev + int64(sites[name])
	}
	return named, more
}
