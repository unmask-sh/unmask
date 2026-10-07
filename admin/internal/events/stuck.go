package events

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// Visitors stuck at the challenge: what the over-block circuit breaker reads.
//
// A visitor who cannot get past the challenge leaves one of two marks, the two
// shapes of the 2026-06-08 production loop:
//
//   - the pass is not honoured: the visitor passes, and the same page on the
//     same site is challenged again moments later (a _bv nginx rejects -- the
//     daemon and the plugin on different secrets);
//   - the pass never comes: the challenge runs and its answer fails
//     verification (a stale challenge script solving the old proof-of-work).
//
// Both are counted per address, against the addresses that ran the challenge
// at all.  The breaker used to divide challenge serves by addresses instead,
// and one scanner hammering a site with a browser's user-agent lifted that
// average over the threshold while every person in the window passed: two
// false alarms on one install in an afternoon (2026-10-07).  An address that
// ran the challenge and was then shown it again, or failed it, is a visitor
// the product is failing; one that never ran it is not.
//
// Individual addresses get stuck every day -- a browser that drops cookies, a
// crawler that keeps no cookie jar but runs the script -- a handful in ten
// minutes on a busy site, a few percent of those that ran the challenge.  A
// loop that over-blocks the site makes nearly all of them stuck.

// loopGap: the same page on the same site and address, challenged again
// within this long of a pass, is the pass not being honoured.  The loops seen
// reload within a second or two; a person behind a shared address who meets
// the challenge for themselves is mostly on another page, or later.
const loopGap = 30 * time.Second

// passPhases are the events a pass records: the _bv cookie issued after the
// proof-of-work, the CAPTCHA, or both.
var passPhases = []string{"bv_pow_only", "bv_captcha_only", "bv_pow_then_captcha"}

// stuckExamples: how many stuck addresses a report names.
const stuckExamples = 5

// StuckReport is one window's reading.
type StuckReport struct {
	Minutes int
	// Loaders: distinct addresses that ran the challenge (a load event).
	Loaders int
	// Stuck: distinct addresses either re-challenged on the same page right
	// after passing (Rechallenged) or failing verification (VerifyFailed).
	Stuck        int
	Rechallenged int
	VerifyFailed int
	// Passed: distinct addresses that passed.
	Passed int
	// Serves / ServeIPs / Loads: the window's challenge volume, for the
	// report's reader (set only when asked for: counting every serve of a
	// long window costs a scan the decision does not need).
	Serves, ServeIPs, Loads int
	// Examples: the stuck addresses with the most marks, most first.
	Examples []StuckExample
}

// StuckExample is one stuck address.
type StuckExample struct {
	IP, Site, Path string
	// Rechallenged: times it was shown the challenge again within loopGap of
	// passing; VerifyFailed: answers that failed verification.
	Rechallenged, VerifyFailed int
}

// StuckShare is Stuck over the addresses that ran the challenge, in percent.
// An address can be stuck without a load in the window (it loaded just before
// it), so the stuck addresses are counted among those that ran it.
func (r StuckReport) StuckShare() int {
	den := r.Loaders
	if r.Stuck > den {
		den = r.Stuck
	}
	if den == 0 {
		return 0
	}
	return r.Stuck * 100 / den
}

// StuckVisitors reads the last `minutes` of the event log.  withVolume also
// counts every challenge served (StuckReport.Serves / ServeIPs / Loads).
func StuckVisitors(ctx context.Context, d *db.DB, minutes int, withVolume bool) (StuckReport, error) {
	r := StuckReport{Minutes: minutes}
	since := d.NowMinusMinutes(minutes)
	passIn := "'" + strings.Join(passPhases, "','") + "'"

	// The window's counts.  Serves are the bulk of the log; they are counted
	// only when the reader asked for the volume.
	phases := "'load'," + passIn
	if withVolume {
		phases = "'serve'," + phases
	}
	err := d.QueryRowContext(ctx, `SELECT
	           COALESCE(SUM(CASE WHEN phase = 'serve' THEN 1 ELSE 0 END), 0),
	           COUNT(DISTINCT CASE WHEN phase = 'serve' THEN ip_address END),
	           COALESCE(SUM(CASE WHEN phase = 'load' THEN 1 ELSE 0 END), 0),
	           COUNT(DISTINCT CASE WHEN phase = 'load' THEN ip_address END),
	           COUNT(DISTINCT CASE WHEN phase IN (`+passIn+`) THEN ip_address END)
	         FROM unmask_event
	         WHERE phase IN (`+phases+`) AND date_created > `+since).
		Scan(&r.Serves, &r.ServeIPs, &r.Loads, &r.Loaders, &r.Passed)
	if err != nil {
		return r, err
	}

	marks := map[string]*StuckExample{} // by packed address
	mark := func(ipb []byte, site, path string) *StuckExample {
		k := string(ipb)
		e := marks[k]
		if e == nil {
			e = &StuckExample{IP: unpackIP(ipb), Site: site, Path: path}
			marks[k] = e
		}
		return e
	}

	// Answers that failed verification.
	rows, err := d.QueryContext(ctx, `SELECT ip_address, site, payload_json FROM unmask_event
	         WHERE phase = 'verify_ng' AND date_created > `+since)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var ipb []byte
		var site, payload *string
		if err := rows.Scan(&ipb, &site, &payload); err != nil {
			rows.Close()
			return r, err
		}
		path, _ := payloadPathReason(payload)
		mark(ipb, deref(site), path).VerifyFailed++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}

	// Passes, then the challenges served to the same addresses: a serve of the
	// passed page within loopGap is the pass not honoured.
	type key struct{ ip, site, path string }
	passedAt := map[key][]time.Time{}
	var passIPs [][]byte
	seenIP := map[string]bool{}
	rows, err = d.QueryContext(ctx, `SELECT ip_address, site, payload_json, date_created FROM unmask_event
	         WHERE phase IN (`+passIn+`) AND date_created > `+since)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var ipb []byte
		var site, payload *string
		var at any
		if err := rows.Scan(&ipb, &site, &payload, &at); err != nil {
			rows.Close()
			return r, err
		}
		t, ok := eventTime(at)
		if !ok {
			continue
		}
		path, _ := payloadPathReason(payload)
		k := key{string(ipb), deref(site), path}
		passedAt[k] = append(passedAt[k], t)
		if !seenIP[string(ipb)] {
			seenIP[string(ipb)] = true
			passIPs = append(passIPs, ipb)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	for start := 0; start < len(passIPs); start += 200 {
		chunk := passIPs[start:min(start+200, len(passIPs))]
		args := make([]any, len(chunk))
		for i, b := range chunk {
			args[i] = b
		}
		rows, err := d.QueryContext(ctx, `SELECT ip_address, site, payload_json, date_created FROM unmask_event
		         WHERE phase = 'serve' AND date_created > `+since+`
		           AND ip_address IN (?`+strings.Repeat(",?", len(chunk)-1)+`)`, args...)
		if err != nil {
			return r, err
		}
		for rows.Next() {
			var ipb []byte
			var site, payload *string
			var at any
			if err := rows.Scan(&ipb, &site, &payload, &at); err != nil {
				rows.Close()
				return r, err
			}
			path, reason := payloadPathReason(payload)
			// A challenge served on purpose to a visitor who has passed --
			// the reuse cap, a rate rule -- is the product deciding, not a
			// pass that was lost.
			if reason != "" && reason != "none" {
				continue
			}
			t, ok := eventTime(at)
			if !ok {
				continue
			}
			for _, p := range passedAt[key{string(ipb), deref(site), path}] {
				if gap := t.Sub(p); gap >= 0 && gap <= loopGap {
					mark(ipb, deref(site), path).Rechallenged++
					break
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return r, err
		}
	}

	all := make([]StuckExample, 0, len(marks))
	for _, e := range marks {
		all = append(all, *e)
		if e.Rechallenged > 0 {
			r.Rechallenged++
		}
		if e.VerifyFailed > 0 {
			r.VerifyFailed++
		}
	}
	r.Stuck = len(all)
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i].Rechallenged+all[i].VerifyFailed, all[j].Rechallenged+all[j].VerifyFailed
		if a != b {
			return a > b
		}
		return all[i].IP < all[j].IP
	})
	if len(all) > stuckExamples {
		all = all[:stuckExamples]
	}
	r.Examples = all
	return r, nil
}

// payloadPathReason reads the page a challenge was for and why it was served
// from an event's payload.
func payloadPathReason(payload *string) (path, reason string) {
	if payload == nil || *payload == "" {
		return "", ""
	}
	var p struct {
		OrigPath    string `json:"orig_path"`
		ForceReason string `json:"force_reason"`
	}
	_ = json.Unmarshal([]byte(*payload), &p)
	return p.OrigPath, p.ForceReason
}

// eventTime reads date_created, which arrives as text on SQLite and as a time
// on MariaDB.
func eventTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case []byte:
		return parseEventTime(string(t))
	case string:
		return parseEventTime(t)
	}
	return time.Time{}, false
}

func parseEventTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
