package nginxconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RenderCause: why a render ran -- what the reload notice tells the operator
// beside when.  Kind is one of the RenderBy* names; Detail is the kind's own
// word on it (the settings section saved, what the sync wrote).  A render
// nobody named (a dry run, an older caller) has the zero cause.
type RenderCause struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

const (
	RenderBySettings = "settings" // a save in the admin; Detail = the section
	RenderByRestore  = "restore"  // a settings restore from the audit log
	RenderByReview   = "review"   // the upgrade enforcement review
	RenderByIPRange  = "iprange"  // the IP-range sync; Detail = "relay" or "sources:<n>"
	RenderByGeoIP    = "geoip"    // the GeoIP database update
	RenderByCLI      = "cli"      // unmask render-nginx (install, upgrade, by hand)
)

// RenderChange: one top-level block of a rendered file whose lines moved --
// a map, a geo, a zone -- with how many lines came, went, or changed (a line
// that went and one that came, counted once).
type RenderChange struct {
	File    string `json:"file"`
	Block   string `json:"block"`
	Added   int    `json:"added,omitempty"`
	Removed int    `json:"removed,omitempty"`
	Changed int    `json:"changed,omitempty"`
}

// RenderRecord: the cause of the last render that changed a file, and what
// it changed, kept beside the rendered files for the reload notice.
type RenderRecord struct {
	At      int64          `json:"at"` // unix seconds
	Cause   RenderCause    `json:"cause"`
	Changes []RenderChange `json:"changes,omitempty"`
}

// renderCauseFile holds the RenderRecord in the render dir.  Dot-named like
// the render watch's state: not a file nginx includes.
const renderCauseFile = ".render-cause"

// renderCausePerm: the record names blocks of http.inc, which carries
// bv_secret and is itself 0640 (the nginx group); so is the record.
const renderCausePerm = 0o640

func writeRenderRecord(outDir string, rec RenderRecord) {
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	// Best effort, like the substantive-render marker: a record that could
	// not be written leaves the notice saying only when, which is still true.
	// The chmod reaches a record written 0644 before 0.1.53 (WriteFile keeps
	// an existing file's mode).
	path := filepath.Join(outDir, renderCauseFile)
	_ = os.WriteFile(path, append(b, '\n'), renderCausePerm)
	_ = os.Chmod(path, renderCausePerm)
}

// ScrubRenderRecord rewrites the record kept in dir under the current rules
// -- blockKey, which stops at a quoted field, and renderCausePerm.  Until
// 0.1.53 a block was keyed by its first three words up to 60 characters,
// which for the `unmask_bv_secret "<hex>";` line of http.inc was the
// directive and the secret's first 42 digits, written 0644 and shown in the
// reload notice to every operator, viewers included, whenever the line
// changed (the first render, a key rotation).  Run once at start
// (renderwatch.Watch.Load); a record this process writes is clean already.
func ScrubRenderRecord(dir string) {
	path := filepath.Join(dir, renderCauseFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var rec RenderRecord
	if json.Unmarshal(b, &rec) == nil {
		changed := false
		for i := range rec.Changes {
			if k := blockKey(rec.Changes[i].Block); k != rec.Changes[i].Block {
				rec.Changes[i].Block = k
				changed = true
			}
		}
		if changed {
			writeRenderRecord(dir, rec)
			return
		}
	}
	_ = os.Chmod(path, renderCausePerm)
}

// ReadRenderRecord: the record of the last render that changed a file in
// dir, if one was kept.
func ReadRenderRecord(dir string) (RenderRecord, bool) {
	b, err := os.ReadFile(filepath.Join(dir, renderCauseFile))
	if err != nil {
		return RenderRecord{}, false
	}
	var rec RenderRecord
	if json.Unmarshal(b, &rec) != nil || rec.At == 0 {
		return RenderRecord{}, false
	}
	return rec, true
}

// changedBlocks compares two renders of one file by top-level block.  A
// block is a line at column 0 and the indented lines under it, keyed by what
// names it (blockKey); the stamps the render id ignores are left out.  Lines
// are compared as multisets, so a reordered block reads as unchanged.
func changedBlocks(file string, prev, next []byte) []RenderChange {
	a, b := splitBlocks(StripRenderStamps(prev)), splitBlocks(StripRenderStamps(next))
	var out []RenderChange
	seen := map[string]bool{}
	for _, k := range blockOrder(b) {
		seen[k] = true
		if ch, ok := diffLines(a[k], b[k]); ok {
			ch.File, ch.Block = file, k
			out = append(out, ch)
		}
	}
	for _, k := range blockOrder(a) {
		if !seen[k] {
			out = append(out, RenderChange{File: file, Block: k, Removed: countLines(a[k])})
		}
	}
	return out
}

// blockLines: the lines of a block, in order, with a sequence number so
// blockOrder can list the keys as the file does.
type blockLines struct {
	seq   int
	lines []string
}

func splitBlocks(text string) map[string]*blockLines {
	out := map[string]*blockLines{}
	var cur *blockLines
	seq := 0
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		top := ln[0] != ' ' && ln[0] != '\t' && t != "}"
		if top {
			k := blockKey(t)
			if b, ok := out[k]; ok {
				cur = b
			} else {
				seq++
				cur = &blockLines{seq: seq}
				out[k] = cur
			}
		}
		if cur == nil { // lines before the first block: a block of their own
			seq++
			cur = &blockLines{seq: seq}
			out[""] = cur
		}
		if top || t != "}" {
			cur.lines = append(cur.lines, t)
		}
	}
	return out
}

func blockOrder(m map[string]*blockLines) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ { // insertion sort by sequence: a few dozen keys
		for j := i; j > 0 && m[keys[j]].seq < m[keys[j-1]].seq; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func countLines(b *blockLines) int {
	if b == nil {
		return 0
	}
	return len(b.lines)
}

// diffLines: how many lines of a block came, went, or changed between two
// renders; ok when any did.  A block missing on one side is all added or
// all removed.
func diffLines(prev, next *blockLines) (RenderChange, bool) {
	count := func(b *blockLines) map[string]int {
		m := map[string]int{}
		if b != nil {
			for _, ln := range b.lines {
				m[ln]++
			}
		}
		return m
	}
	pc, nc := count(prev), count(next)
	var ch RenderChange
	for ln, n := range pc {
		if d := n - nc[ln]; d > 0 {
			ch.Removed += d
		}
	}
	for ln, n := range nc {
		if d := n - pc[ln]; d > 0 {
			ch.Added += d
		}
	}
	if ch.Added == 0 && ch.Removed == 0 {
		return RenderChange{}, false
	}
	ch.Changed = ch.Added
	if ch.Removed < ch.Changed {
		ch.Changed = ch.Removed
	}
	ch.Added -= ch.Changed
	ch.Removed -= ch.Changed
	return ch, true
}

// blockKey names a top-level line: a map or geo by the variable it sets, a
// zone by its name, a block it opens ("{") by its first three words, a
// plain directive by its first two -- and never a quoted field, where a
// value sits: `unmask_bv_secret "<hex>";` is keyed by the directive alone
// (ScrubRenderRecord says what the key used to carry).
func blockKey(line string) string {
	t := strings.TrimSpace(line)
	opens := strings.HasSuffix(t, "{")
	t = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(t, "{")), ";"))
	f := strings.Fields(t)
	if len(f) == 0 {
		return ""
	}
	switch f[0] {
	case "map", "geo":
		return f[0] + " " + f[len(f)-1]
	case "limit_req_zone", "limit_conn_zone":
		for _, w := range f[1:] {
			if strings.HasPrefix(w, "zone=") {
				return f[0] + " " + strings.SplitN(strings.TrimPrefix(w, "zone="), ":", 2)[0]
			}
		}
	}
	n := 2
	if opens {
		n = 3
	}
	if len(f) < n {
		n = len(f)
	}
	for i, w := range f[:n] {
		if w[0] == '"' || w[0] == '\'' {
			n = i
			break
		}
	}
	k := strings.Join(f[:n], " ")
	if len(k) > 60 {
		k = k[:60]
	}
	return k
}

// BlockLabelKey: the word the page has for a block key -- the suffix of an
// i18n reload_notice.block.* key -- or "" for a block it names as it is.
func BlockLabelKey(key string) string {
	f := strings.Fields(key)
	if len(f) == 0 {
		return ""
	}
	switch f[0] {
	case "limit_req_zone", "limit_conn_zone":
		return "rate_zones"
	case "log_format":
		return "log_format"
	case "upstream":
		return "upstream"
	case "unmask_bv_secret":
		return "secret"
	}
	if f[0] != "map" && f[0] != "geo" || len(f) < 2 {
		return ""
	}
	v := strings.TrimPrefix(f[1], "$")
	for _, r := range []struct{ prefix, label string }{
		{"unmask_country", "country"},
		{"is_bypass_ip", "bypass"},
		{"unmask_bind_key", "relay"},
		{"unmask_search_bot_ua", "crawlers"},
		{"is_search_bot", "crawlers"},
		{"unmask_notif_preview_ua", "crawlers"},
		{"unmask_apple_tls", "crawlers"},
		{"is_challenge_target", "ua_filter"},
		{"is_known_browser", "ua_filter"},
		{"unmatched_", "ua_filter"},
		{"unmask_ua_", "ua_filter"},
		{"unmask_hp_", "honeypot"},
		{"serve_bot_challenge", "honeypot"},
		{"unmask_pp_", "protected"},
		{"protected_mode", "protected"},
		{"unmask_cr_", "custom_rules"},
		{"unmask_asn", "asn"},
		{"is_asn_", "asn"},
		{"unmask_geo_", "geo"},
		{"is_geo_", "geo"},
		{"ja4_", "ja4"},
		{"effective_ja4", "ja4"},
		{"unmask_ja4_", "ja4"},
		{"unmask_lb_", "lb"},
		{"unmask_any_lb_header", "lb"},
		{"unmask_forwarded_", "lb"},
		{"unmask_port_fallback", "lb"},
		{"unmask_default_port", "lb"},
		{"unmask_stats_excluded", "stats_exclude"},
		{"unmask_log_keep", "stats_exclude"},
		{"unmask_observe", "observe"},
		{"unmask_ban", "bans"},
		{"unmask_banned", "bans"},
		{"unmask_cb_", "community_bans"},
		{"unmask_bv_", "cookies"},
		{"bv_", "cookies"},
		{"unmask_needs_captcha_grade", "cookies"},
		{"unmask_chmode", "chain"},
	} {
		if strings.HasPrefix(v, r.prefix) {
			return r.label
		}
	}
	return ""
}

// renderRecordAt: a record written at about the render's time -- the one
// the reload notice may trust to be about the configuration waiting.
func (r RenderRecord) About(written time.Time) bool {
	d := r.At - written.Unix()
	return d >= -60 && d <= 60
}
