package ban

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"time"
)

// mirrorEntry is one live ban as the checks see it: a row of the table, or
// a ban written since the last load, whose row the next load reads back.
type mirrorEntry struct {
	id        int64 // the row's; 0 for a ban written since the last load
	ip, ja4   string
	scope     string // the scope the ban enforces under (effectiveScope)
	source    string
	action    string
	bannedBy  string
	bannedAt  int64
	expiresAt int64
}

// live reports whether the entry is in force at now.
func (e *mirrorEntry) live(now int64) bool {
	return e.expiresAt == 0 || e.expiresAt > now
}

// mirrorPrefix is an ip_only ban on a whole prefix ("2001:db8:1:2::/64").
type mirrorPrefix struct {
	prefix netip.Prefix
	e      mirrorEntry
}

// mirror holds the table's live bans in memory, by the key each row's scope
// makes of it -- the keys the module holds the file by.  The checks read it
// on every line of the access log, so the table is not asked each time: the
// manager's own writes keep it current (mirrorPut), and every load from the
// table (loadMirror: each write of the file, an operator's edit) rebuilds it
// whole.  Expiry is judged at lookup, so a load is never owed for it.
type mirror struct {
	tuple  map[string][]mirrorEntry // "<ip>|<ja4>": the ip_ja4 rows
	ja4    map[string][]mirrorEntry // "<ja4>": the ja4_only rows
	ip     map[string][]mirrorEntry // "<ip>": the ip_only rows on one address
	prefix []mirrorPrefix           // the ip_only rows on a prefix, longest first
	byIP   map[string][]mirrorEntry // every row naming one address, any scope: the JA4-less check
	n      int
}

func newMirror() *mirror {
	return &mirror{
		tuple: map[string][]mirrorEntry{},
		ja4:   map[string][]mirrorEntry{},
		ip:    map[string][]mirrorEntry{},
		byIP:  map[string][]mirrorEntry{},
	}
}

// effectiveScope is the scope a row enforces under, from its columns: the
// stored scope when its key field is there, else the one the key fields
// imply (a legacy row without a scope; an ip_ja4 row missing one side, whose
// file line has the shape of the other scope anyway).
func effectiveScope(ip, ja4, scope string) string {
	switch scope {
	case ScopeJA4Only:
		if ja4 != "" {
			return ScopeJA4Only
		}
	case ScopeIPOnly:
		if ip != "" {
			return ScopeIPOnly
		}
	}
	return DeriveScope(ip, ja4)
}

// banKey is the key the ban file carries for a row, the module's bsearch
// handle: "<ip>|<ja4>" for the tuple, "|<ja4>" for a fingerprint alone,
// "<ip>|" for an address or a prefix alone.
func banKey(ip, ja4, scope string) string {
	switch effectiveScope(ip, ja4, scope) {
	case ScopeJA4Only:
		return "|" + ja4
	case ScopeIPOnly:
		return ip + "|"
	default:
		return ip + "|" + ja4
	}
}

// add files e under its key.  e.scope is the effective scope.
func (mr *mirror) add(e mirrorEntry) {
	switch e.scope {
	case ScopeJA4Only:
		mr.ja4[e.ja4] = append(mr.ja4[e.ja4], e)
	case ScopeIPOnly:
		if p, ok := parsePrefixKey(e.ip); ok {
			mr.prefix = append(mr.prefix, mirrorPrefix{prefix: p, e: e})
			// Longest prefix first: the more specific row wins, as in the module.
			sort.SliceStable(mr.prefix, func(i, j int) bool { return mr.prefix[i].prefix.Bits() > mr.prefix[j].prefix.Bits() })
			mr.n++
			return
		}
		mr.ip[e.ip] = append(mr.ip[e.ip], e)
	default:
		mr.tuple[e.ip+"|"+e.ja4] = append(mr.tuple[e.ip+"|"+e.ja4], e)
	}
	if e.ip != "" {
		mr.byIP[e.ip] = append(mr.byIP[e.ip], e)
	}
	mr.n++
}

// remove takes out the entries on the upsert's key (ip, ja4, scope).
func (mr *mirror) remove(ip, ja4, scope string) {
	same := func(e mirrorEntry) bool { return e.ip == ip && e.ja4 == ja4 && e.scope == scope }
	drop := func(m map[string][]mirrorEntry, key string) {
		list := m[key]
		kept := list[:0]
		for _, e := range list {
			if same(e) {
				mr.n--
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(m, key)
		} else {
			m[key] = kept
		}
	}
	switch scope {
	case ScopeJA4Only:
		drop(mr.ja4, ja4)
	case ScopeIPOnly:
		if _, ok := parsePrefixKey(ip); ok {
			kept := mr.prefix[:0]
			for _, mp := range mr.prefix {
				if same(mp.e) {
					mr.n--
					continue
				}
				kept = append(kept, mp)
			}
			mr.prefix = kept
			return
		}
		drop(mr.ip, ip)
	default:
		drop(mr.tuple, ip+"|"+ja4)
	}
	if ip != "" {
		// byIP is the second index of the same rows: not counted twice.
		n := mr.n
		drop(mr.byIP, ip)
		mr.n = n
	}
}

// put replaces the entries on e's key with e, as the table's upsert does.
func (mr *mirror) put(e mirrorEntry) {
	mr.remove(e.ip, e.ja4, e.scope)
	mr.add(e)
}

// first returns the first entry of list in force at now that skip does not
// rule out.
func first(list []mirrorEntry, now int64, skip func(*mirrorEntry) bool) (mirrorEntry, bool) {
	for i := range list {
		e := &list[i]
		if !e.live(now) || (skip != nil && skip(e)) {
			continue
		}
		return *e, true
	}
	return mirrorEntry{}, false
}

// match finds the ban in force on a request, in the module's order: the
// tuple, the fingerprint alone, the address alone, then the prefixes (the
// longest first).  A request without a fingerprint -- forward-auth with no
// TLS data, a page asking whether an address is banned at all -- takes any
// row naming the address, as the table lookup did, then the prefixes.
func (mr *mirror) match(ip, ja4 string, now int64, skip func(*mirrorEntry) bool) (mirrorEntry, bool) {
	if ja4 != "" {
		if e, ok := first(mr.tuple[ip+"|"+ja4], now, skip); ok {
			return e, true
		}
		if e, ok := first(mr.ja4[ja4], now, skip); ok {
			return e, true
		}
		if e, ok := first(mr.ip[ip], now, skip); ok {
			return e, true
		}
	} else if e, ok := first(mr.byIP[ip], now, skip); ok {
		return e, true
	}
	if len(mr.prefix) > 0 {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return mirrorEntry{}, false
		}
		for i := range mr.prefix {
			mp := &mr.prefix[i]
			if !mp.e.live(now) || (skip != nil && skip(&mp.e)) {
				continue
			}
			b := a
			if b.Is4In6() && mp.prefix.Addr().Is4() {
				b = b.Unmap()
			}
			if mp.prefix.Contains(b) {
				return mp.e, true
			}
		}
	}
	return mirrorEntry{}, false
}

// loadMirror reads the live rows of the table into a new mirror and installs
// it, and returns them in the file's order for the writer.  One load at a
// time, so two cannot install each other's older picture.
func (m *Manager) loadMirror() ([]mirrorEntry, error) {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	now := time.Now().Unix()
	rows, err := m.DB.QueryContext(context.Background(),
		`SELECT id, ip, ja4, source, action, scope, COALESCE(banned_by,''), banned_at, expires_at FROM unmask_ban
		 WHERE expires_at = 0 OR expires_at > ?
		 ORDER BY ip, ja4, id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	lifted := m.liftedIDs()
	mr := newMirror()
	all := []mirrorEntry{}
	for rows.Next() {
		var e mirrorEntry
		if err := rows.Scan(&e.id, &e.ip, &e.ja4, &e.source, &e.action, &e.scope, &e.bannedBy, &e.bannedAt, &e.expiresAt); err != nil {
			return nil, err
		}
		if lifted[e.id] {
			continue // unbanned during a hold: out of the file and the checks from now
		}
		// A row written before the spelling was fixed at the door (Start
		// rewrites those once) still matches the request's spelling.
		e.ip = normalizeIP(e.ip)
		e.scope = effectiveScope(e.ip, e.ja4, e.scope)
		mr.add(e)
		all = append(all, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	m.mirrorMu.Lock()
	m.mirror = mr
	m.mirrorMu.Unlock()
	return all, nil
}

// ensureMirror loads the mirror when none is installed yet (a manager
// before its first flush).  Reports whether one is there now.
func (m *Manager) ensureMirror() bool {
	m.mirrorMu.RLock()
	have := m.mirror != nil
	m.mirrorMu.RUnlock()
	if have {
		return true
	}
	if m.DB == nil {
		return false
	}
	if _, err := m.loadMirror(); err != nil {
		log.Printf("ban: loading the ban list into memory: %v", err)
		return false
	}
	return true
}

// mirrorPut files a ban just written to the table (or kept for it), so the
// checks see it before the next load.  A manager with no mirror yet loads
// one instead: the table has the row.
func (m *Manager) mirrorPut(e mirrorEntry) {
	e.ip = normalizeIP(e.ip)
	e.scope = effectiveScope(e.ip, e.ja4, e.scope)
	m.mirrorMu.Lock()
	if m.mirror == nil {
		m.mirrorMu.Unlock()
		m.ensureMirror()
		return
	}
	m.mirror.put(e)
	m.mirrorMu.Unlock()
}

// reloadMirror rebuilds the mirror from the table after a change the
// manager cannot apply in place (a row edited or deleted, the kept bans
// written).
func (m *Manager) reloadMirror() {
	if m.DB == nil {
		return
	}
	if _, err := m.loadMirror(); err != nil {
		log.Printf("ban: reloading the ban list into memory: %v", err)
	}
}

// mirrorMatch answers the check from memory.  loaded is false when there is
// no mirror to ask (the table could not be read), found when a ban is in
// force on (ip, ja4).  A row lifted during a hold and an automatic ban on a
// CDN's egress do not hold, as in the file.
func (m *Manager) mirrorMatch(ip, ja4 string) (e mirrorEntry, found, loaded bool) {
	if !m.ensureMirror() {
		return mirrorEntry{}, false, false
	}
	lifted := m.liftedIDs()
	skip := func(e *mirrorEntry) bool {
		if lifted != nil && e.id != 0 && lifted[e.id] {
			return true
		}
		if e.bannedBy == "" && e.ip != "" {
			if _, ok := m.isEgress(e.ip); ok {
				return true
			}
		}
		return false
	}
	now := time.Now().Unix()
	m.mirrorMu.RLock()
	defer m.mirrorMu.RUnlock()
	e, found = m.mirror.match(ip, ja4, now, skip)
	return e, found, true
}

// MirrorSize is the number of live bans held in memory, for diagnostics.
func (m *Manager) MirrorSize() int {
	if m == nil {
		return 0
	}
	m.mirrorMu.RLock()
	defer m.mirrorMu.RUnlock()
	if m.mirror == nil {
		return 0
	}
	return m.mirror.n
}

// recentlyPlaced reports whether an automatic ban on (ip, ja4), from the
// same source and with the same action, is in force and was written within
// the refresh interval: the client tripped the trap again.  The row is not
// rewritten, the file not written again, nothing announced -- a banned
// scanner that keeps probing used to cost an upsert, a full write of the
// file and a notification at every hit.  Counted (RepeatedTrips).
func (m *Manager) recentlyPlaced(ip, ja4, source, action string, now int64) bool {
	scope := DeriveScope(ip, ja4)
	since := now - int64(m.refreshInterval()/time.Second)
	fresh := func(e mirrorEntry) bool {
		return e.ip == ip && e.ja4 == ja4 && e.scope == scope && e.source == source && e.action == action &&
			e.bannedBy == "" && e.bannedAt > since && e.live(now)
	}
	m.mu.Lock()
	for _, h := range m.held {
		if fresh(mirrorEntry{ip: h.ip, ja4: h.ja4, scope: effectiveScope(h.ip, h.ja4, h.scope), source: h.source,
			action: h.action, bannedBy: h.bannedBy, bannedAt: h.bannedAt, expiresAt: h.expiresAt}) {
			m.mu.Unlock()
			return true
		}
	}
	m.mu.Unlock()
	m.mirrorMu.RLock()
	defer m.mirrorMu.RUnlock()
	if m.mirror == nil {
		return false
	}
	var list []mirrorEntry
	switch scope {
	case ScopeJA4Only:
		list = m.mirror.ja4[ja4]
	case ScopeIPOnly:
		list = m.mirror.ip[ip]
	default:
		list = m.mirror.tuple[ip+"|"+ja4]
	}
	for _, e := range list {
		if fresh(e) {
			return true
		}
	}
	return false
}

// refreshInterval is how often a repeated trip rewrites an automatic ban's
// row (its banned_at and expiry): once an hour, or half the ban's lifetime
// when that is shorter, so a short ban is still extended by a client that
// keeps tripping.
func (m *Manager) refreshInterval() time.Duration {
	const refreshEvery = time.Hour
	if m.duration > 0 && m.duration/2 < refreshEvery {
		return m.duration / 2
	}
	return refreshEvery
}

// RepeatedTrips is how many automatic bans were asked for on a client
// already banned the same way since the daemon started, for diagnostics.
func (m *Manager) RepeatedTrips() uint64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.repeatTrips
}

// escalate64 widens a run of automatic bans on addresses of one IPv6 /64 to
// the /64 itself.  A /64 is the smallest allocation a host or a customer
// gets, and a client that walks its interface identifiers arrives with a
// fresh address, a fresh pass budget and a fresh ban each time, so the bans
// never catch up with it.  Three distinct addresses of one /64 banned
// inside a day is one client, not a neighbourhood; from then on the /64 is
// banned whatever address it presents, with the action and for as long as
// the ban that tipped it.  One row per /64: one already in force is left.
const (
	prefix64EscalateMin    = 3
	prefix64EscalateWindow = 24 * time.Hour
)

func (m *Manager) escalate64(ctx context.Context, ip, source, action string, now, expires int64) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
		return
	}
	p := netip.PrefixFrom(a, 64).Masked()
	key := p.String()
	since := now - int64(prefix64EscalateWindow/time.Second)
	m.mirrorMu.RLock()
	mr := m.mirror
	have := false
	addrs := map[string]bool{}
	if mr != nil {
		for i := range mr.prefix {
			if mr.prefix[i].prefix == p && mr.prefix[i].e.live(now) {
				have = true
				break
			}
		}
		if !have {
			for addr, list := range mr.byIP {
				if b, err := netip.ParseAddr(addr); err != nil || !p.Contains(b) {
					continue
				}
				for i := range list {
					if e := &list[i]; e.bannedBy == "" && e.bannedAt >= since && e.live(now) {
						addrs[addr] = true
						break
					}
				}
			}
		}
	}
	m.mirrorMu.RUnlock()
	if have || len(addrs) < prefix64EscalateMin {
		return
	}
	// The module reads the ban list before the bypass: a /64 that shares
	// an address with the operator's allowlist would take that address
	// with it.  The allowlist test reads a prefix as "overlaps any range".
	if m.isWhitelisted(key) {
		m.mu.Lock()
		say := time.Since(m.skip64LoggedAt) > time.Minute
		if say {
			m.skip64LoggedAt = time.Now()
		}
		m.mu.Unlock()
		if say {
			log.Printf("ban: /64 escalation of %s skipped: overlaps a bypass range", key)
		}
		return
	}
	reason := fmt.Sprintf("escalated: %d addresses in the same /64 were banned within a day", len(addrs))
	if err := m.upsertWithin(ctx, autoBanWriteWithin, key, "", source, reason, now, expires, "", action, ScopeIPOnly); err != nil {
		return
	}
	m.mirrorPut(mirrorEntry{ip: key, scope: ScopeIPOnly, source: source, action: action, bannedAt: now, expiresAt: expires})
	m.markDirty()
	m.requestFlush()
	if m.OnCreated != nil {
		m.OnCreated(key, "", source, reason, "")
	}
}
