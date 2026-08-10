package communitybans

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Map file names.  WriteMapFiles produces them; LoadMatcher reads them back.
const (
	MapFileIPJA4 = "community-bans-ipja4.map"
	MapFileJA4   = "community-bans-ja4.map"
	MapFileIP    = "community-bans-ip.map"
)

// Match kinds reported by Matcher.Hit -- mirrors the feed's MatchIPJA4 /
// MatchJA4 / MatchIPOnly so a decision reason names the same thing the
// "共有 BAN" tab shows for the entry.
const (
	HitKindIPJA4 = "ip_ja4"
	HitKindJA4   = "ja4_only"
	HitKindIP    = "ip_only"
)

// Matcher answers "is this client on the enforceable community feed?" for the
// code paths nginx's map lookups cannot serve: the forward-auth decision (an
// Apache / fa-nginx node has no community-bans maps at all) and ServeChallenge
// (which needs the reason and the chain, not just a yes/no).
//
// It is built by parsing the very map files nginx includes rather than from
// the feed document, so the two enforcement surfaces cannot drift: whatever
// nginx blocks, the daemon blocks, byte for byte.  That also makes the answer
// survive a daemon restart with an unreachable hub -- the files on disk are
// the persisted enforcement state, already filtered for bypassed crawlers and
// local mutes.
//
// Keys are compared literally, exactly as nginx compares them.  An IP written
// in a non-canonical form by whoever reported it misses in both places
// identically, which is the property worth having.
//
// A nil *Matcher is a valid empty matcher (= never hits), so callers holding
// an un-initialised client need no guard.
type Matcher struct {
	ipja4 map[string]struct{}
	ja4   map[string]struct{}
	ip    map[string]struct{}
}

// LoadMatcher reads the three map files in dir.  A missing file is treated as
// empty (= a fresh install before the first pull), so the only errors returned
// are real read failures.
func LoadMatcher(dir string) (*Matcher, error) {
	m := &Matcher{
		ipja4: map[string]struct{}{},
		ja4:   map[string]struct{}{},
		ip:    map[string]struct{}{},
	}
	if strings.TrimSpace(dir) == "" {
		return m, nil
	}
	for _, f := range []struct {
		name string
		set  map[string]struct{}
	}{
		{MapFileIPJA4, m.ipja4},
		{MapFileJA4, m.ja4},
		{MapFileIP, m.ip},
	} {
		if err := loadMapKeys(filepath.Join(dir, f.name), f.set); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// loadMapKeys parses `"<key>" 1;` lines into set.  Anything else on the line
// (blank, comment, malformed) is skipped: the file is machine-written, and a
// partial read must never be louder than the enforcement it describes.
func loadMapKeys(path string, set map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Feed keys are short (an ipja4 key tops out near 80 bytes), but a
	// corrupted file must not blow the default 64KiB token limit into a
	// scanner error that hides every valid line after it.
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		// The key is a Go-quoted string (WriteMapFiles emits it with %q);
		// strconv.Unquote is its exact inverse.
		end := strings.LastIndex(line, `"`)
		if end <= 0 {
			continue
		}
		key, err := strconv.Unquote(line[:end+1])
		if err != nil || key == "" {
			continue
		}
		set[key] = struct{}{}
	}
	return sc.Err()
}

// Hit reports whether the client is on the feed, and under which match kind.
// ip_ja4 is checked first, then ja4_only, then ip_only -- most specific first,
// so the reason names the narrowest rule that caught the request.
func (m *Matcher) Hit(ip, ja4 string) (string, bool) {
	if m == nil {
		return "", false
	}
	if ip != "" && ja4 != "" {
		if _, ok := m.ipja4[ip+":"+ja4]; ok {
			return HitKindIPJA4, true
		}
	}
	if ja4 != "" {
		if _, ok := m.ja4[ja4]; ok {
			return HitKindJA4, true
		}
	}
	if ip != "" {
		if _, ok := m.ip[ip]; ok {
			return HitKindIP, true
		}
	}
	return "", false
}

// Len returns the number of enforceable keys, for logging and the admin UI.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.ipja4) + len(m.ja4) + len(m.ip)
}
