package communitybans

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ja4KeyRE is the shape of a JA4 string as the map files may carry it:
// the 10-character "a" part (t/q, TLS version, SNI flag, cipher and
// extension counts, ALPN), then the two 12-hex-digit hashes.
//
// The feed is fetched over TLS from the hub and nothing else vouches for its
// content, and the entries become KEYS of an nginx map that nginx loads as
// root.  Quoting alone does not make a key inert: a quoted "default" is still
// the map's default, "~..." is still a regex, "include ..." still an include.
// A feed that could say those would turn every subscribed install at once --
// everyone challenged, nginx refusing to start, a pathological regex on every
// request.  So an entry is written only when its address parses as one and
// its JA4 has exactly this shape; anything else is dropped and counted.
var ja4KeyRE = regexp.MustCompile(`^[tq][0-9a-z]{9}_[0-9a-f]{12}_[0-9a-f]{12}$`)

// mapKeyIP returns the address in its canonical text form, or "" when the
// value is not a single address.  The map matches $remote_addr literally, so
// a prefix, a port or a zone would never hit anyway; canonical text also
// keeps "1.2.3.4" and "001.2.3.4" from becoming two keys.
func mapKeyIP(v string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil || a.Zone() != "" {
		return ""
	}
	return a.String()
}

// mapKeyJA4 returns the JA4 when it has the shape the map may carry, else "".
func mapKeyJA4(v string) string {
	v = strings.TrimSpace(v)
	if !ja4KeyRE.MatchString(v) {
		return ""
	}
	return v
}

// The legacy on-disk WriteDocument/ReadDocument pair (= persisted
// community-bans-doc.json) was retired in favour of Client.cachedDoc /
// Client.GetCachedDoc().  nginx never read the file, and admin restart is
// rare enough that an in-memory cache is sufficient.

// ensureMapPlaceholders lays down empty community-bans map files in dir when
// they do not exist yet, so http.inc's `include community-bans-*.map` directives
// resolve before the very first successful pull.  A later pull overwrites them;
// the existence check means a populated map is never clobbered.  This is what
// keeps `nginx -t` (and nginx startup) from aborting on a fresh install whose
// first fetch fails -- e.g. the hub is unreachable or the box is offline.
func ensureMapPlaceholders(dir string) {
	if dir == "" {
		return
	}
	if _, err := os.Stat(filepath.Join(dir, MapFileIPJA4)); os.IsNotExist(err) {
		_ = WriteMapFiles(FeedDocument{GeneratedAt: time.Now().Unix()}, dir)
	}
}

// WriteMapFiles: split feed entries across 3 nginx map snippets and atomic-write.
//
// Output:
//
//	community-bans-ipja4.map  ← match=ip_ja4  : `"<ip>:<ja4>" 1;`
//	community-bans-ja4.map    ← match=ja4_only: `"<ja4>"      1;`
//	community-bans-ip.map     ← match=ip_only : `"<ip>"       1;`
//
// nginx includes them via map ${key} ${var} { default 0; include ...; } to
// drive the hit check, and the forward-auth matcher loads the same files.
//
// Only promoted entries go in: the hub decides what is enforced, and the rest
// of the feed is listed for browsing.  An entry without the flag -- whatever
// the document's version -- is never enforced.
//
// Always generates all 3 files even on empty feed (= avoids nginx startup
// failure on missing include).
func WriteMapFiles(doc FeedDocument, dir string) error {
	if dir == "" {
		return fmt.Errorf("WriteMapFiles: empty dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	now := time.Now().Unix()

	var ipja4, ja4, ip []string
	dropped := 0
	for _, e := range doc.Entries {
		if e.ExpiresAt > 0 && e.ExpiresAt < now {
			continue
		}
		if !e.Promoted {
			continue
		}
		// Shape-checked before they become map keys (see ja4KeyRE): an
		// entry the hub could not have produced is dropped, not quoted.
		ipv := mapKeyIP(e.IP)
		j := mapKeyJA4(e.JA4)
		switch e.Match {
		case MatchIPJA4:
			if ipv == "" || j == "" {
				dropped++
				continue
			}
			ipja4 = append(ipja4, fmt.Sprintf("%q 1;", ipv+":"+j))
		case MatchJA4:
			if j == "" {
				dropped++
				continue
			}
			ja4 = append(ja4, fmt.Sprintf("%q 1;", j))
		case MatchIPOnly:
			if ipv == "" {
				dropped++
				continue
			}
			ip = append(ip, fmt.Sprintf("%q 1;", ipv))
		}
	}
	if dropped > 0 {
		log.Printf("communitybans: %d promoted entries dropped from the map files: address or JA4 not in the expected shape", dropped)
	}
	sort.Strings(ipja4)
	sort.Strings(ja4)
	sort.Strings(ip)

	if err := atomicWriteLines(filepath.Join(dir, MapFileIPJA4), ipja4); err != nil {
		return err
	}
	if err := atomicWriteLines(filepath.Join(dir, MapFileJA4), ja4); err != nil {
		return err
	}
	if err := atomicWriteLines(filepath.Join(dir, MapFileIP), ip); err != nil {
		return err
	}
	return nil
}

// atomicWriteLines: atomic via tmp file + rename.  Sorted duplicates are uniq'd.
func atomicWriteLines(path string, lines []string) error {
	var b strings.Builder
	b.WriteString("# generated by unmask communitybans. DO NOT EDIT.\n")
	last := ""
	for _, l := range lines {
		if l == last {
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
		last = l
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s → %s: %w", tmp, path, err)
	}
	return nil
}
