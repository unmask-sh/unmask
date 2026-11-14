package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/nginxpath"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// nginxDumpRealIP is the nginx configuration checkRealIPFrom reads, in the
// form `nginx -T` prints it.  nginx -T itself when it answers; it does not as
// a rule, because doctor drops to the daemon's user before it runs and nginx
// -T needs root to read the host's keys -- so, failing that, the files read
// directly (nginxConfFilesDump).  A variable so the tests can hand it a dump.
var nginxDumpRealIP = func(s settings.Settings) string {
	if nginxBin, err := exec.LookPath("nginx"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, _ := exec.CommandContext(ctx, nginxBin, "-T").Output()
		cancel()
		if strings.Contains(string(out), "# configuration file ") {
			return string(out)
		}
	}
	return nginxConfFilesDump(nginxpath.ConfPath(s.Nginx.ConfPath))
}

// nginxConfFilesDump reads nginx.conf and what it includes, four levels
// down, and lays them out as nginx -T does: each file whole, under a
// "# configuration file <path>:" line.  Without nginx and without root --
// files the daemon's user cannot read are left out, as are include paths
// that use variables.  A relative include is taken from nginx.conf's
// directory, nginx's default prefix for it.
func nginxConfFilesDump(confPath string) string {
	var b strings.Builder
	seen := map[string]bool{}
	base := filepath.Dir(confPath)
	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		if depth > 4 || seen[path] {
			return
		}
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		b.WriteString("# configuration file " + path + ":\n")
		b.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			b.WriteByte('\n')
		}
		for _, ln := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(ln, '#'); i >= 0 {
				ln = ln[:i]
			}
			for _, stmt := range strings.Split(ln, ";") {
				f := strings.Fields(stmt)
				if len(f) != 2 || f[0] != "include" {
					continue
				}
				arg := strings.Trim(f[1], `"'`)
				if !filepath.IsAbs(arg) {
					arg = filepath.Join(base, arg)
				}
				matches, _ := filepath.Glob(arg)
				for _, m := range matches {
					walk(m, depth+1)
				}
			}
		}
	}
	walk(confPath, 0)
	return b.String()
}

// realIPFrom is one set_real_ip_from of the loaded configuration.
type realIPFrom struct {
	value string       // as written
	file  string       // the file nginx -T shows it in
	line  int          // its line in that file
	pfx   netip.Prefix // the range; not valid for unix: and host names
}

// realIPFromEntries finds every set_real_ip_from in an `nginx -T` dump, with
// its file and line.  nginx -T prints each file whole after a
// "# configuration file <path>:" line, so counting from there gives the
// line in the file.
func realIPFromEntries(dump string) []realIPFrom {
	var out []realIPFrom
	file, n := "", 0
	for _, ln := range strings.Split(dump, "\n") {
		if rest, ok := strings.CutPrefix(ln, "# configuration file "); ok {
			file, n = strings.TrimSuffix(rest, ":"), 0
			continue
		}
		n++
		if i := strings.IndexByte(ln, '#'); i >= 0 {
			ln = ln[:i]
		}
		for _, stmt := range strings.Split(ln, ";") {
			f := strings.Fields(stmt)
			if len(f) != 2 || f[0] != "set_real_ip_from" {
				continue
			}
			e := realIPFrom{value: strings.Trim(f[1], `"'`), file: file, line: n}
			e.pfx = parsePrefixOrAddr(e.value)
			out = append(out, e)
		}
	}
	return out
}

// parsePrefixOrAddr reads a CIDR, or a lone address as its own /32 or /128;
// the zero Prefix for anything else.
func parsePrefixOrAddr(v string) netip.Prefix {
	v = strings.TrimSpace(v)
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked()
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return netip.PrefixFrom(a, a.BitLen())
	}
	return netip.Prefix{}
}

// realIPInternal: ranges nobody on the internet sends from -- the host's
// own, private networks, shared address space.  A proxy there is the
// operator's, so trusting it is not this check's business.
var realIPInternal = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// prefixWithin: every address of p is inside one of the ranges.
func prefixWithin(p netip.Prefix, ranges []netip.Prefix) bool {
	for _, r := range ranges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// lbPrefixes: the ranges of the given load balancer entries and the
// addresses they put into X-Forwarded-For as their own (XFFHops) --
// together, what unmask's own real_ip lists name.
func lbPrefixes(lbs []nginxconf.LBIPRange) []netip.Prefix {
	var out []netip.Prefix
	for _, lb := range lbs {
		for _, groups := range [][]string{lb.CIDRs, lb.XFFHops} {
			for _, c := range groups {
				if p := parsePrefixOrAddr(c); p.IsValid() {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// realIPPresetOff names the preset a range falls in when that preset is off:
// most likely what the operator meant to tell unmask as well.  "" for none.
func realIPPresetOff(p netip.Prefix, n settings.Nginx) string {
	on := map[string]bool{}
	for _, id := range n.TrustedLBPresets {
		on[id] = true
	}
	for _, preset := range nginxconf.LBIPRanges {
		if on[preset.ID] {
			continue
		}
		full := nginxconf.EffectiveLBs(settings.Nginx{TrustedLBPresets: []string{preset.ID}})
		if prefixWithin(p, lbPrefixes(full)) {
			return preset.Label
		}
	}
	return ""
}

// checkRealIPFrom holds the ranges nginx trusts for the visitor's address to
// the load balancers unmask is told about.  A set_real_ip_from in a server
// block replaces, for that server, the list unmask renders at http level
// (and unmask renders none when the configuration declares real_ip_header:
// HostDeclaresRealIPHeader), so the operator's own list is the one that
// runs.  A public range in it that is wider than the load balancer lets a
// client there choose the address unmask sees with X-Forwarded-For: get
// another address banned through a trap, slip a rate limit.  Loopback and
// private ranges are the host's own and are not judged; unix: and host
// names cannot be.  Says nothing when the configuration cannot be read.
func checkRealIPFrom(s settings.Settings, addOK, addWarn func(t, m string)) {
	entries := realIPFromEntries(nginxDumpRealIP(s))
	if len(entries) == 0 {
		return
	}
	trusted := lbPrefixes(nginxconf.EffectiveLBs(s.Nginx))
	type badRange struct{ where, preset string }
	var bad []badRange
	for _, e := range entries {
		if !e.pfx.IsValid() || prefixWithin(e.pfx, realIPInternal) || prefixWithin(e.pfx, trusted) {
			continue
		}
		bad = append(bad, badRange{fmt.Sprintf("%s (%s:%d", e.value, e.file, e.line), realIPPresetOff(e.pfx, s.Nginx)})
	}
	if len(bad) == 0 {
		addOK("nginx real_ip ranges", fmt.Sprintf("%d set_real_ip_from, each loopback/private or a trusted load balancer's", len(entries)))
		return
	}
	// Grouped by the preset they fall in, each preset said once: the ranges
	// in none come first -- enabling a preset does not cover them.
	var order []string
	byPreset := map[string][]string{}
	for _, b := range bad {
		if _, ok := byPreset[b.preset]; !ok {
			if b.preset == "" {
				order = append([]string{""}, order...)
			} else {
				order = append(order, b.preset)
			}
		}
		byPreset[b.preset] = append(byPreset[b.preset], b.where+")")
	}
	var parts []string
	shown := 0
	for _, preset := range order {
		items := byPreset[preset]
		if room := 5 - shown; len(items) > room {
			items = items[:room]
		}
		if len(items) == 0 {
			break
		}
		shown += len(items)
		part := strings.Join(items, ", ")
		if preset != "" {
			part += fmt.Sprintf(" [in the %q preset, which is off]", preset)
		}
		parts = append(parts, part)
	}
	tail := ""
	if len(bad) > shown {
		tail = fmt.Sprintf(" and %d more", len(bad)-shown)
	}
	addWarn("nginx real_ip ranges", fmt.Sprintf("nginx believes X-Forwarded-For from %s%s, outside the trusted load balancers unmask knows (Settings > Network): a client in such a range chooses the address unmask sees -- it can get another address banned or slip a rate limit. Narrow each to the load balancer's own addresses, or add them to unmask as a trusted load balancer.", strings.Join(parts, "; "), tail))
}
