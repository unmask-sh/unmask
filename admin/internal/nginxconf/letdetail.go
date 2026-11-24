package nginxconf

import (
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// LetDetail names what a bypass matched, for the admin's list of requests the
// site answered without a challenge (nginxlog/let_through.go): the range an
// address is in, the bypass path row a path matches.  nginx decides the
// bypass and logs that it did (why=ip / why=path); which preset or which row
// it was is worked out here, from the settings the render was made of -- so
// the geo and the maps keep their "0" / "1" and are not drawn twice.
//
// A preset is named by its id ("google-common", "static-assets"); a row of
// the operator's own by LetDetailOwn and its title, or the range or pattern
// itself where it has none.  The operator's rows are tried first: an address
// in both is theirs to answer for.  "" when nothing matches -- the render
// nginx runs may be older than these settings.
type LetDetail struct {
	ips   []letDetailRange
	paths []letDetailPath

	mu    sync.Mutex
	cache map[string]string // address -> label, up to letDetailCacheMax
}

// LetDetailOwn prefixes the detail of an operator's own row.
const LetDetailOwn = "list:"

// letDetailCacheMax: the addresses whose range is remembered.  A crawler's
// ranges run to thousands of prefixes and its addresses repeat all day.
const letDetailCacheMax = 4096

type letDetailRange struct {
	net   *net.IPNet
	label string
}

type letDetailPath struct {
	re    *regexp.Regexp
	site  string // "" = every host
	label string
}

// NewLetDetail compiles the bypass ranges and bypass paths of n.  The
// statistics exclusions are left out: nginx does not log their requests.  A
// path pattern Go's regexp does not read (nginx's is PCRE) is left out too,
// and its requests are listed with no row named.
func NewLetDetail(n settings.Nginx) *LetDetail {
	d := &LetDetail{cache: map[string]string{}}
	for i, raw := range n.BypassIPs {
		if i < len(n.BypassIPsDisabled) && n.BypassIPsDisabled[i] {
			continue
		}
		raw = strings.TrimSpace(raw)
		label := raw
		if i < len(n.BypassIPsTitle) && strings.TrimSpace(n.BypassIPsTitle[i]) != "" {
			label = strings.TrimSpace(n.BypassIPsTitle[i])
		}
		d.addRange(raw, LetDetailOwn+label)
	}
	for _, id := range EffectiveBypassIPPresets(n) {
		g := bypassIPGroupByID(id)
		if g == nil {
			continue
		}
		for _, p := range g.Prefixes() {
			d.addRange(p, id)
		}
	}
	for _, r := range n.BypassPaths.Paths {
		p := trimPattern(r.Path)
		if r.Disabled || p == "" {
			continue
		}
		label := p
		if strings.TrimSpace(r.Title) != "" {
			label = strings.TrimSpace(r.Title)
		}
		d.addPath(p, strings.TrimSpace(r.Site), LetDetailOwn+label)
	}
	enabled := EffectiveBypassPathPresets(n.BypassPaths.EnabledPresets, n.BypassPaths.DisabledPresets)
	for _, g := range BypassPathPresetGroups {
		if !enabled[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			d.addPath(r.Pattern, r.Site, g.ID)
		}
	}
	return d
}

func (d *LetDetail) addRange(s, label string) {
	if s == "" {
		return
	}
	if _, nw, err := net.ParseCIDR(s); err == nil {
		d.ips = append(d.ips, letDetailRange{nw, label})
		return
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return
	}
	bits := 128
	if v4 := ip.To4(); v4 != nil {
		ip, bits = v4, 32
	}
	d.ips = append(d.ips, letDetailRange{&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, label})
}

func (d *LetDetail) addPath(pattern, site, label string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return
	}
	d.paths = append(d.paths, letDetailPath{re, site, label})
}

// IP names the bypass range ip is in, "" when it is in none.
func (d *LetDetail) IP(ip string) string {
	if d == nil || ip == "" {
		return ""
	}
	d.mu.Lock()
	label, ok := d.cache[ip]
	d.mu.Unlock()
	if ok {
		return label
	}
	if pip := net.ParseIP(ip); pip != nil {
		for _, r := range d.ips {
			if r.net.Contains(pip) {
				label = r.label
				break
			}
		}
	}
	d.mu.Lock()
	if len(d.cache) >= letDetailCacheMax {
		d.cache = map[string]string{}
	}
	d.cache[ip] = label
	d.mu.Unlock()
	return label
}

// Path names the bypass path row that matches path on host, "" when none
// does.  path is the request's path as nginx logged it: up to the query, and
// possibly cut short.
func (d *LetDetail) Path(host, path string) string {
	if d == nil || path == "" {
		return ""
	}
	for _, p := range d.paths {
		if p.site != "" && !strings.EqualFold(p.site, host) {
			continue
		}
		if p.re.MatchString(path) {
			return p.label
		}
	}
	return ""
}
