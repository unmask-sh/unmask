// LB (= Load Balancer / CDN) IP range presets.
//
// When an SSL-terminating LB sits in front, nginx only sees the JA4 of
// the LB <-> backend TLS.  To get the real client JA4 the LB must
// forward it via a header, but a spoofed header coming directly to the
// server is dangerous, so we need a defense that "accepts the header
// only from trusted LB IPs."  This file presets that IP range list per
// vendor.
//
// In nginx-rendered.conf this expands to a `geo $unmask_lb_<vendor>` block
// so a user can simply write something like
//
//	if ($unmask_lb_gcp = 1) { set $effective_ja4 $http_x_client_ja4; }
//
// IP ranges are release snapshots (= updated manually).  The vendor's
// official source is referenced from the Source field of each entry.
// Automatic update is planned for a future `unmask update-iprange`.
package nginxconf

import (
	"net"
	"regexp"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// NginxVarFromHeader: normalize an HTTP header name (e.g. "Cf-Ja4" /
// "X-Client-JA4") to nginx variable notation (e.g. "$http_cf_ja4").
// Values already in nginx variable notation are returned as-is.  Empty
// stays empty.
//
// Use case: convert what the user types as an HTTP header name in the
// settings UI into a form usable inside nginx-rendered.conf, and store
// it (= storage is unified on nginx variable notation).
// httpHeaderVarRE matches a clean nginx $http_ variable.  NginxVarFromHeader's
// result is emitted unquoted into a map directive, so anything outside this
// shape (spaces, ';', '}', newlines) must be rejected or a custom LB header
// could break out into arbitrary http-scope config.
var httpHeaderVarRE = regexp.MustCompile(`^\$http_[a-z0-9_]+$`)

func NginxVarFromHeader(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "$http_") {
		s = strings.ToLower(s)
	} else {
		s = strings.TrimPrefix(s, "$")
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, "-", "_")
		s = "$http_" + s
	}
	// Reject anything that isn't a clean $http_<name>; the value goes into an
	// unquoted nginx map directive (= injection guard, see httpHeaderVarRE).
	if !httpHeaderVarRE.MatchString(s) {
		return ""
	}
	return s
}

// HeaderFromNginxVar: convert "$http_cf_ja4" back to "Cf-JA4" (= for UI display).
// Values that aren't in nginx variable notation are returned as-is.
//
// Conventional acronyms (= JA4 / JA3 / IP etc.) are displayed in uppercase.
func HeaderFromNginxVar(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "$http_") {
		return s
	}
	name := strings.TrimPrefix(s, "$http_")
	parts := strings.Split(name, "_")
	for i, p := range parts {
		parts[i] = titleHeaderSeg(p)
	}
	return strings.Join(parts, "-")
}

// titleHeaderSeg: format one segment of a header name for display.  Use
// the acronym map if it hits, otherwise title-case with the first letter
// uppered.
func titleHeaderSeg(s string) string {
	if s == "" {
		return s
	}
	if up, ok := headerAcronyms[s]; ok {
		return up
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

var headerAcronyms = map[string]string{
	"ja4": "JA4",
	"ja3": "JA3",
	"ip":  "IP",
	"ua":  "UA",
	"uri": "URI",
	"url": "URL",
	"id":  "ID",
}

// IsTrustedLBIP: returns whether the source IP is in the user-configured
// trusted LB list.  Evaluates the merge of the presets (= vendors enabled
// via TrustedLBPresets) and extras.
//
// Use case: the IP filter on the forward-auth mode handler side
// (= decides whether to trust X-Client-JA4).  Prevents header spoofing
// from a direct-access (= non-LB) request.
//
// The returned vendor is "gcp" / "cloudflare" / the extras' id etc.
// Returns "" when not trusted.
func IsTrustedLBIP(ip string, n settings.Nginx) (trusted bool, vendor string) {
	if ip == "" {
		return false, ""
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false, ""
	}
	for _, p := range effectiveLBs(n.TrustedLBPresets, n.TrustedLBExtra) {
		for _, cidr := range p.CIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ipnet.Contains(parsed) {
				return true, p.ID
			}
		}
	}
	return false, ""
}

// EffectiveLBCIDRs returns the flat CIDR list across every enabled preset +
// custom extra in n.  Used by callers outside this package that need the
// same trust list — primarily the forward-auth admin peer check, which reuses
// the native-mode LB list so an operator configures one place instead of two.
func EffectiveLBCIDRs(n settings.Nginx) []string {
	lbs := effectiveLBs(n.TrustedLBPresets, n.TrustedLBExtra)
	out := make([]string, 0, len(lbs)*4)
	for _, p := range lbs {
		out = append(out, p.CIDRs...)
	}
	return out
}

// effectiveLBs: return the merged list of user-enabled presets + custom
// extras.  Both empty -> empty (= trust no LB.  secure default).  Extras
// win on ID collisions.
func effectiveLBs(enabledIDs []string, extras []settings.TrustedLBExtra) []LBIPRange {
	on := map[string]bool{}
	for _, id := range enabledIDs {
		on[id] = true
	}
	out := make([]LBIPRange, 0, len(enabledIDs)+len(extras))
	for _, p := range LBIPRanges {
		if !on[p.ID] || len(p.CIDRs) == 0 {
			continue
		}
		out = append(out, p)
	}
	for _, e := range extras {
		if e.ID == "" || len(e.CIDRs) == 0 || e.Disabled {
			continue
		}
		hdr := e.Header
		if hdr == "" {
			hdr = "$http_x_client_ja4"
		}
		label := e.Label
		if label == "" {
			label = e.ID
		}
		// Override a preset with the same ID (= when the user wants to
		// override IP / header on their side).
		replaced := false
		for i, p := range out {
			if p.ID == e.ID {
				out[i] = LBIPRange{ID: e.ID, Label: label, Source: "(custom)", Header: hdr, CIDRs: e.CIDRs}
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, LBIPRange{ID: e.ID, Label: label, Source: "(custom)", Header: hdr, CIDRs: e.CIDRs})
		}
	}
	return out
}

// LBIPRange: trusted LB IP ranges for one vendor.
type LBIPRange struct {
	ID     string   // internal ID (= "gcp" / "cloudflare" etc.).  Becomes the value of $unmask_lb_vendor.
	Label  string   // UI display name (= e.g. "GCP HTTPS Load Balancer")
	Source string   // distribution URL (= the snapshot's origin.  for the user to look up an updated list)
	Header string   // the nginx variable this vendor puts JA4 in (= "$http_x_client_ja4" / "$http_cf_ja4" etc.)
	CIDRs  []string // mixed IPv4 / IPv6.  goes directly into a geo directive.
	// AddedIn: release this vendor joined the catalog (v-form).  Drives the
	// settings UI "since vX.Y.Z" label + NEW badge, like every other preset.
	// Empty is defaulted to "v0.1.0" in data.go's init().
	AddedIn string
}

// LBIPRanges: per-vendor IP range snapshots.  Add to this list by appending.
//
// **Important**: the CIDRs listed here are **IPs reserved for the vendor's
// LB infrastructure**.  The vendor officially guarantees these ranges are
// not assigned to customer compute (= GCE instances / EC2 instances /
// customer VPCs).  Users sometimes worry "if I put a bot on GCP at
// 35.191.*, I can attack from here," but **35.191.0.0/16 etc. are not
// handed out to customers**, so that's impossible.
//
// In addition, this IP filter assumes **defense in depth with firewall
// rules**.  Without a firewall protecting nginx from direct access, an
// attacker can spoof their IP as 35.191.* and break through (= unreachable
// through normal routing, but depending on the path it is possible).
//
// Snapshot date: 2026-05-08 (= each vendor's official list at release time).
var LBIPRanges = []LBIPRange{
	{
		ID:     "gcp",
		Label:  "GCP HTTPS Load Balancer (Global / Regional)",
		Source: "https://cloud.google.com/load-balancing/docs/https#health-check-firewall-rules",
		Header: "$http_x_client_ja4", // the convention of issuing X-Client-JA4 via gcloud's custom_request_header
		CIDRs: []string{
			// Source IPs that GCP HTTPS LB uses to forward to backends.
			// The same range issues the GCP health checks.
			// **Not assigned to customer instances** (= reserved for GCP infra).
			"35.191.0.0/16",
			"130.211.0.0/22",
			"35.227.0.0/16",
			// IPv6 (= added after 2024).  See official docs.
			"2600:1901:8001::/48",
			"2600:2d00:1:1::/64",
			"2600:2d00:1:b029::/64",
		},
	},
	{
		ID:     "cloudflare",
		Label:  "Cloudflare (CDN / WAF)",
		Source: "https://www.cloudflare.com/ips/",
		Header: "$http_cf_ja4", // read Cloudflare's native cf-ja4 header directly
		CIDRs: []string{
			// IPv4
			"173.245.48.0/20",
			"103.21.244.0/22",
			"103.22.200.0/22",
			"103.31.4.0/22",
			"141.101.64.0/18",
			"108.162.192.0/18",
			"190.93.240.0/20",
			"188.114.96.0/20",
			"197.234.240.0/22",
			"198.41.128.0/17",
			"162.158.0.0/15",
			"104.16.0.0/13",
			"104.24.0.0/14",
			"172.64.0.0/13",
			"131.0.72.0/22",
			// IPv6
			"2400:cb00::/32",
			"2606:4700::/32",
			"2803:f800::/32",
			"2405:b500::/32",
			"2405:8100::/32",
			"2a06:98c0::/29",
			"2c0f:f248::/32",
		},
	},
	{
		ID:     "aws_cloudfront",
		Label:  "AWS CloudFront (edge POP egress to origin)",
		Source: "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips",
		Header: "$http_x_client_ja4", // CloudFront itself has no native JA4 feature.  Assumes the user injects X-Client-JA4 via e.g. Lambda@Edge.
		CIDRs: []string{
			// Source IP range of CloudFront edge -> origin traffic (snapshot).
			// The CIDR count is large and changes often, so for production
			// strongly recommend fetching the JSON automatically.
			"3.5.140.0/22",
			"3.5.36.0/25",
			"13.32.0.0/15",
			"13.224.0.0/14",
			"54.182.0.0/16",
			"54.192.0.0/16",
			"54.230.0.0/16",
			"54.239.128.0/18",
			"54.239.192.0/19",
			"99.84.0.0/16",
			"99.86.0.0/16",
			"108.138.0.0/15",
			"143.204.0.0/16",
			"205.251.192.0/19",
			"216.137.32.0/19",
		},
	},
	{
		ID:     "aws_alb",
		Label:  "AWS ALB / ELB (all regions. The right answer is to use your own VPC subnets.)",
		Source: "https://ip-ranges.amazonaws.com/ip-ranges.json",
		Header: "$http_x_client_ja4",
		CIDRs:  []string{
			// ALB calls the backend with VPC-internal IPs, so a global
			// CIDR list is unnecessary.  Users should normally specify
			// the internal subnets of the same VPC as the ALB / ELB.
			// This preset is intentionally empty to prevent misuse.
		},
	},
}
