package settings

import "strings"

// HostingProvider: one entry in the built-in catalog of well-known cloud /
// VPS / hosting / bulletproof networks.  An operator enables a provider (with
// an action) instead of hunting down its AS numbers by hand -- one provider
// spans many ASNs (Microsoft/Azure alone is a dozen+), so the match is by the
// autonomous-system ORGANIZATION name, not a hard-coded AS-number list that
// would go stale.  OrgPatterns are case-insensitive substrings tested against
// the ASN mmdb's autonomous_system_organization field.  ASNs is the exception,
// for a provider whose networks carry a name it shares with networks it does
// not run.
//
// This same catalog powers three things: the preset table (enable a provider),
// the "block all data centers" bulk action (enable them all), and the
// autocomplete suggestions on the custom org-rule input.
type HostingProvider struct {
	ID          string   // stable identifier (config + UI); never renamed
	Label       string   // display name
	OrgPatterns []string // case-insensitive org-name substrings that identify this provider
	ASNs        []uint   // AS numbers that are the provider's whatever the ASN database calls them
	Aliases     []string // brand/nickname terms ABSENT from the org name (Azure, GCP, AWS...) -- used only to match a suggest query to this provider, never for the block decision
	AddedIn     string   // release the provider joined the catalog (v-form); drives the "NEW" badge
	UpdatedIn   string   // last release that changed its patterns ("updated vX"); shown only
}

// Matches reports whether a network -- its AS number and organization name --
// belongs to the provider.
func (hp HostingProvider) Matches(asn uint, org string) bool {
	if asn != 0 {
		for _, n := range hp.ASNs {
			if n == asn {
				return true
			}
		}
	}
	return OrgMatchesAny(org, hp.OrgPatterns)
}

// HostingProviders: the built-in catalog.  Order is UI display order (roughly
// by prevalence as a scraper source).  Patterns are deliberately broad enough
// to catch a provider's sub-brands but specific enough not to collide with
// unrelated orgs.  Verified against DB-IP and GeoLite2 ASN org strings.
// asnCatalogInitial: the release the first ASN provider catalog shipped in.
// Providers carrying this AddedIn are the founding batch; later additions get
// a newer version so an upgrading operator sees a "NEW" badge only on the
// genuinely-new entries.
const asnCatalogInitial = "v0.1.11"

var HostingProviders = []HostingProvider{
	{ID: "amazon", Label: "Amazon AWS", OrgPatterns: []string{"Amazon", "AWS"}, Aliases: []string{"AWS", "EC2", "Lightsail"}, AddedIn: asnCatalogInitial},
	{ID: "microsoft", Label: "Microsoft / Azure", OrgPatterns: []string{"Microsoft"}, Aliases: []string{"Azure"}, AddedIn: asnCatalogInitial},
	{ID: "google", Label: "Google Cloud", OrgPatterns: []string{"Google"}, Aliases: []string{"GCP", "GCE"}, AddedIn: asnCatalogInitial},
	{ID: "digitalocean", Label: "DigitalOcean", OrgPatterns: []string{"DigitalOcean"}, AddedIn: asnCatalogInitial},
	{ID: "ovh", Label: "OVH", OrgPatterns: []string{"OVH"}, AddedIn: asnCatalogInitial},
	{ID: "hetzner", Label: "Hetzner", OrgPatterns: []string{"Hetzner"}, AddedIn: asnCatalogInitial},
	// Linode is Akamai's cloud now, and the ASN databases name it after the
	// parent: GeoLite2 calls AS63949 "Akamai Connected Cloud", DB-IP "Akamai
	// Technologies, Inc." -- the name DB-IP gives Akamai's content-delivery
	// networks too, the ones most of Apple's iCloud Private Relay leaves from.
	// A bare "Akamai" pattern took in every one of them, so a site that turned
	// the provider on challenged the iPhones and Macs behind the relay.  The
	// AS number finds Linode under either name; "Akamai Connected Cloud" keeps
	// any network the cloud adds under its own.
	{ID: "linode", Label: "Linode / Akamai Cloud", OrgPatterns: []string{"Linode", "Akamai Connected Cloud"}, ASNs: []uint{63949}, AddedIn: asnCatalogInitial, UpdatedIn: "v0.1.51"},
	// Vultr operates as "The Constant Company"; "Choopa" is its former name (still
	// seen on legacy allocations) -- folded here so it is one provider, not two.
	{ID: "vultr", Label: "Vultr", OrgPatterns: []string{"Vultr", "Constant Company", "Choopa"}, Aliases: []string{"Choopa"}, AddedIn: asnCatalogInitial},
	{ID: "oracle", Label: "Oracle Cloud", OrgPatterns: []string{"Oracle"}, Aliases: []string{"OCI"}, AddedIn: asnCatalogInitial},
	{ID: "alibaba", Label: "Alibaba Cloud", OrgPatterns: []string{"Alibaba", "Aliyun"}, Aliases: []string{"Aliyun"}, AddedIn: asnCatalogInitial},
	{ID: "tencent", Label: "Tencent Cloud", OrgPatterns: []string{"Tencent"}, AddedIn: asnCatalogInitial},
	{ID: "huawei", Label: "Huawei Cloud", OrgPatterns: []string{"Huawei"}, AddedIn: asnCatalogInitial},
	{ID: "contabo", Label: "Contabo", OrgPatterns: []string{"Contabo"}, AddedIn: asnCatalogInitial},
	{ID: "leaseweb", Label: "Leaseweb", OrgPatterns: []string{"Leaseweb", "LeaseWeb"}, AddedIn: asnCatalogInitial},
	{ID: "scaleway", Label: "Scaleway / Online SAS", OrgPatterns: []string{"Scaleway", "Online SAS", "Online S.a.s."}, AddedIn: asnCatalogInitial},
	{ID: "ibm", Label: "IBM Cloud / SoftLayer", OrgPatterns: []string{"SoftLayer", "IBM Cloud"}, Aliases: []string{"SoftLayer"}, AddedIn: asnCatalogInitial},
	{ID: "gcore", Label: "G-Core", OrgPatterns: []string{"G-Core", "Gcore"}, AddedIn: asnCatalogInitial},
	{ID: "kamatera", Label: "Kamatera", OrgPatterns: []string{"Kamatera"}, AddedIn: asnCatalogInitial},
	{ID: "psychz", Label: "Psychz Networks", OrgPatterns: []string{"Psychz"}, AddedIn: asnCatalogInitial},
	// ColoCrossing was acquired by HostPapa; the ASN databases now carry the
	// parent's name on its networks (AS36352 etc.), so the pattern must match
	// "HostPapa" -- "ColoCrossing" no longer appears and counted 0.
	{ID: "colocrossing", Label: "ColoCrossing / HostPapa", OrgPatterns: []string{"HostPapa"}, AddedIn: asnCatalogInitial},
	{ID: "quadranet", Label: "QuadraNet", OrgPatterns: []string{"QuadraNet"}, AddedIn: asnCatalogInitial},
	{ID: "m247", Label: "M247", OrgPatterns: []string{"M247"}, AddedIn: asnCatalogInitial},
}

// ProvidersMatchingQuery returns catalog providers whose ID, label, or brand
// alias contains the query (case-insensitive).  This is the bridge that lets an
// operator type a product/brand name the ASN mmdb does not carry in its org
// strings -- "azure" -> Microsoft, "gcp" -> Google, "aws" -> Amazon -- so the
// suggest endpoint can expand the query to the provider's real OrgPatterns.
// OrgPatterns themselves are intentionally NOT matched here: those are real
// org-name substrings, already found by the raw mmdb search.
func ProvidersMatchingQuery(q string) []HostingProvider {
	ql := strings.ToLower(strings.TrimSpace(q))
	if ql == "" {
		return nil
	}
	var out []HostingProvider
	for _, hp := range HostingProviders {
		if strings.Contains(strings.ToLower(hp.ID), ql) || strings.Contains(strings.ToLower(hp.Label), ql) {
			out = append(out, hp)
			continue
		}
		for _, a := range hp.Aliases {
			if strings.Contains(strings.ToLower(a), ql) {
				out = append(out, hp)
				break
			}
		}
	}
	return out
}

// hostingProviderByID: lookup helper.
func HostingProviderByID(id string) *HostingProvider {
	for i := range HostingProviders {
		if HostingProviders[i].ID == id {
			return &HostingProviders[i]
		}
	}
	return nil
}

// OrgMatchesAny reports whether org (the ASN's organization name) contains any
// of the given case-insensitive patterns.  Shared by the decision path
// (forward-auth) and the render walk (native).
func OrgMatchesAny(org string, patterns []string) bool {
	if org == "" {
		return false
	}
	low := strings.ToLower(org)
	for _, p := range patterns {
		if p != "" && strings.Contains(low, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
