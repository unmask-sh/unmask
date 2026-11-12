package nginxconf

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
)

// loadedPrefix picks one loaded prefix of a preset as a netip.Prefix: the
// first IPv4 one (wantV6 false) or the first IPv6 one.  The addresses under
// test come from the range data itself, so a refresh of the shipped files
// does not date the test.
func loadedPrefix(t *testing.T, preset string, wantV6 bool) (netip.Prefix, bool) {
	t.Helper()
	for _, s := range FlattenBypassPresets([]string{preset}) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is6() == wantV6 && !p.Addr().Is4In6() {
			return p.Masked(), true
		}
	}
	return netip.Prefix{}, false
}

// lastAddr is the highest address inside p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// A crawler's name answers "published" when some UARangePresets pattern folds
// to it, and a request is in range when its address is inside the ranges
// loaded for the presets behind that pattern.
func TestCrawlerVendorRange(t *testing.T) {
	bing := classify.CrawlerNameFromPattern(`bingbot`)
	p, ok := loadedPrefix(t, "bing", false)
	if !ok {
		t.Fatal("the bing preset loaded no IPv4 prefix; embed broken?")
	}
	for _, addr := range []netip.Addr{p.Addr(), lastAddr(p)} {
		if pub, in := CrawlerVendorRange(bing, addr.String()); !pub || !in {
			t.Errorf("%s at %s (inside %s): published=%v inRange=%v, want both", bing, addr, p, pub, in)
		}
		// The same address as nginx may log it for a dual-stack listener.
		mapped := "::ffff:" + addr.String()
		if pub, in := CrawlerVendorRange(bing, mapped); !pub || !in {
			t.Errorf("%s at %s: published=%v inRange=%v, want both (a v4-mapped address is the IPv4 one)", bing, mapped, pub, in)
		}
	}
	// TEST-NET-1 is nobody's crawler.
	if pub, in := CrawlerVendorRange(bing, "192.0.2.1"); !pub || in {
		t.Errorf("%s at 192.0.2.1: published=%v inRange=%v, want published and out of range", bing, pub, in)
	}
	// One vendor's ranges do not vouch for another's name.
	gpt := classify.CrawlerNameFromPattern(`GPTBot`)
	if pub, in := CrawlerVendorRange(gpt, p.Addr().String()); !pub || in {
		t.Errorf("%s at a bing address: published=%v inRange=%v, want published and out of range", gpt, pub, in)
	}
	// An address that says nothing.
	for _, ip := range []string{"", "not-an-address", "192.0.2.1/24", "203.0.113.300"} {
		if pub, in := CrawlerVendorRange(bing, ip); !pub || in {
			t.Errorf("%s at %q: published=%v inRange=%v, want published and out of range", bing, ip, pub, in)
		}
	}
	// A crawler whose vendor publishes nothing, and no crawler at all.
	for _, name := range []string{"Yeti", "other", ""} {
		if pub, in := CrawlerVendorRange(name, p.Addr().String()); pub || in {
			t.Errorf("%q: published=%v inRange=%v, want neither", name, pub, in)
		}
	}
}

// The union of a vendor's files backs each of its names, IPv6 included: a
// Google crawler is in range from any of the three lists.
func TestCrawlerVendorRangeUnionAndIPv6(t *testing.T) {
	googlebot := classify.CrawlerNameFromPattern(`Googlebot\/`)
	for _, preset := range googleRangePresets {
		p, ok := loadedPrefix(t, preset, false)
		if !ok {
			continue
		}
		if pub, in := CrawlerVendorRange(googlebot, p.Addr().String()); !pub || !in {
			t.Errorf("%s at %s (preset %s): published=%v inRange=%v, want both", googlebot, p.Addr(), preset, pub, in)
		}
	}
	p6, ok := loadedPrefix(t, "google-common", true)
	if !ok {
		t.Skip("google-common loaded no IPv6 prefix")
	}
	for _, addr := range []netip.Addr{p6.Addr(), lastAddr(p6)} {
		if _, in := CrawlerVendorRange(googlebot, addr.String()); !in {
			t.Errorf("%s at %s (inside %s): out of range", googlebot, addr, p6)
		}
	}
	if _, in := CrawlerVendorRange(googlebot, "2001:db8::1"); in {
		t.Error("the documentation prefix 2001:db8::/32 is in Google's ranges")
	}
}

// Every name UARangePresets folds to is published, and nothing else of the
// crawler list is: the CSV's range_published column and the verified count
// both stand on it.
func TestCrawlerVendorRangeCoversEveryRangePattern(t *testing.T) {
	for pat := range UARangePresets {
		name := classify.CrawlerNameFromPattern(pat)
		if name == "" || name == "other" {
			t.Errorf("pattern %q folds to no crawler name", pat)
			continue
		}
		if pub, _ := CrawlerVendorRange(name, ""); !pub {
			t.Errorf("pattern %q folds to %q, which is not reported as published", pat, name)
		}
	}
}

// The ranges answer for the request, whichever presets the operator enabled:
// the function takes no settings, and its index is rebuilt when the ranges
// are loaded again (a pull, an override file) -- what was in range under the
// old list is out under the new one, and the reverse.
func TestCrawlerVendorRangeFollowsAReload(t *testing.T) {
	bing := classify.CrawlerNameFromPattern(`bingbot`)
	SetOverrideDir("")
	Reload()
	shipped, ok := loadedPrefix(t, "bing", false)
	if !ok {
		t.Fatal("the bing preset loaded no IPv4 prefix; embed broken?")
	}
	if _, in := CrawlerVendorRange(bing, shipped.Addr().String()); !in {
		t.Fatalf("%s is out of range at %s before the reload", bing, shipped.Addr())
	}
	if _, in := CrawlerVendorRange(bing, "198.51.100.7"); in {
		t.Fatal("TEST-NET-2 is in the shipped bing ranges")
	}

	// A pulled copy the vendor dated now, holding one documentation block.
	dir := t.TempDir()
	body := `{"creationTime":"` + time.Now().UTC().Format("2006-01-02T15:04:05.000000") + `","prefixes":[{"ipv4Prefix":"198.51.100.0/24"},{"ipv6Prefix":"2001:db8:77::/48"}]}`
	if err := os.WriteFile(filepath.Join(dir, "bingbot.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	SetOverrideDir(dir)
	t.Cleanup(func() {
		SetOverrideDir("")
		Reload()
	})
	if _, in := CrawlerVendorRange(bing, "198.51.100.7"); !in {
		t.Error("after the reload 198.51.100.7 is out of range: the index was not rebuilt")
	}
	if _, in := CrawlerVendorRange(bing, "2001:db8:77:1::9"); !in {
		t.Error("after the reload 2001:db8:77:1::9 is out of range")
	}
	if _, in := CrawlerVendorRange(bing, shipped.Addr().String()); in {
		t.Errorf("after the reload %s is still in range: the old index answered", shipped.Addr())
	}
	// Another vendor's index was dropped with it and built again from its
	// own, unchanged, list.
	gpt := classify.CrawlerNameFromPattern(`GPTBot`)
	if g, ok := loadedPrefix(t, "openai-gptbot", false); ok {
		if _, in := CrawlerVendorRange(gpt, g.Addr().String()); !in {
			t.Errorf("%s is out of range at %s after another vendor's reload", gpt, g.Addr())
		}
	}
}

// The index holds the prefixes as the range files write them: CIDR blocks of
// either family, bare hosts, v4-mapped blocks; and what does not parse is
// left out without taking the rest with it.
func TestPrefixIndex(t *testing.T) {
	x := newPrefixIndex([]string{
		"198.51.100.0/24", "203.0.113.64/26", "203.0.113.9",
		"2001:db8:1::/48", "2001:db8:2::5", "::ffff:192.0.2.0/120",
		"", "garbage", "198.51.100.0/33",
		" 192.0.2.200/31 ", // host bits set, and padded
	})
	for ip, want := range map[string]bool{
		"198.51.100.0":         true,
		"198.51.100.255":       true,
		"198.51.101.0":         false,
		"203.0.113.64":         true,
		"203.0.113.127":        true,
		"203.0.113.128":        false,
		"203.0.113.9":          true,
		"203.0.113.10":         false,
		"192.0.2.77":           true, // the v4-mapped block, asked in IPv4
		"::ffff:192.0.2.77":    true, // and as the mapped address
		"::ffff:198.51.100.20": true,
		"192.0.2.200":          true,
		"192.0.2.201":          true,
		"2001:db8:1:ffff::1":   true,
		"2001:db8:2::5":        true,
		"2001:db8:2::6":        false,
		"2001:db8:3::1":        false,
		"fe80::1%eth0":         false,
	} {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("test address %q: %v", ip, err)
		}
		if got := x.contains(addr); got != want {
			t.Errorf("contains(%s) = %v, want %v", ip, got, want)
		}
	}
	if (*prefixIndex)(nil).contains(netip.MustParseAddr("192.0.2.1")) || x.contains(netip.Addr{}) {
		t.Error("a nil index or a zero address answered true")
	}
	// A lookup is one probe per prefix length present, not one per prefix:
	// a vendor's list of over a thousand prefixes has a handful of lengths.
	big := make([]string, 0, 2048)
	for i := 0; i < 2048; i++ {
		big = append(big, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}).String()+"/24")
	}
	if bx := newPrefixIndex(big); len(bx.v4) != 1 || len(bx.v6) != 0 || !bx.contains(netip.MustParseAddr("10.7.255.9")) {
		t.Errorf("2048 /24 blocks: %d IPv4 lengths, %d IPv6 lengths (want 1 and 0), or a member not found", len(bx.v4), len(bx.v6))
	}
}

// The reader's worker and the CSV handler ask at the same time, while a pull
// may be replacing the ranges under them (run under -race).  Whatever the
// timing, an address is never in range for a name without published ranges
// and never in range from outside every list; and once the reloads have
// stopped, the answer is the list's again -- an index is only kept when it
// was built from the list of the generation it is kept under.
func TestCrawlerVendorRangeConcurrent(t *testing.T) {
	bing := classify.CrawlerNameFromPattern(`bingbot`)
	names := []string{
		bing,
		classify.CrawlerNameFromPattern(`Googlebot\/`),
		classify.CrawlerNameFromPattern(`GPTBot`),
		"Yeti",
	}
	p, ok := loadedPrefix(t, "bing", false)
	if !ok {
		t.Fatal("the bing preset loaded no IPv4 prefix; embed broken?")
	}
	inside := p.Addr().String()
	ips := []string{inside, "192.0.2.1", "2001:db8::1", ""}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				name, ip := names[(g+i)%len(names)], ips[i%len(ips)]
				pub, in := CrawlerVendorRange(name, ip)
				if pub != (name != "Yeti") {
					t.Errorf("%s: published=%v", name, pub)
				}
				if in && (!pub || ip != inside || name != bing) {
					t.Errorf("%s at %q: in range", name, ip)
				}
			}
		}(g)
	}
	for i := 0; i < 30; i++ {
		Reload() // the ranges are loaded again: every index is dropped
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if _, in := CrawlerVendorRange(bing, inside); !in {
		t.Errorf("%s at %s is out of range once the reloads have stopped: an index of a half-loaded list was kept", bing, inside)
	}
}
