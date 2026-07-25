package crawlerverify

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeResolver returns canned PTR / forward answers and counts calls (to prove
// caching skips DNS).
type fakeResolver struct {
	ptr     map[string][]string // ip -> hostnames
	fwd     map[string][]string // host -> ips
	ptrErr  map[string]error
	fwdErr  map[string]error
	addrHit int
	hostHit int
}

func (f *fakeResolver) LookupAddr(_ context.Context, ip string) ([]string, error) {
	f.addrHit++
	if e := f.ptrErr[ip]; e != nil {
		return nil, e
	}
	return f.ptr[ip], nil
}
func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.hostHit++
	if e := f.fwdErr[host]; e != nil {
		return nil, e
	}
	return f.fwd[host], nil
}

func newV(f *fakeResolver) *Verifier {
	v := New(f)
	// deterministic clock
	t := time.Unix(1_700_000_000, 0)
	v.now = func() time.Time { return t }
	return v
}

func TestVerify_GenuineGooglebot(t *testing.T) {
	f := &fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		fwd: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}},
	}
	r := newV(f).Verify(context.Background(), "66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	if r.Status != Verified || r.Crawler != "Googlebot" {
		t.Fatalf("got %+v, want Verified/Googlebot", r)
	}
}

func TestVerify_ForgedWrongPTRDomain(t *testing.T) {
	f := &fakeResolver{
		ptr: map[string][]string{"1.2.3.4": {"host.cheap-vps.example."}},
	}
	r := newV(f).Verify(context.Background(), "1.2.3.4", "Googlebot/2.1")
	if r.Status != Forged {
		t.Fatalf("got %+v, want Forged (PTR not a google domain)", r)
	}
	if f.hostHit != 0 {
		t.Errorf("forward lookup should be skipped when PTR domain doesn't match")
	}
}

func TestVerify_ForgedForwardMismatch(t *testing.T) {
	// PTR *looks* like google, but forward-confirm returns a different IP.
	f := &fakeResolver{
		ptr: map[string][]string{"1.2.3.4": {"x.googlebot.com"}},
		fwd: map[string][]string{"x.googlebot.com": {"9.9.9.9"}},
	}
	r := newV(f).Verify(context.Background(), "1.2.3.4", "Googlebot")
	if r.Status != Forged {
		t.Fatalf("got %+v, want Forged (forward-confirm failed)", r)
	}
}

func TestVerify_NotApplicable(t *testing.T) {
	f := &fakeResolver{}
	r := newV(f).Verify(context.Background(), "1.2.3.4", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0")
	if r.Status != NotApplicable {
		t.Fatalf("got %+v, want NotApplicable", r)
	}
	if f.addrHit != 0 {
		t.Errorf("no DNS should happen for a non-crawler UA")
	}
}

func TestVerify_UnresolvedOnPTRError(t *testing.T) {
	f := &fakeResolver{ptrErr: map[string]error{"1.2.3.4": errors.New("timeout")}}
	r := newV(f).Verify(context.Background(), "1.2.3.4", "bingbot/2.0")
	if r.Status != Unresolved || r.Crawler != "Bingbot" {
		t.Fatalf("got %+v, want Unresolved/Bingbot", r)
	}
}

func TestVerify_Bingbot(t *testing.T) {
	f := &fakeResolver{
		ptr: map[string][]string{"40.77.167.1": {"msnbot-40-77-167-1.search.msn.com"}},
		fwd: map[string][]string{"msnbot-40-77-167-1.search.msn.com": {"40.77.167.1"}},
	}
	r := newV(f).Verify(context.Background(), "40.77.167.1", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)")
	if r.Status != Verified || r.Crawler != "Bingbot" {
		t.Fatalf("got %+v, want Verified/Bingbot", r)
	}
}

func TestVerify_CacheHitSkipsDNS(t *testing.T) {
	f := &fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com"}},
		fwd: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}},
	}
	v := newV(f)
	_ = v.Verify(context.Background(), "66.249.66.1", "Googlebot")
	callsAddr, callsHost := f.addrHit, f.hostHit
	r := v.Verify(context.Background(), "66.249.66.1", "Googlebot")
	if r.Status != Verified {
		t.Fatalf("got %+v", r)
	}
	if f.addrHit != callsAddr || f.hostHit != callsHost {
		t.Errorf("second Verify should be served from cache (addr %d->%d, host %d->%d)", callsAddr, f.addrHit, callsHost, f.hostHit)
	}
}

func TestVerify_CacheExpires(t *testing.T) {
	f := &fakeResolver{ptrErr: map[string]error{"1.2.3.4": errors.New("timeout")}}
	v := New(f)
	base := time.Unix(1_700_000_000, 0)
	cur := base
	v.now = func() time.Time { return cur }
	_ = v.Verify(context.Background(), "1.2.3.4", "Googlebot") // Unresolved, ttlSoft=1m
	first := f.addrHit
	cur = base.Add(2 * time.Minute) // past ttlSoft
	_ = v.Verify(context.Background(), "1.2.3.4", "Googlebot")
	if f.addrHit == first {
		t.Errorf("expired soft cache should re-query DNS")
	}
}

func TestDomainMatch(t *testing.T) {
	if !domainMatch("crawl-1.googlebot.com.", []string{"googlebot.com"}) {
		t.Error("subdomain with trailing dot should match")
	}
	if !domainMatch("google.com", []string{"google.com"}) {
		t.Error("bare domain should match")
	}
	if domainMatch("notgooglebot.com", []string{"googlebot.com"}) {
		t.Error("must not match a domain that merely ends in the string without a dot boundary")
	}
	if domainMatch("evilgooglebot.com.attacker.net", []string{"googlebot.com"}) {
		t.Error("must not match when the domain is a mid-label, not a suffix")
	}
}
