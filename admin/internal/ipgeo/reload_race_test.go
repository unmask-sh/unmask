package ipgeo

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestReloadDuringLookups: lookups keep running while the databases are
// swapped underneath them.  Reload used to close the mmdb reader while a
// lookup held its pointer, with the lookups outside the lock: a read of
// the unmapped file.  Run under -race, this is the test that saw it.
func TestReloadDuringLookups(t *testing.T) {
	geo, asn := testCountryDB(t), testASNDB(t)
	r := Open(geo, asn)
	defer r.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				ip := fmt.Sprintf("203.0.113.%d", (i+g)%256)
				info := r.LookupInfo(ip)
				if info.Country != "" && info.Country != "JP" {
					t.Errorf("%s: country %q", ip, info.Country)
					return
				}
				if n, _ := r.LookupASN(ip); n != 0 && n != 64500 {
					t.Errorf("%s: asn %d", ip, n)
					return
				}
				r.LookupBytes([]byte{198, 51, 100, byte(i)})
				r.Loaded()
				r.ASNLoaded()
			}
		}(g)
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		// The clear-then-reload the auto-update does, so the files are
		// closed and opened again although their paths are the same.
		r.Reload("", "")
		r.Reload(geo, asn)
		r.SuggestASN("Example", 3)
	}
	close(stop)
	wg.Wait()
	if got := r.LookupInfo("203.0.113.1"); got.Country != "JP" || got.ASN != 64500 {
		t.Fatalf("after the reloads: %+v", got)
	}
}

// TestLookupAfterClose: a closed reader answers empty instead of reaching
// into a file that is no longer mapped.
func TestLookupAfterClose(t *testing.T) {
	r := Open(testCountryDB(t), testASNDB(t))
	if got := r.LookupInfo("203.0.113.1"); got.Country != "JP" {
		t.Fatalf("before close: %+v", got)
	}
	r.Close()
	if got := r.LookupInfo("203.0.113.2"); got.Country != "" || got.ASN != 0 {
		t.Fatalf("after close: %+v", got)
	}
	if r.Loaded() || r.ASNLoaded() {
		t.Fatal("a closed reader still reports its databases loaded")
	}
}
