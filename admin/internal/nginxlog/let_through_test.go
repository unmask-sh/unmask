package nginxlog

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/hll"
)

// letReader is cookieIPReader with the let-through buckets.
func letReader(t *testing.T) (*Reader, *db.DB) {
	t.Helper()
	r, d := cookieIPReader(t)
	r.letBuckets = map[letKey]*letBucket{}
	return r, d
}

// letLine is an access-log line as the configuration writes it now, with the
// fields a let-through line varies.
func letLine(ts int64, site, kind, ip, why, lp, ua string) string {
	fc := "0"
	if why == LetWatch {
		fc = "1"
	}
	return fmt.Sprintf("<134>%d.000 site=%s kind=%s fc=%s hp=0 ip=%s ja4=t13d1516h2_8daaf6152771_02713d6af862 hpuri= bp=0 scheme=https cr= pv=0 sb=0 sfs= sfd= rh= bv= bvid= mo= mc= why=%s lp=%s ua=%s",
		ts, site, kind, fc, ip, why, lp, ua)
}

// letFeed counts one line the way onLine does, without the buckets of the
// other tables (letReader has none of them).
func letFeed(t *testing.T, r *Reader, line string) {
	t.Helper()
	p, ok := r.parse(line)
	if !ok {
		t.Fatalf("the line did not parse: %s", line)
	}
	r.bumpLet(p.site, p)
}

type letTotal struct {
	cnt, addrs int
}

func readLetTotals(t *testing.T, d *db.DB) map[string]letTotal {
	t.Helper()
	rows, err := d.Query(`SELECT site, reason, detail, cnt, ips FROM unmask_let_hourly`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]letTotal{}
	for rows.Next() {
		var site, reason, detail string
		var cnt int
		var sk []byte
		if err := rows.Scan(&site, &reason, &detail, &cnt, &sk); err != nil {
			t.Fatal(err)
		}
		k := site + "|" + reason + "|" + detail
		if _, dup := out[k]; dup {
			t.Fatalf("two rows for %s (two hours in one test?)", k)
		}
		out[k] = letTotal{cnt: cnt, addrs: hll.Load(sk).Estimate()}
	}
	return out
}

type letAddrRow struct {
	cnt           int
	ja4, ua, path string
}

func readLetAddrs(t *testing.T, d *db.DB, reason, detail string) map[string]letAddrRow {
	t.Helper()
	rows, err := d.Query(`SELECT ip, cnt, ja4, ua, path FROM unmask_let_ip_hourly WHERE reason = ? AND detail = ?`, reason, detail)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]letAddrRow{}
	for rows.Next() {
		var ipb []byte
		var a letAddrRow
		if err := rows.Scan(&ipb, &a.cnt, &a.ja4, &a.ua, &a.path); err != nil {
			t.Fatal(err)
		}
		out[net.IP(ipb).String()] = a
	}
	return out
}

// TestParseWhyFields: the line carries why= and lp= ahead of the UA, and a
// line from a configuration without them still parses, with neither.
func TestParseWhyFields(t *testing.T) {
	r := &Reader{}
	p, ok := r.parse(letLine(1761700000, "s1.example", "", "203.0.113.9", "name", "/feed/latest", "Mozilla/5.0 (compatible; ExampleBot/1.0) why=x lp=/y"))
	if !ok {
		t.Fatal("the line with why= and lp= did not parse")
	}
	if p.why != "name" || p.lp != "/feed/latest" {
		t.Errorf("why=%q lp=%q", p.why, p.lp)
	}
	if p.ua != "Mozilla/5.0 (compatible; ExampleBot/1.0) why=x lp=/y" || p.ip != "203.0.113.9" || p.fc {
		t.Errorf("the fields around why= moved: ua=%q ip=%q fc=%v", p.ua, p.ip, p.fc)
	}
	// A line unmask answered: why is there and empty.
	p, ok = r.parse(letLine(1761700000, "s1.example", "", "203.0.113.9", "", "", "curl/8"))
	if !ok || p.why != "" || p.lp != "" || p.ua != "curl/8" {
		t.Errorf("an empty why=: ok=%v why=%q lp=%q ua=%q", ok, p.why, p.lp, p.ua)
	}
	// From a configuration rendered before the fields: a User-Agent that
	// spells them does not become them.
	old := "<134>1761700000.123 site=s1.example kind= fc=0 hp=0 ip=203.0.113.9 ja4=t13d_a hpuri= bp=0 scheme=https cr= pv=0 sb=0 sfs= sfd= rh= bv= bvid= mo= mc= ua=Bot why=ip lp=/admin"
	p, ok = r.parse(old)
	if !ok || p.why != "" || p.lp != "" || p.ua != "Bot why=ip lp=/admin" {
		t.Errorf("a line without the fields: ok=%v why=%q lp=%q ua=%q", ok, p.why, p.lp, p.ua)
	}
}

// TestLetThroughCountsByReason: each line the site answered without a
// challenge is counted under its reason and detail, and its address kept --
// except a pass cookie's, which is counted only.  A line unmask answered
// (why empty) is nobody's.
func TestLetThroughCountsByReason(t *testing.T) {
	r, d := letReader(t)
	r.classifyCrawler = func(ua string) string {
		if strings.Contains(ua, "ExampleBot") {
			return "search"
		}
		return ""
	}
	r.crawlerNamer = func(ua, tag string) string {
		if tag == "search" {
			return "ExampleBot"
		}
		return ""
	}
	r.SetLetThroughDetail(
		func(ip string) string {
			if strings.HasPrefix(ip, "198.51.100.") {
				return "list:office"
			}
			return ""
		},
		func(host, path string) string {
			if strings.HasPrefix(path, "/static/") {
				return "static-assets"
			}
			return ""
		})
	ts := time.Now().Unix()
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	for i := 0; i < 3; i++ {
		letFeed(t, r, letLine(ts, "a.example", "captcha", "203.0.113.1", LetCookie, "", browser))
	}
	letFeed(t, r, letLine(ts, "a.example", "pow", "203.0.113.2", LetCookie, "", browser))
	letFeed(t, r, letLine(ts, "a.example", "", "198.51.100.7", LetIP, "/page", browser))
	letFeed(t, r, letLine(ts, "a.example", "", "198.51.100.7", LetIP, "/other", browser))
	letFeed(t, r, letLine(ts, "a.example", "", "203.0.113.3", LetPath, "/static/app.js", browser))
	letFeed(t, r, letLine(ts, "a.example", "", "203.0.113.4", LetName, "/news/1", "Mozilla/5.0 (compatible; ExampleBot/1.0)"))
	letFeed(t, r, letLine(ts, "a.example", "", "203.0.113.4", LetName, "/news/2", "Mozilla/5.0 (compatible; ExampleBot/1.0)"))
	letFeed(t, r, letLine(ts, "a.example", "", "203.0.113.5", LetNone, "/admin", browser))
	letFeed(t, r, letLine(ts, "a.example", "", "203.0.113.6", "", "", browser)) // a challenge was served
	r.flushOnce(true)

	totals := readLetTotals(t, d)
	for k, want := range map[string]letTotal{
		"a.example|cookie|captcha":     {3, 1},
		"a.example|cookie|pow":         {1, 1},
		"a.example|ip|list:office":     {2, 1},
		"a.example|path|static-assets": {1, 1},
		"a.example|name|ExampleBot":    {2, 1},
		"a.example|none|":              {1, 1},
	} {
		if got := totals[k]; got != want {
			t.Errorf("%s: %+v, want %+v", k, got, want)
		}
	}
	if len(totals) != 6 {
		t.Errorf("%d total rows, want 6: %v", len(totals), totals)
	}
	if n := len(readLetAddrs(t, d, LetCookie, "captcha")); n != 0 {
		t.Errorf("%d addresses listed under a pass cookie; a pass is counted, not listed", n)
	}
	ip := readLetAddrs(t, d, LetIP, "list:office")
	if a := ip["198.51.100.7"]; a.cnt != 2 || a.path != "/other" || a.ua != browser || a.ja4 == "" {
		t.Errorf("the bypass address: %+v", a)
	}
	name := readLetAddrs(t, d, LetName, "ExampleBot")
	if a := name["203.0.113.4"]; a.cnt != 2 || a.path != "/news/2" {
		t.Errorf("the named crawler's address: %+v", a)
	}
	if a := readLetAddrs(t, d, LetNone, "")["203.0.113.5"]; a.cnt != 1 || a.path != "/admin" {
		t.Errorf("the address that got through on no ground: %+v", a)
	}

	// A second flush adds to the rows; nothing is counted twice.
	letFeed(t, r, letLine(ts, "a.example", "", "198.51.100.7", LetIP, "/third", browser))
	letFeed(t, r, letLine(ts, "a.example", "", "198.51.100.8", LetIP, "/page", browser))
	r.flushOnce(true)
	if got := readLetTotals(t, d)["a.example|ip|list:office"]; got != (letTotal{4, 2}) {
		t.Errorf("after the second flush: %+v, want 4 requests from 2 addresses", got)
	}
	ip = readLetAddrs(t, d, LetIP, "list:office")
	if ip["198.51.100.7"].cnt != 3 || ip["198.51.100.8"].cnt != 1 {
		t.Errorf("after the second flush: %+v", ip)
	}
}

// TestLetThroughPreviewIsNotANameAlone: pv=1 on a line let through by name
// says the configuration checked the fetcher's network too.
func TestLetThroughPreviewIsNotANameAlone(t *testing.T) {
	r, d := letReader(t)
	ts := time.Now().Unix()
	line := strings.Replace(letLine(ts, "a.example", "", "203.0.113.4", LetName, "/p", "PreviewBot/1"), " pv=0 ", " pv=1 ", 1)
	letFeed(t, r, line)
	r.flushOnce(true)
	totals := readLetTotals(t, d)
	if totals["a.example|preview|"].cnt != 1 || len(totals) != 1 {
		t.Errorf("a verified preview fetcher is filed as %v", totals)
	}
}

// TestLetThroughKeepsTheBusiestAddresses: a bucket keeps letAddrsPerKey
// addresses.  One that keeps coming stays in while a crowd of one-request
// addresses turns over beneath it; the row of an address pushed out is
// deleted; the totals count every request and every address.
func TestLetThroughKeepsTheBusiestAddresses(t *testing.T) {
	r, d := letReader(t)
	ts := time.Now().Unix()
	ua := "Mozilla/5.0 (compatible; ExampleBot/1.0)"
	addr := func(i int) string { return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255) }
	// The first crowd fills the bucket, and is written.
	for i := 0; i < letAddrsPerKey; i++ {
		letFeed(t, r, letLine(ts, "a.example", "", addr(i), LetName, "/x", ua))
	}
	r.flushOnce(true)
	if n := len(readLetAddrs(t, d, LetName, "")); n != letAddrsPerKey {
		t.Fatalf("%d rows after the first crowd, want %d", n, letAddrsPerKey)
	}
	// One address that keeps coming, among a second crowd three times the size.
	const heavy = "192.0.2.77"
	for i := 0; i < 3*letAddrsPerKey; i++ {
		letFeed(t, r, letLine(ts, "a.example", "", addr(1000+i), LetName, "/x", ua))
		if i%10 == 0 {
			letFeed(t, r, letLine(ts, "a.example", "", heavy, LetName, "/heavy", ua))
		}
	}
	r.flushOnce(true)
	rows := readLetAddrs(t, d, LetName, "")
	if len(rows) > letAddrsPerKey {
		t.Errorf("%d rows for one bucket, more than the %d it keeps", len(rows), letAddrsPerKey)
	}
	if got := rows[heavy]; got.cnt != 30 || got.path != "/heavy" {
		t.Errorf("the address that kept coming: %+v, want all 30 of its requests", got)
	}
	total := readLetTotals(t, d)["a.example|name|"]
	if want := letAddrsPerKey + 3*letAddrsPerKey + 30; total.cnt != want {
		t.Errorf("the bucket counts %d requests, want %d", total.cnt, want)
	}
	if lo, hi := 4*letAddrsPerKey*9/10, 4*letAddrsPerKey*11/10+1; total.addrs < lo || total.addrs > hi {
		t.Errorf("the bucket's sketch estimates %d addresses, want about %d", total.addrs, 4*letAddrsPerKey+1)
	}
}

// TestLetThroughABusyGroundKeepsARegular: on a ground thousands of addresses
// pass on once each, an address that has made a few requests of its own
// stays listed, with every request it goes on to make -- however far apart.
// The newcomers inherit the standing of the address they displace, and by
// that alone the crowd would climb past it; an address past letAddrSettled
// is not what makes room for them.
//
// What the list does not promise: an address whose requests are that few and
// each a full turnover of the bucket apart is displaced before its second
// one, and is in the bucket's totals only.
func TestLetThroughABusyGroundKeepsARegular(t *testing.T) {
	r, d := letReader(t)
	ts := time.Now().Unix()
	const regular, sparse = "192.0.2.88", "192.0.2.99"
	crowd := func(i int) string { return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255) }
	line := func(ip, path string) { letFeed(t, r, letLine(ts, "a.example", "", ip, LetNoGate, path, "ua")) }
	for i := 0; i <= letAddrSettled; i++ {
		line(regular, "/img/all.zip") // settled: letAddrSettled+1 requests of its own
	}
	for i := 0; i < 6000; i++ {
		line(crowd(i), "/img/x.png")
		if i%500 == 0 {
			line(regular, "/img/all.zip")
			line(sparse, "/img/one.png")
		}
		if i%1000 == 999 {
			r.flushOnce(true)
		}
	}
	r.flushOnce(true)
	rows := readLetAddrs(t, d, LetNoGate, "")
	if len(rows) > letAddrsPerKey {
		t.Errorf("%d rows for one bucket, more than the %d it keeps", len(rows), letAddrsPerKey)
	}
	if got, want := rows[regular].cnt, letAddrSettled+1+12; got != want {
		t.Errorf("the address past the mark is listed with %d of its %d requests", got, want)
	}
	if got := rows[sparse].cnt; got > 1 {
		t.Errorf("the address with one request per turnover is listed with %d: the limit this test describes has moved", got)
	}
	if total, want := readLetTotals(t, d)["a.example|nogate|"].cnt, 6000+letAddrSettled+1+12+12; total != want {
		t.Errorf("the bucket counts %d requests, want %d", total, want)
	}
}

// TestLetThroughFitsItsColumns: what the line carries is cut to the columns'
// widths (a longer value is refused by MariaDB's strict mode, and with it
// the whole flush).
func TestLetThroughFitsItsColumns(t *testing.T) {
	r, d := letReader(t)
	r.SetLetThroughDetail(func(string) string { return strings.Repeat("範", 100) }, nil)
	ts := time.Now().Unix()
	letFeed(t, r, letLine(ts, "a.example", "", "203.0.113.9", LetIP, "/"+strings.Repeat("p", 400), strings.Repeat("ü", 400)))
	letFeed(t, r, letLine(ts, "a.example", "", "203.0.113.9", strings.Repeat("z", 40), "/q", "ua"))
	r.flushOnce(true)
	rows, err := d.Query(`SELECT reason, detail, ua, path FROM unmask_let_ip_hourly`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
		var reason, detail, ua, path string
		if err := rows.Scan(&reason, &detail, &ua, &path); err != nil {
			t.Fatal(err)
		}
		if len([]rune(reason)) > letReasonWidth || len([]rune(detail)) > letDetailWidth || len([]rune(ua)) > cookieIPUAMax || len([]rune(path)) > letPathWidth {
			t.Errorf("a value wider than its column: reason %d, detail %d, ua %d, path %d characters",
				len([]rune(reason)), len([]rune(detail)), len([]rune(ua)), len([]rune(path)))
		}
	}
	if n != 2 {
		t.Errorf("%d rows, want 2", n)
	}
}

// TestLetThroughRestoresAFailedFlush: the deltas of a flush that did not go
// through are counted again by the next, once.
func TestLetThroughRestoresAFailedFlush(t *testing.T) {
	r, d := letReader(t)
	ts := time.Now()
	for i := 0; i < 4; i++ {
		letFeed(t, r, letLine(ts.Unix(), "a.example", "", "203.0.113.9", LetPath, "/a", "ua"))
	}
	r.mu.Lock()
	taken := r.collectLetLocked(ts)
	r.mu.Unlock()
	letFeed(t, r, letLine(ts.Unix(), "a.example", "", "203.0.113.9", LetPath, "/b", "ua"))
	letFeed(t, r, letLine(ts.Unix(), "a.example", "", "203.0.113.10", LetPath, "/b", "ua"))
	r.mu.Lock()
	r.restoreLetLocked(taken) // the flush failed
	r.mu.Unlock()
	r.flushOnce(true)
	if got := readLetTotals(t, d)["a.example|path|"]; got != (letTotal{6, 2}) {
		t.Errorf("after a failed flush and a good one: %+v, want 6 requests from 2 addresses", got)
	}
	rows := readLetAddrs(t, d, LetPath, "")
	if rows["203.0.113.9"].cnt != 5 || rows["203.0.113.10"].cnt != 1 {
		t.Errorf("after a failed flush and a good one: %+v", rows)
	}
}

// letHeld is what the reader holds: the buckets, the addresses in them, and
// the two figures it bounds itself by.
func letHeld(r *Reader) (buckets, addrs, countedKeys, countedAddrs int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.letBuckets {
		addrs += len(b.addrs)
	}
	for _, n := range r.letHourKeys {
		countedKeys += n
	}
	return len(r.letBuckets), addrs, countedKeys, r.letAddrCount
}

// letAddrRowsBySite: the address rows written, per site.
func letAddrRowsBySite(t *testing.T, d *db.DB) map[string]int {
	t.Helper()
	rows, err := d.Query(`SELECT site, COUNT(*) FROM unmask_let_ip_hourly GROUP BY site`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var site string
		var n int
		if err := rows.Scan(&site, &n); err != nil {
			t.Fatal(err)
		}
		out[site] = n
	}
	return out
}

// TestLetThroughPastTheKeyBoundCountsUnderOther: an hour that holds all the
// buckets it may counts a line with no bucket of its own under OtherSite, by
// its reason.  Varying the Host fills the bound, and a request that came
// after it used to be counted nowhere -- a way to blind the list first and
// lean on a ground afterwards.
func TestLetThroughPastTheKeyBoundCountsUnderOther(t *testing.T) {
	r, d := letReader(t)
	defer func(n int) { letKeysMax = n }(letKeysMax)
	letKeysMax = 3
	ts := time.Now().Unix()
	for i := 0; i < 3; i++ {
		letFeed(t, r, letLine(ts, fmt.Sprintf("s%d.example", i), "", fmt.Sprintf("203.0.113.%d", i), LetNoGate, "/a", "ua"))
	}
	// The bound is reached.  Two hosts more, a second ground, a crawler by
	// its name: none has a bucket.
	letFeed(t, r, letLine(ts, "s3.example", "", "198.51.100.1", LetNoGate, "/b", "ua"))
	letFeed(t, r, letLine(ts, "s4.example", "", "198.51.100.2", LetNoGate, "/c", "ua"))
	letFeed(t, r, letLine(ts, "s4.example", "pow", "198.51.100.2", LetCookie, "", "ua"))
	letFeed(t, r, letLine(ts, "s0.example", "", "198.51.100.3", LetName, "/d", "ua"))
	// A line whose bucket is there is counted in it, as before.
	letFeed(t, r, letLine(ts, "s0.example", "", "198.51.100.4", LetNoGate, "/e", "ua"))
	if buckets, _, counted, _ := letHeld(r); buckets != 6 || counted != buckets {
		t.Errorf("the reader holds %d buckets and counts %d: want 6 (the 3 of the bound, and one a reason under %s)", buckets, counted, OtherSite)
	}
	r.flushOnce(true)
	got := readLetTotals(t, d)
	want := map[string]int{
		"s0.example|nogate|": 2, "s1.example|nogate|": 1, "s2.example|nogate|": 1,
		OtherSite + "|nogate|": 2, OtherSite + "|cookie|": 1, OtherSite + "|name|": 1,
	}
	total := 0
	for k, row := range got {
		total += row.cnt
		if want[k] != row.cnt {
			t.Errorf("%s: %d requests, want %d", k, row.cnt, want[k])
		}
	}
	if len(got) != len(want) || total != 8 {
		t.Errorf("%d rows counting %d requests, want %d rows and all 8: %+v", len(got), total, len(want), got)
	}
	// The addresses of the lines that had no bucket are listed all the same.
	if rows := readLetAddrs(t, d, LetNoGate, ""); rows["198.51.100.1"].cnt != 1 || rows["198.51.100.2"].cnt != 1 {
		t.Errorf("the addresses counted under %s are not listed: %+v", OtherSite, rows)
	}
	if rows := readLetAddrs(t, d, LetName, ""); rows["198.51.100.3"].cnt != 1 {
		t.Errorf("the address that passed by name past the bound is not listed: %+v", rows)
	}
}

// TestLetThroughPastTheSpareRoomIsNotHeld: past the bound a reason costs one
// bucket, and past the spare room for those not even that -- reasons are the
// configuration's, a dozen of them, so only a writer that is not nginx gets
// this far.
func TestLetThroughPastTheSpareRoomIsNotHeld(t *testing.T) {
	r, _ := letReader(t)
	defer func(n int) { letKeysMax = n }(letKeysMax)
	letKeysMax = 2
	ts := time.Now().Unix()
	for i := 0; i < 2*letKeysSpare; i++ {
		// a reason of its own each: aa, ab, ...
		why := string([]byte{'a' + byte(i/26), 'a' + byte(i%26)})
		letFeed(t, r, letLine(ts, "a.example", "", "203.0.113.9", why, "/a", "ua"))
	}
	if buckets, _, counted, _ := letHeld(r); buckets != letKeysMax+letKeysSpare || counted != buckets {
		t.Errorf("the reader holds %d buckets and counts %d, want %d: the bound and the spare room", buckets, counted, letKeysMax+letKeysSpare)
	}
}

// TestLetThroughAddressBudget: the buckets together hold letAddrsMax
// addresses, and past that letAddrsFloor each: a bucket with its share takes
// a new address in the place of one of its own.  At twice letAddrsMax nothing
// is added at all, and a bucket that holds nobody lists nobody.  Every
// request stays in the totals.
func TestLetThroughAddressBudget(t *testing.T) {
	r, d := letReader(t)
	defer func(n int) { letAddrsMax = n }(letAddrsMax)
	letAddrsMax = 30
	ts := time.Now().Unix()
	crowd := func(site string, net, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			letFeed(t, r, letLine(ts, site, "", fmt.Sprintf("10.0.%d.%d", net, i), LetNoGate, "/"+site, "ua"))
		}
	}
	held := func() int {
		t.Helper()
		_, addrs, _, counted := letHeld(r)
		if counted != addrs {
			t.Errorf("the reader holds %d addresses and counts %d", addrs, counted)
		}
		return addrs
	}
	crowd("a.example", 0, 30) // the first ground takes all the buckets may hold together
	crowd("b.example", 1, 25) // a second still gets its share, and then turns over within it
	crowd("a.example", 2, 5)  // the first holds what it has; a newcomer takes a place in it
	if got, want := held(), 30+letAddrsFloor; got != want {
		t.Errorf("%d addresses held, want %d: the bound, and the second bucket's share", got, want)
	}
	crowd("f.example", 7, 3) // a small one, short of its share
	crowd("c.example", 3, 25)
	crowd("d.example", 4, 25) // twice the bound is reached, 7 addresses into this one
	crowd("e.example", 5, 3)  // a bucket with nobody in it lists nobody now
	crowd("f.example", 6, 1)  // and one with somebody, however few, still turns over
	if got, want := held(), 2*letAddrsMax; got != want {
		t.Errorf("%d addresses held, want %d: twice the bound, and no more", got, want)
	}
	r.flushOnce(true)
	got := readLetTotals(t, d)
	for site, want := range map[string]int{"a.example": 35, "b.example": 25, "c.example": 25, "d.example": 25, "e.example": 3, "f.example": 4} {
		if n := got[site+"|nogate|"].cnt; n != want {
			t.Errorf("%s: %d requests counted, want %d -- the bound is on the addresses listed, not on the count", site, n, want)
		}
	}
	rows := letAddrRowsBySite(t, d)
	for site, want := range map[string]int{"a.example": 30, "b.example": letAddrsFloor, "c.example": letAddrsFloor, "d.example": 7, "e.example": 0, "f.example": 3} {
		if rows[site] != want {
			t.Errorf("%s: %d address rows written, want %d", site, rows[site], want)
		}
	}
	// The last newcomer took a place in a bucket that had somebody: it is
	// listed, which the three of the bucket that had nobody are not.
	listed := readLetAddrs(t, d, LetNoGate, "")
	if listed["10.0.6.0"].cnt != 1 {
		t.Errorf("the newcomer to a bucket that holds somebody is not listed: it takes a place, at any bound")
	}
	if _, ok := listed["10.0.5.0"]; ok {
		t.Errorf("an address of the bucket that held nobody at twice the bound is listed")
	}
	held() // the flush counts afresh; with nothing let go it finds the same
}

// TestLetThroughHoldsSoManyHours: buckets of an hour that is over are held
// only while their flush fails, and letHoursHeld hours' worth is the most the
// reader holds -- past it an hour gets the one bucket a reason, and past the
// spare room for those nothing.
func TestLetThroughHoldsSoManyHours(t *testing.T) {
	r, _ := letReader(t)
	defer func(n int) { letKeysMax = n }(letKeysMax)
	letKeysMax = 2
	now := time.Now().Unix()
	p, ok := r.parse(letLine(now, "a.example", "", "203.0.113.7", LetNoGate, "/a", "ua"))
	if !ok {
		t.Fatal("the line did not parse")
	}
	// No flush takes anything: 200 hours, three sites in each.
	for h := int64(0); h < 200; h++ {
		for s := 0; s < 3; s++ {
			r.bumpLetAt(fmt.Sprintf("s%d.example", s), LetNoGate, "", p, now-3600*h)
		}
	}
	if buckets, _, counted, _ := letHeld(r); buckets != letHoursHeld*letKeysMax+letKeysSpare || counted != buckets {
		t.Errorf("the reader holds %d buckets and counts %d, want %d: %d hours' worth and the spare room",
			buckets, counted, letHoursHeld*letKeysMax+letKeysSpare, letHoursHeld)
	}
}

// TestLetThroughAnHourThatIsOverIsLetGo: the flush after an hour ends takes
// what its buckets still had to write and lets them go; a flush that fails
// brings them back, counted once.
func TestLetThroughAnHourThatIsOverIsLetGo(t *testing.T) {
	r, d := letReader(t)
	now := time.Now()
	p, ok := r.parse(letLine(now.Unix(), "a.example", "", "203.0.113.7", LetNoGate, "/a", "ua"))
	if !ok {
		t.Fatal("the line did not parse")
	}
	r.bumpLetAt("a.example", LetNoGate, "", p, now.Unix()-3600) // the hour before
	r.bumpLetAt("a.example", LetNoGate, "", p, now.Unix())
	r.mu.Lock()
	taken := r.collectLetLocked(now)
	r.mu.Unlock()
	if buckets, addrs, countedKeys, countedAddrs := letHeld(r); len(taken) != 2 || buckets != 1 || addrs != 1 || countedKeys != 1 || countedAddrs != 1 {
		t.Fatalf("after the flush: %d entries taken, %d bucket(s) with %d address(es) held (counted %d and %d); want 2 taken and this hour's one held",
			len(taken), buckets, addrs, countedKeys, countedAddrs)
	}
	r.mu.Lock()
	r.restoreLetLocked(taken) // the flush failed
	r.mu.Unlock()
	if buckets, addrs, countedKeys, countedAddrs := letHeld(r); buckets != 2 || addrs != 2 || countedKeys != 2 || countedAddrs != 2 {
		t.Fatalf("after the failed flush: %d bucket(s) with %d address(es) held (counted %d and %d), want both hours back",
			buckets, addrs, countedKeys, countedAddrs)
	}
	r.flushOnce(true)
	rows, err := d.Query(`SELECT bucket_hour, cnt FROM unmask_let_hourly ORDER BY bucket_hour`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var hours []int64
	for rows.Next() {
		var hour int64
		var cnt int
		if err := rows.Scan(&hour, &cnt); err != nil {
			t.Fatal(err)
		}
		if cnt != 1 {
			t.Errorf("hour %d counts %d requests, want 1", hour, cnt)
		}
		hours = append(hours, hour)
	}
	if len(hours) != 2 || hours[1]-hours[0] != 1 {
		t.Errorf("rows for the hours %v, want the two hours, one request each", hours)
	}
}

// TestLetThroughHoldsAStampToItsHour: a line stamped far from now is counted
// in this hour.  The bucket is keyed by the line's own time, and a stamp from
// years away would start a bucket no flush ends.
func TestLetThroughHoldsAStampToItsHour(t *testing.T) {
	r, _ := letReader(t)
	before := time.Now().Unix() / 3600
	letFeed(t, r, letLine(1000000000, "a.example", "", "203.0.113.7", LetNoGate, "/a", "ua"))
	letFeed(t, r, letLine(4000000000, "a.example", "", "203.0.113.7", LetNoGate, "/a", "ua"))
	after := time.Now().Unix() / 3600
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.letBuckets) == 0 {
		t.Fatal("the lines were not counted")
	}
	for k := range r.letBuckets {
		if k.hour < before || k.hour > after {
			t.Errorf("a bucket for hour %d, which is not this hour (%d)", k.hour, after)
		}
	}
}
