package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

// The live tail draws a flag before each address, the way the static rows
// do.  The static rows get their country from the page handler; the tail
// gets its rows from the SSE stream, which used to send the stored row and
// nothing else -- so the tail had no country to draw and showed none.
//
// The stream now carries "cc" beside the row.  Pinned end to end through the
// real handler, because the field is added at the one place rows are written
// to the wire and a refactor of that loop would drop it silently: the JSON
// would still parse, the tail would still render, only the flag would be
// missing again.
func TestEventsStreamCarriesCountryCode(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.10:BR:16509")
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "") // overrides drive the lookup; no mmdb needed

	// The stream anchors on MAX(id) at connect time and only emits rows
	// written after that, so the row goes in first and the stream starts
	// from before it.
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site,host,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('s','',?,?,'t13d','',0,'serve',0,0,'','','{"bt":"x","orig_path":"/members/?p=1"}',datetime('now'))`,
		[]byte{203, 0, 113, 10},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"); err != nil {
		t.Fatal(err)
	}

	// One poll tick is 2s; give the handler a little more than that and
	// then cancel, which is how a client disconnect ends the stream.
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/events/stream?since=0", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	h.AdminEventsStream(rr, req)

	var data []string
	for _, line := range strings.Split(rr.Body.String(), "\n") {
		if strings.HasPrefix(line, "data: ") {
			data = append(data, strings.TrimPrefix(line, "data: "))
		}
	}
	if len(data) == 0 {
		t.Fatalf("the stream emitted no data lines in one poll interval; body:\n%s", rr.Body.String())
	}
	var ev struct {
		IP      string `json:"ip"`
		CC      string `json:"cc"`
		ASN     uint   `json:"asn"`
		ASNOrg  string `json:"asn_org"`
		UAShort string `json:"ua_short"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal([]byte(data[0]), &ev); err != nil {
		t.Fatalf("stream data is not JSON: %v\n%s", err, data[0])
	}
	if ev.IP != "203.0.113.10" {
		t.Fatalf("unexpected row on the stream: %+v", ev)
	}
	if ev.CC != "BR" {
		t.Errorf("the stream row carries cc=%q, want BR -- the live tail has no country to draw a flag from", ev.CC)
	}
	if ev.ASN != 16509 {
		t.Errorf("the stream row carries asn=%d, want 16509", ev.ASN)
	}
	// The override table seeds no org name, so the client falls back to the
	// bare AS number; what is pinned is that the field is wired at all.
	if !strings.Contains(ev.UAShort, "Chrome") {
		t.Errorf("the stream row carries ua_short=%q, want the classifier's short reading", ev.UAShort)
	}
	// The path was always on the row; the tail just never showed it.  Pinned
	// so the field the tail now reads cannot quietly stop being emitted.
	if ev.Path != "/members/?p=1" {
		t.Errorf("the stream row carries path=%q, want the requested path", ev.Path)
	}
}

// Without a geo database the field is simply absent (omitempty), and the
// client draws the unknown flag -- the same fallback the static rows use.
func TestEventsStreamOmitsCountryWithoutGeo(t *testing.T) {
	h := newTestHandler(t) // IPGeo nil
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site,host,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('s','',?,'UA','','',0,'serve',0,0,'','','{}',datetime('now'))`, []byte{198, 51, 100, 7}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	rr := httptest.NewRecorder()
	h.AdminEventsStream(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/api/events/stream?since=0", nil).WithContext(ctx))
	body := rr.Body.String()
	if !strings.Contains(body, `"ip":"198.51.100.7"`) {
		t.Fatalf("row not streamed:\n%s", body)
	}
	for _, f := range []string{`"cc":`, `"asn":`, `"asn_org":`} {
		if strings.Contains(body, f) {
			t.Errorf("a stream with no geo database must omit %s, not send an empty one", f)
		}
	}
}
