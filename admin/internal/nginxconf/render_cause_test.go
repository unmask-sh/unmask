package nginxconf

import (
	"reflect"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Two renders of a file compared block by block: the lines that changed,
// came and went in each map, geo or zone; a block that came or went whole.
func TestChangedBlocks(t *testing.T) {
	prev := []byte(`# rendered
geo $remote_addr $unmask_country {
    default "";
    2a09:bac2:d588::/45 US;
    2a09:bac3:d588::/45 US;
    1.2.3.0/24 JP;
}
map $http_user_agent $unmask_search_bot_ua {
    default 0;
    ~*googlebot 1;
}
limit_req_zone $binary_remote_addr zone=unmask_default:10m rate=100r/m;
map $uri $unmask_pp_global {
    default "";
}
`)
	next := []byte(`# rendered
geo $remote_addr $unmask_country {
    default "";
    2a09:bac2:d588::/45 IN;
    2a09:bac3:d588::/45 IN;
    2a09:bac2:d580::/44 IN;
    2a09:bac3:d580::/44 IN;
    1.2.3.0/24 JP;
}
map $http_user_agent $unmask_search_bot_ua {
    ~*googlebot 1;
    default 0;
}
limit_req_zone $binary_remote_addr zone=unmask_default:10m rate=200r/m;
map $request_uri $unmask_hp_global {
    default "";
    ~*^/wp-login 1;
}
`)
	got := changedBlocks("http.inc", prev, next)
	want := []RenderChange{
		{File: "http.inc", Block: "geo $unmask_country", Changed: 2, Added: 2},
		{File: "http.inc", Block: "limit_req_zone unmask_default", Changed: 1},
		{File: "http.inc", Block: "map $unmask_hp_global", Added: 3},
		{File: "http.inc", Block: "map $unmask_pp_global", Removed: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes:\n got %+v\nwant %+v", got, want)
	}
	if got := changedBlocks("http.inc", next, next); len(got) != 0 {
		t.Errorf("the same render reads as changed: %+v", got)
	}
}

func TestBlockLabelKey(t *testing.T) {
	for _, c := range []struct{ key, want string }{
		{"geo $unmask_country", "country"},
		{"geo $is_bypass_ip", "bypass"},
		{"geo $unmask_bind_key", "relay"},
		{"map $is_search_bot", "crawlers"},
		{"map $unmask_cr_1_ip", "custom_rules"},
		{"map $unmask_hp_host_x", "honeypot"},
		{"map $protected_mode", "protected"},
		{"limit_req_zone unmask_default", "rate_zones"},
		{"log_format unmask_minimal", "log_format"},
		{"map $something_else", ""},
		{"location ^~ /unmask/", ""},
	} {
		if got := BlockLabelKey(c.key); got != c.want {
			t.Errorf("%q: %q, want %q", c.key, got, c.want)
		}
	}
}

// A render that changed a file keeps why and what beside the files; one
// that changed nothing leaves the record as it was.
func TestRenderForKeepsCauseAndChanges(t *testing.T) {
	dir := t.TempDir()
	s := settings.Settings{}
	if err := RenderFor(s, dir, "test", RenderCause{Kind: RenderByCLI}); err != nil {
		t.Fatal(err)
	}
	rec, ok := ReadRenderRecord(dir)
	if !ok || rec.Cause.Kind != RenderByCLI || rec.At == 0 || len(rec.Changes) == 0 {
		t.Fatalf("the first render's record: %+v (%v)", rec, ok)
	}
	if err := RenderFor(s, dir, "test", RenderCause{Kind: RenderByIPRange, Detail: "relay"}); err != nil {
		t.Fatal(err)
	}
	if again, _ := ReadRenderRecord(dir); !reflect.DeepEqual(again, rec) {
		t.Errorf("a render that changed nothing rewrote the record: %+v", again)
	}
	s.Nginx.CustomRules = []settings.CustomRule{{ID: "cr1", Label: "x", Enabled: true, Action: "captcha_only",
		Conditions: []settings.CustomCondition{{Kind: "ip", Values: []string{"203.0.113.0/24"}}}}}
	if err := RenderFor(s, dir, "test", RenderCause{Kind: RenderBySettings, Detail: "custom-rules-add"}); err != nil {
		t.Fatal(err)
	}
	rec, ok = ReadRenderRecord(dir)
	if !ok || rec.Cause != (RenderCause{Kind: RenderBySettings, Detail: "custom-rules-add"}) {
		t.Fatalf("the save's record: %+v (%v)", rec, ok)
	}
	named := false
	for _, c := range rec.Changes {
		if BlockLabelKey(c.Block) == "custom_rules" && (c.Added > 0 || c.Changed > 0) {
			named = true
		}
	}
	if !named {
		t.Errorf("the rule's blocks are not among the changes: %+v", rec.Changes)
	}
}
