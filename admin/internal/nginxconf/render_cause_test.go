package nginxconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
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
		{"unmask_bv_secret", "secret"},
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

const testSecretHex = "0123456789abcdef0123456789abcdef0123456789abcdef"

// A block's key stops at a quoted field and, for a plain directive, at two
// words: the secret's value never names its block.  A block opener keeps
// its three words; a map, geo or zone keeps its own naming.
func TestBlockKeyStopsAtQuotedField(t *testing.T) {
	for line, want := range map[string]string{
		`unmask_bv_secret                "` + testSecretHex + `";`:                "unmask_bv_secret",
		`unmask_bv_secret '` + testSecretHex + `';`:                               "unmask_bv_secret",
		`log_format unmask_minimal escape=json '{"ts":"$time_iso8601"}';`:         "log_format unmask_minimal",
		`location ^~ /unmask/ {`:                                                  "location ^~ /unmask/",
		`include /var/lib/unmask/nginx/upstream.conf;`:                            "include /var/lib/unmask/nginx/upstream.conf",
		`map $http_user_agent $unmask_search_bot_ua {`:                            "map $unmask_search_bot_ua",
		`geo $remote_addr $unmask_country {`:                                      "geo $unmask_country",
		`limit_req_zone $binary_remote_addr zone=unmask_default:10m rate=100r/m;`: "limit_req_zone unmask_default",
		`upstream unmask_daemon {`:                                                "upstream unmask_daemon",
	} {
		if got := blockKey(line); got != want {
			t.Errorf("%s: %q, want %q", line, got, want)
		}
	}
}

var hexRunRE = regexp.MustCompile(`[0-9a-f]{12,}`)

// A render whose secret line changed records the block as the directive,
// so neither the record nor the notice built from it carries the key.
func TestChangedBlocksSecretLine(t *testing.T) {
	prev := []byte("unmask_bv_secret                \"" + strings.Repeat("ab", 24) + "\";\nmap $x $unmask_chmode {\n    default pow;\n}\n")
	next := []byte("unmask_bv_secret                \"" + testSecretHex + "\";\nmap $x $unmask_chmode {\n    default pow;\n}\n")
	got := changedBlocks("http.inc", prev, next)
	want := []RenderChange{{File: "http.inc", Block: "unmask_bv_secret", Changed: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes: %+v, want %+v", got, want)
	}
	b, _ := json.Marshal(RenderRecord{At: 1, Changes: got})
	if hexRunRE.Match(b) {
		t.Errorf("the record carries a run of the secret: %s", b)
	}
}

// A record written before 0.1.53 -- the secret's first digits in a block
// key, the file 0644 -- is rewritten under the current rules and mode; the
// other keys stay, and a record that needs nothing is only chmod'ed.
func TestScrubRenderRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, renderCauseFile)
	old := RenderRecord{At: 1700000000, Cause: RenderCause{Kind: RenderByCLI}, Changes: []RenderChange{
		{File: "http.inc", Block: `unmask_bv_secret "` + testSecretHex[:42], Changed: 1},
		{File: "http.inc", Block: "map $unmask_chmode", Added: 2},
		{File: "http.inc", Block: "limit_req_zone unmask_default", Changed: 1},
		{File: "server.inc", Block: "location ^~ /unmask/", Added: 1},
	}}
	b, _ := json.Marshal(old)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	ScrubRenderRecord(dir)
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("after the scrub: %v, mode %v", err, st.Mode())
	}
	rec, ok := ReadRenderRecord(dir)
	if !ok || rec.At != old.At || rec.Cause != old.Cause {
		t.Fatalf("the record after the scrub: %+v (%v)", rec, ok)
	}
	var blocks []string
	for _, c := range rec.Changes {
		blocks = append(blocks, c.Block)
	}
	if want := []string{"unmask_bv_secret", "map $unmask_chmode", "limit_req_zone unmask_default", "location ^~"}; !reflect.DeepEqual(blocks, want) {
		t.Errorf("blocks after the scrub: %q, want %q", blocks, want)
	}
	if raw, _ := os.ReadFile(path); hexRunRE.Match(raw) {
		t.Errorf("the scrubbed record still carries a run of the secret: %s", raw)
	}

	// Clean already: the mode is set, the content untouched.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	ScrubRenderRecord(dir)
	after, _ := os.ReadFile(path)
	st, _ = os.Stat(path)
	if string(before) != string(after) || st.Mode().Perm() != 0o640 {
		t.Errorf("a clean record: rewritten=%v mode=%v", string(before) != string(after), st.Mode())
	}
	ScrubRenderRecord(t.TempDir()) // no record: nothing happens
}

// A render's own record is 0640 like the http.inc it describes.
func TestRenderRecordMode(t *testing.T) {
	dir := t.TempDir()
	if err := RenderFor(settings.Settings{}, dir, "test", RenderCause{Kind: RenderByCLI}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, renderCauseFile))
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Errorf("the record: %v, mode %v", err, st.Mode())
	}
}
