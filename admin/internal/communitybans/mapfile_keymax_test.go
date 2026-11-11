package communitybans

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A key longer than the map_hash bucket in force holds is left out of the map
// files: nginx loads a map only when every key fits, so one shared entry
// could stop the host's nginx from reloading or starting.  With the default
// bucket (keys up to 46 bytes) an IPv4 ip:ja4 key of 49 bytes is left out,
// the address-only and JA4-only keys are written.
func TestWriteMapFilesLeavesOutKeysOverTheCap(t *testing.T) {
	dir := t.TempDir()
	doc := FeedDocument{Version: 2, Entries: []FeedEntry{
		{Match: MatchIPJA4, IP: "203.0.113.58", JA4: "t13d1516h2_8daaf6152771_b0da82dd1658", Promoted: true},
		{Match: MatchJA4, JA4: "t13d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb", Promoted: true},
		{Match: MatchIPOnly, IP: "2001:db8::42", Promoted: true},
	}}
	if err := WriteMapFilesLimited(doc, dir, 46); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := read(MapFileIPJA4); strings.Contains(got, "203.0.113.58") {
		t.Errorf("a 49-byte key was written under a 46-byte cap:\n%s", got)
	}
	if !strings.Contains(read(MapFileJA4), "t13d0000h1_aaaaaaaaaaaa_bbbbbbbbbbbb") || !strings.Contains(read(MapFileIP), "2001:db8::42") {
		t.Errorf("keys under the cap were left out")
	}
	// No cap (http.inc sizes the bucket): the same key is written.
	if err := WriteMapFilesLimited(doc, dir, 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(MapFileIPJA4), "203.0.113.58:t13d1516h2_8daaf6152771_b0da82dd1658") {
		t.Errorf("without a cap the ip:ja4 key is missing")
	}
}
