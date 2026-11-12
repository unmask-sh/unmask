package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/outbound"
)

// update-crawler-list writes what the daemon will build its rescue lists
// from.  A body that is not the list -- an error page answered with 200, a
// download cut short -- was written all the same (only its length was
// looked at), over the list that was there.
func TestUpdateCrawlerListRefusesWhatIsNotAList(t *testing.T) {
	was := outbound.SetLoopbackForTests(true)
	t.Cleanup(func() { outbound.SetLoopbackForTests(was) })
	body := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "crawler-user-agents.json")
	const kept = `[{"pattern":"the list that was there"}]`
	if err := os.WriteFile(out, []byte(kept), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, b := range map[string]string{
		"an error page":        "<!doctype html><title>502</title>" + strings.Repeat("<p>bad gateway</p>", 200),
		"a download cut short": string(assets.CrawlerUserAgentsJSON[:len(assets.CrawlerUserAgentsJSON)/2]),
		"a list of three":      `[{"pattern":"OneBot"},{"pattern":"TwoBot"},{"pattern":"ThreeBot"}]` + strings.Repeat(" ", 2000),
	} {
		body = b
		if err := cmdUpdateCrawlerList([]string{"-url", srv.URL, "-out", out}); err == nil {
			t.Errorf("%s: written without a word", name)
		}
		if got, _ := os.ReadFile(out); string(got) != kept {
			t.Errorf("%s: the list that was there was replaced", name)
		}
	}

	body = string(assets.CrawlerUserAgentsJSON)
	if err := cmdUpdateCrawlerList([]string{"-url", srv.URL, "-out", out}); err != nil {
		t.Fatalf("a real list: %v", err)
	}
	if got, _ := os.ReadFile(out); string(got) != body {
		t.Error("a real list: the file does not hold it")
	}
	if _, err := os.Stat(out + ".tmp"); err == nil {
		t.Error("the temporary file was left beside the list")
	}
}
