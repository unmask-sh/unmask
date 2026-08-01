package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The public-test-pages section configures the PUBLIC pages, so its links lead
// with the public one; the admin page follows as a secondary note.  It stays
// in the markup on purpose: the public pages ship disabled, and in that state
// the admin page is the only test page that actually answers.
func TestChallengeTabLeadsWithThePublicTestLink(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=challenge", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("challenge tab: %d", rr.Code)
	}
	body := rr.Body.String()

	pub := strings.Index(body, `href="/test/"`)
	adm := strings.Index(body, `href="/admin/test/"`)
	if pub < 0 || adm < 0 {
		t.Fatalf("test links missing (public=%d admin=%d)", pub, adm)
	}
	if pub > adm {
		t.Error("the admin test link comes first; this section is about the public pages")
	}

	// A rule separates this section from the settings above it, the way the
	// roaming section below is separated.
	sec := strings.LastIndex(body[:strings.Index(body, "settings.challenge.public_test_pages")+1], "<hr")
	if sec < 0 {
		// i18n renders the key, so search the rendered heading instead.
		head := strings.Index(body, `data-help-target="ch-test-help"`)
		if head < 0 {
			t.Fatal("the public-test-pages section did not render")
		}
		if !strings.Contains(body[:head], "<hr") {
			t.Error("no rule above the public-test-pages section")
		}
	}
}

// With the public pages off (the shipped default) the section still says so
// next to the link, rather than offering a link that silently 404s.
func TestPublicTestLinkIsMarkedWhenDisabled(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=challenge", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	body := rr.Body.String()

	i := strings.Index(body, `href="/test/"`)
	if i < 0 {
		t.Fatal("public test link missing")
	}
	// The disabled marker sits between the public link and the admin one.
	seg := body[i:]
	if j := strings.Index(seg, `href="/admin/test/"`); j > 0 {
		seg = seg[:j]
	}
	if !strings.Contains(seg, "(") {
		t.Error("the public link carries no 'currently disabled' marker while the pages are off")
	}
}
