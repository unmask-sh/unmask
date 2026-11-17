package events

import "testing"

// An address that names a page of the admin UI loses its query; every other
// address is stored as it came.
func TestWithoutOwnAdminQuery(t *testing.T) {
	const admin = "/unmask/admin"
	for _, c := range []struct{ in, want string }{
		// The reset and setup links, as a path and as a Referer.
		{"/unmask/admin/reset-password?token=0123abcd", "/unmask/admin/reset-password"},
		{"https://admin.example.com/unmask/admin/reset-password?token=0123abcd&err=empty", "https://admin.example.com/unmask/admin/reset-password"},
		{"/unmask/admin?token=0123abcd", "/unmask/admin"},
		{"/unmask/admin/hunt/#token=0123abcd", "/unmask/admin/hunt/"},
		// The same pages as nginx still routes them.
		{"/unmask//admin/reset-password?token=0123abcd", "/unmask//admin/reset-password"},
		{"/unmask/%61dmin/reset-password?token=0123abcd", "/unmask/%61dmin/reset-password"},
		{"/unmask/./x/../admin/reset-password?token=0123abcd", "/unmask/./x/../admin/reset-password"},
		// The challenge page standing at its own address, the page asked for in _orig.
		{"/unmask/challenge/?_orig=/unmask/admin/reset-password?token=0123abcd", "/unmask/challenge/"},
		{"https://example.com/unmask/challenge/?_orig=%2Funmask%2Fadmin%2Freset-password%3Ftoken%3D0123abcd", "https://example.com/unmask/challenge/"},
		{"https://example.com/unmask/challenge/?_orig=%252Funmask%252Fadmin%252Freset-password%253Ftoken%253D0123abcd", "https://example.com/unmask/challenge/"},
		// The site's own pages keep their query, an "admin" of their own included.
		{"/search?q=a&token=0123abcd", "/search?q=a&token=0123abcd"},
		{"/admin/reset-password?token=0123abcd", "/admin/reset-password?token=0123abcd"},
		{"/unmask/administrator?token=0123abcd", "/unmask/administrator?token=0123abcd"},
		{"https://example.com/shop/?next=/unmask/admin/reset-password?token=0123abcd", "https://example.com/shop/?next=/unmask/admin/reset-password?token=0123abcd"},
		{"/unmask/challenge/?_orig=/search?q=a", "/unmask/challenge/?_orig=/search?q=a"},
		{"/unmask/admin/reset-password", "/unmask/admin/reset-password"},
		{"", ""},
	} {
		if got := withoutOwnAdminQuery(c.in, admin); got != c.want {
			t.Errorf("withoutOwnAdminQuery(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The scrub reads the four address fields and leaves the rest of the payload
// alone; with another base path it follows that one.
func TestScrubOwnAdminURLs(t *testing.T) {
	t.Cleanup(func() { ownAdminPath.Store(nil) })
	e := &Event{Phase: "serve", Payload: map[string]any{
		"orig_path":    "/unmask/admin/reset-password?token=0123abcd",
		"uri":          "/unmask/admin/reset-password?token=0123abcd",
		"url":          "https://example.com/unmask/admin/reset-password?token=0123abcd",
		"referer":      "https://example.com/unmask/admin/reset-password?token=0123abcd",
		"force_reason": "protected",
		"bt":           "/unmask/admin/reset-password?token=0123abcd", // not an address field
	}}
	scrubOwnAdminURLs(e)
	for _, k := range urlPayloadKeys {
		if v := e.Payload[k].(string); v != "/unmask/admin/reset-password" && v != "https://example.com/unmask/admin/reset-password" {
			t.Errorf("%s kept its query: %q", k, v)
		}
	}
	if e.Payload["force_reason"] != "protected" || e.Payload["bt"] != "/unmask/admin/reset-password?token=0123abcd" {
		t.Errorf("the scrub touched another field: %v", e.Payload)
	}

	SetOwnAdminPath("/gate/admin/")
	e = &Event{Phase: "serve", Payload: map[string]any{
		"orig_path": "/gate/admin/reset-password?token=0123abcd",
		"referer":   "https://example.com/unmask/admin/reset-password?token=0123abcd", // a page of the site's, on this install
	}}
	scrubOwnAdminURLs(e)
	if got := e.Payload["orig_path"]; got != "/gate/admin/reset-password" {
		t.Errorf("under base path /gate: orig_path %q", got)
	}
	if got := e.Payload["referer"]; got != "https://example.com/unmask/admin/reset-password?token=0123abcd" {
		t.Errorf("under base path /gate: the site's own page lost its query: %q", got)
	}
	scrubOwnAdminURLs(nil)
	scrubOwnAdminURLs(&Event{})
}
