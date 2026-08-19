package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestConfigAssemblyExpandsHostPlaceholder pins the __hostname__ contract:
// the stored setting keeps the literal placeholder (so one config fragment
// serves a whole fleet), and the runtime configs assembled from it carry the
// resolved host id -- in the site label and the mail From name, on every
// occurrence, while every other field passes through untouched.  Both
// assembly paths (daemon startup, post-save hot-swap) go through these two
// functions, so this is the whole expansion surface.
func TestConfigAssemblyExpandsHostPlaceholder(t *testing.T) {
	n := settings.Notifications{
		URL:             "https://hooks.example/x",
		Format:          "slack",
		SiteLabel:       "__hostname__",
		WebhookDisabled: true,
		MailDisabled:    true,
	}
	nc := NotifierConfigFrom(n, "tool1-jp")
	if nc.Sites != "tool1-jp" {
		t.Errorf("Sites = %q, want the resolved host id", nc.Sites)
	}
	if nc.URL != n.URL || nc.Format != n.Format {
		t.Error("unrelated notifier fields must pass through unchanged")
	}
	if !nc.WebhookDisabled || !nc.MailDisabled {
		t.Error("per-channel pause flags must reach the runtime config")
	}
	// MailTo: the comma-separated setting arrives parsed and trimmed; empty
	// stays empty (= fall back to the admin users).
	if got := NotifierConfigFrom(settings.Notifications{MailTo: " a@x ,, b@x "}, "h").MailTo; len(got) != 2 || got[0] != "a@x" || got[1] != "b@x" {
		t.Errorf("MailTo parsing: %v", got)
	}
	if got := NotifierConfigFrom(settings.Notifications{}, "h").MailTo; len(got) != 0 {
		t.Errorf("empty MailTo must stay empty, got %v", got)
	}

	m := settings.SMTP{
		Host: "127.0.0.1", Port: 25,
		// An address must be a real mailbox: the placeholder is NOT expanded
		// there, even written literally.
		FromAddress: "notify+__hostname__@example.com",
		FromName:    "unmask __hostname__ (__hostname__)",
	}
	mc := MailConfigFrom(m, "tool2-jp")
	if mc.FromName != "unmask tool2-jp (tool2-jp)" {
		t.Errorf("FromName = %q, want every placeholder expanded", mc.FromName)
	}
	if mc.FromAddress != m.FromAddress {
		t.Errorf("FromAddress = %q, must pass through unexpanded", mc.FromAddress)
	}

	// No placeholder -> verbatim.
	if got := NotifierConfigFrom(settings.Notifications{SiteLabel: "blog-jp"}, "h").Sites; got != "blog-jp" {
		t.Errorf("literal label rewritten: %q", got)
	}
	// Empty stays empty (= "no label" remains expressible).
	if got := NotifierConfigFrom(settings.Notifications{}, "h").Sites; got != "" {
		t.Errorf("empty label became %q", got)
	}
}
