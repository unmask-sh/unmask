package main

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestOverBlockAlertRoute pins the deliverability decision behind doctor's
// "over-block alerts" check: the breaker's trip alert travels only through the
// notifications webhook or SMTP mail, and Notifications.Disabled gates both
// (notifier.OverBlock returns before the mail path when the section is off).
func TestOverBlockAlertRoute(t *testing.T) {
	cases := []struct {
		name string
		mod  func(s *settings.Settings)
		want string
	}{
		{"nothing configured", func(s *settings.Settings) {}, ""},
		{"webhook only", func(s *settings.Settings) { s.Notifications.URL = "https://hooks.example/x" }, "webhook"},
		{"mail only", func(s *settings.Settings) { s.SMTP.Host = "smtp.example.com" }, "mail"},
		{"both", func(s *settings.Settings) {
			s.Notifications.URL = "https://hooks.example/x"
			s.SMTP.Host = "smtp.example.com"
		}, "webhook + mail"},
		{"notifications disabled gates both", func(s *settings.Settings) {
			s.Notifications.Disabled = true
			s.Notifications.URL = "https://hooks.example/x"
			s.SMTP.Host = "smtp.example.com"
		}, ""},
		// A paused channel is configured but not a route.
		{"webhook paused leaves mail", func(s *settings.Settings) {
			s.Notifications.URL = "https://hooks.example/x"
			s.Notifications.WebhookDisabled = true
			s.SMTP.Host = "smtp.example.com"
		}, "mail"},
		{"mail paused leaves webhook", func(s *settings.Settings) {
			s.Notifications.URL = "https://hooks.example/x"
			s.SMTP.Host = "smtp.example.com"
			s.Notifications.MailDisabled = true
		}, "webhook"},
		{"both paused = no route", func(s *settings.Settings) {
			s.Notifications.URL = "https://hooks.example/x"
			s.Notifications.WebhookDisabled = true
			s.SMTP.Host = "smtp.example.com"
			s.Notifications.MailDisabled = true
		}, ""},
	}
	for _, c := range cases {
		var s settings.Settings
		c.mod(&s)
		if got := overBlockAlertRoute(s); got != c.want {
			t.Errorf("%s: overBlockAlertRoute = %q, want %q", c.name, got, c.want)
		}
	}
}
