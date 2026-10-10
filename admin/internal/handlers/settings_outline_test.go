package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The outline the assistant reads: a tab reduced to its headings and
// fields, in the operator's language and with the current values, so an
// answer can name the exact section and field; and the search across tabs
// that finds them from a few words.
func TestSettingsOutlineAndFind(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	ctx := context.WithValue(context.Background(), sessionCtxKey{}, &SessionPayload{UserID: 1, Role: "admin", Exp: time.Now().Add(time.Hour).Unix()})

	o, err := h.SettingsTabOutline(ctx, "ja", "network")
	if err != nil {
		t.Fatal(err)
	}
	if o.Path != "/unmask/admin/settings/network/" || o.Title != i18n.T("ja", "settings.tab.network") {
		t.Errorf("tab: %+v", o.Path)
	}
	// The card's heading carries its help; its "preset" half, named under
	// the heading, carries the GCP checkbox.
	heading := strings.Join(strings.Fields(i18n.T("ja", "settings.network.lb_h")), " ")
	var card *SettingsSection
	var gcp *SettingsField
	for i := range o.Sections {
		sec := &o.Sections[i]
		if sec.Heading == heading {
			card = sec
		}
		if !strings.HasPrefix(sec.Heading, heading) {
			continue
		}
		for j := range sec.Fields {
			f := &sec.Fields[j]
			if f.Name == "_csrf" || f.Kind == "hidden" {
				t.Errorf("a hidden field leaked into the outline: %+v", f)
			}
			if f.Name == "trusted_lb_preset" && f.Option == "gcp" {
				gcp = f
			}
		}
	}
	if card == nil {
		var hs []string
		for _, s := range o.Sections {
			hs = append(hs, s.Heading)
		}
		t.Fatalf("no section headed %q; headings: %q", heading, hs)
	}
	if !strings.Contains(card.Help, "JA4") {
		t.Errorf("the heading's help tip is not carried: %q", card.Help)
	}
	if gcp == nil || gcp.Kind != "checkbox" || gcp.Value != "off" || !strings.Contains(gcp.Label, "GCP") {
		t.Errorf("the GCP preset checkbox: %+v", gcp)
	}

	// A few words find the section, with where it is.
	ms, err := h.SettingsFind(ctx, "ja", "GCP LB")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range ms {
		if m.Tab == "network" && strings.HasPrefix(m.Heading, heading) && m.Path == "/unmask/admin/settings/network/" && len(m.Fields) > 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("the trusted-LB section was not found for \"GCP LB\": %+v", ms)
	}
	// Particles and "setting" alone find nothing to look for.
	if _, err := h.SettingsFind(ctx, "ja", "の 設定"); err == nil {
		t.Error("a query of stop words must be refused")
	}
	// A tab behind the advanced switch is not shown, and says so.
	if _, err := h.SettingsTabOutline(ctx, "ja", "web-bot-auth"); err == nil {
		t.Error("the web-bot-auth tab must not render while the advanced switch is off")
	}
	if _, err := h.SettingsTabOutline(ctx, "ja", "no-such-tab"); err == nil {
		t.Error("an unknown tab must be an error")
	}
	// A secret is only said to be set.
	s = h.snapshotSettings()
	s.AIAdvisor.APIKey = "sk-very-secret"
	s.AIAdvisor.Enabled = true
	h.SetSettings(s)
	ai, err := h.SettingsTabOutline(ctx, "en", "ai-advisor")
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range ai.Sections {
		for _, f := range sec.Fields {
			if strings.Contains(f.Value, "very-secret") {
				t.Errorf("the API key leaked: %+v", f)
			}
			// The page never echoes the key, so the field is empty or
			// only said to be set; config_keys carries "set".
			if f.Name == "ai_api_key" && f.Value != "" && f.Value != "(set; not shown)" {
				t.Errorf("the API key field must not carry a value: %+v", f)
			}
		}
	}
}

func TestSearchTerms(t *testing.T) {
	got := strings.Join(searchTerms("GCP の LB はどこで設定する？ (real_ip)"), "|")
	if got != "gcp|lb|はどこで設定する|real_ip" {
		t.Errorf("terms: %q", got)
	}
}
