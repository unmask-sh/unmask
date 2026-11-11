package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// draftPage renders a settings tab with the cookies a save's redirect set.
func draftPage(t *testing.T, h *Handler, tab string, cookies []*http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/"+tab+"/", nil)
	req.SetPathValue("tab", tab)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: HTTP %d", tab, rr.Code)
	}
	return rr.Body.String()
}

// listBlock cuts one rule-list out of a page: its rows, and its row template
// (the columns a new row posts).
func listBlock(t *testing.T, body, name string) (rows, tmpl string) {
	t.Helper()
	i := strings.Index(body, `data-rule-name="`+name+`"`)
	if i < 0 {
		t.Fatalf("list %s not on the page", name)
	}
	j := strings.Index(body[i:], `<template class="rule-row-template">`)
	if j < 0 {
		t.Fatalf("list %s has no row template", name)
	}
	k := strings.Index(body[i+j:], `</template>`)
	return body[i : i+j], body[i+j : i+j+k]
}

// rowTemplateFor: the row template of the list whose rows post valueField
// (a list's data-rule-name is not always its value field: JA4's is
// "ja4_extra", its value ja4_extra_pat).
func rowTemplateFor(t *testing.T, body, valueField string) string {
	t.Helper()
	const open, end = `<template class="rule-row-template">`, `</template>`
	rest := body
	for {
		i := strings.Index(rest, open)
		if i < 0 {
			t.Fatalf("no row template posts %q", valueField)
		}
		rest = rest[i:]
		k := strings.Index(rest, end)
		if k < 0 {
			t.Fatalf("an unterminated row template")
		}
		if tmpl := rest[:k]; strings.Contains(tmpl, `name="`+valueField+`"`) {
			return tmpl
		}
		rest = rest[k:]
	}
}

// fieldValues: the values of the named input, in page order.
func fieldValues(block, name string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`name="`+name+`" value="([^"]*)"`).FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	return out
}

// The draft a rejected save carries is read under the field names the page
// posts, and carries every column a row has.  The names were a second,
// hand-kept copy: bypass-ips' were the convention's (bypass_ip_title) while
// the page posts bypass_title, and the black list's action, JA4's chain and
// id and every list's stamps were not carried at all -- so a re-save from the
// error page switched disabled rows on and moved or dropped those columns.
func TestRuleListRegistryMatchesThePage(t *testing.T) {
	h := ruleTestHandler(t)
	nameRE := regexp.MustCompile(`name="([a-z0-9_]+)"`)
	sections := make([]string, 0, len(ruleListRegistry))
	for s := range ruleListRegistry {
		sections = append(sections, s)
	}
	sort.Strings(sections)
	for _, section := range sections {
		body := draftPage(t, h, section, nil)
		onPage := map[string]bool{}
		for _, m := range nameRE.FindAllStringSubmatch(body, -1) {
			onPage[m[1]] = true
		}
		for _, sp := range ruleListRegistry[section] {
			registered := map[string]bool{}
			for _, f := range []string{sp.Name, sp.Title, sp.Enabled, sp.Action, sp.Site, sp.Verdict, sp.Rate, sp.CreatedAt, sp.UpdatedAt, sp.Chain, sp.ID} {
				if f == "" {
					continue
				}
				registered[f] = true
				if !onPage[f] {
					t.Errorf("%s / %s: the draft reads %q, which the page does not post", section, sp.Name, f)
				}
			}
			tmpl := rowTemplateFor(t, body, sp.Name)
			for _, m := range nameRE.FindAllStringSubmatch(tmpl, -1) {
				if !registered[m[1]] {
					t.Errorf("%s / %s: a row posts %q, which the draft does not carry", section, sp.Name, m[1])
				}
			}
		}
	}
}

// A rejected bypass-ips save keeps the operator's rows as they were: a
// switched-off row stays off, titles and the stamps of when each row was
// added stay, through the error page and a re-save of what it shows.
func TestRejectedSaveKeepsBypassRows(t *testing.T) {
	h := ruleTestHandler(t)
	if res := settingsSave(t, h, "bypass-ips", url.Values{
		"bypass_ip":         {"10.0.0.1", "203.0.113.7"},
		"bypass_title":      {"office", "old vendor"},
		"bypass_enabled":    {"1", "0"},
		"bypass_created_at": {"1700000000", "1700000001"},
		"bypass_updated_at": {"0", "0"},
	}); res.StatusCode != http.StatusFound {
		t.Fatalf("first save: %d", res.StatusCode)
	}
	res := settingsSave(t, h, "bypass-ips", url.Values{
		"bypass_ip":         {"10.0.0.1", "203.0.113.7", "not-an-ip"},
		"bypass_title":      {"office", "old vendor", "new"},
		"bypass_enabled":    {"1", "0", "1"},
		"bypass_created_at": {"1700000000", "1700000001", ""},
		"bypass_updated_at": {"0", "0", ""},
	})
	rows, _ := listBlock(t, draftPage(t, h, "bypass-ips", res.Cookies()), "bypass_ip")
	ips, titles, en, cr := fieldValues(rows, "bypass_ip"), fieldValues(rows, "bypass_title"), fieldValues(rows, "bypass_enabled"), fieldValues(rows, "bypass_created_at")
	if fmt.Sprint(ips) != "[10.0.0.1 203.0.113.7 not-an-ip]" || fmt.Sprint(titles) != "[office old vendor new]" ||
		len(en) != 3 || en[1] != "0" || len(cr) < 2 || cr[0] != "1700000000" || cr[1] != "1700000001" {
		t.Fatalf("the error page shows ips=%v titles=%q enabled=%v created=%v", ips, titles, en, cr)
	}
	ips[2] = "192.0.2.9"
	if res := settingsSave(t, h, "bypass-ips", url.Values{
		"bypass_ip": ips, "bypass_title": titles, "bypass_enabled": en,
		"bypass_created_at": cr, "bypass_updated_at": fieldValues(rows, "bypass_updated_at"),
	}); res.StatusCode != http.StatusFound {
		t.Fatalf("re-save: %d", res.StatusCode)
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	n := cur.Nginx
	if len(n.BypassIPsDisabled) < 2 || !n.BypassIPsDisabled[1] {
		t.Errorf("the switched-off row is on after the re-save: disabled=%v", n.BypassIPsDisabled)
	}
	if fmt.Sprint(n.BypassIPsTitle[:2]) != "[office old vendor]" || n.BypassIPsCreatedAt[0] != 1700000000 || n.BypassIPsCreatedAt[1] != 1700000001 {
		t.Errorf("titles / stamps after the re-save: %q / %v", n.BypassIPsTitle, n.BypassIPsCreatedAt)
	}
}

// The UA black list's per-row action follows its row through a rejected save.
func TestRejectedSaveKeepsBlackListActions(t *testing.T) {
	h := ruleTestHandler(t)
	if res := settingsSave(t, h, "ua-filter", url.Values{
		"black_extra":         {"exact:AAA-bot", "exact:BBB-bot"},
		"black_extra_title":   {"a", "b"},
		"black_extra_enabled": {"1", "1"},
		"black_extra_action":  {"deny", ""},
	}); res.StatusCode != http.StatusFound {
		t.Fatalf("first save: %d", res.StatusCode)
	}
	// AAA-bot (the deny row) removed, a bad row added: rejected.
	res := settingsSave(t, h, "ua-filter", url.Values{
		"black_extra":         {"exact:BBB-bot", "bad("},
		"black_extra_title":   {"b", "new"},
		"black_extra_enabled": {"1", "1"},
		"black_extra_action":  {"", ""},
	})
	rows, _ := listBlock(t, draftPage(t, h, "ua-filter", res.Cookies()), "black_extra")
	selRE := regexp.MustCompile(`(?s)<select name="black_extra_action".*?</select>`)
	optRE := regexp.MustCompile(`<option value="([^"]*)"[^>]*\bselected\b`)
	for _, row := range strings.Split(rows, `<div class="rule-row`)[1:] {
		if !strings.Contains(row, `value="exact:BBB-bot"`) {
			continue
		}
		if o := optRE.FindStringSubmatch(selRE.FindString(row)); o != nil && o[1] == "deny" {
			t.Fatalf("BBB-bot (submitted with no action of its own) shows the removed row's deny on the error page")
		}
	}
}

// JA4's per-row chain belongs to the row it was set on, blank rows (the
// row's "+" adds one) anywhere in the list.
func TestJA4ChainFollowsItsRowPastABlank(t *testing.T) {
	h := ruleTestHandler(t)
	for _, c := range []struct {
		name          string
		pats, chains  []string
		wantChainByID map[string]string
	}{
		{"blank between", []string{"t13d1516h2_aaaa", "", "t13d9999h2_bbbb"}, []string{"inherit", "inherit", "deny"},
			map[string]string{"t13d1516h2_aaaa": "", "t13d9999h2_bbbb": "deny"}},
		{"blank first", []string{"", "t13d1516h2_aaaa", "t13d9999h2_bbbb"}, []string{"inherit", "deny", "inherit"},
			map[string]string{"t13d1516h2_aaaa": "deny", "t13d9999h2_bbbb": ""}},
	} {
		verds := make([]string, len(c.pats))
		for i, p := range c.pats {
			if p != "" {
				verds[i] = "bot_" + p[len(p)-4:]
			}
		}
		if res := settingsSave(t, h, "ja4-verdicts", url.Values{
			"ja4_extra_pat": c.pats, "ja4_extra_verd": verds,
			"ja4_extra_action": {"bot", "bot", "bot"}, "ja4_extra_enabled": {"1", "1", "1"},
			"ja4_extra_id": {"0", "0", "0"}, "ja4_extra_action_chain": c.chains,
		}); res.StatusCode != http.StatusFound {
			t.Fatalf("%s: save %d", c.name, res.StatusCode)
		}
		cur, err := settings.Load(h.ConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		j := cur.Nginx.JA4Verdicts
		for i, e := range j.Extra {
			got := ""
			if i < len(j.ExtraAction) {
				got = j.ExtraAction[i]
			}
			if want := c.wantChainByID[e.Pattern]; got != want {
				t.Errorf("%s: %s stored chain %q, want %q (column %q)", c.name, e.Pattern, got, want, j.ExtraAction)
			}
		}
	}
}

// A long list keeps the operator's rows through a rejected save: a draft too
// big for the flash cookie is kept by the daemon and the cookie names it.  It
// was dropped, and the error page showed the saved list.
func TestRejectedSaveKeepsALongList(t *testing.T) {
	h := ruleTestHandler(t)
	form := url.Values{}
	for i := 0; i < 60; i++ {
		form.Add("bypass_ip", fmt.Sprintf("198.51.100.%d", i+1))
		form.Add("bypass_title", fmt.Sprintf("partner network number %02d, kept for the review", i))
		form.Add("bypass_enabled", "1")
		form.Add("bypass_created_at", "1700000000")
		form.Add("bypass_updated_at", "0")
	}
	form.Add("bypass_ip", "not-an-ip")
	form.Add("bypass_title", "bad")
	form.Add("bypass_enabled", "1")
	res := settingsSave(t, h, "bypass-ips", form)
	var flash *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == flashCookiePrefix+netListDraftFlash {
			flash = c
		}
	}
	if flash == nil || len(flash.Value) > 4000 {
		t.Fatalf("the draft cookie: %v", flash)
	}
	rows, _ := listBlock(t, draftPage(t, h, "bypass-ips", res.Cookies()), "bypass_ip")
	if got := len(fieldValues(rows, "bypass_ip")); got != 61 {
		t.Fatalf("the error page shows %d rows, want the 61 submitted", got)
	}
	// Shown once: the kept copy is gone after the page read it.
	if draftFromFlash(draftStorePrefix+strings.TrimPrefix(flash.Value, url.QueryEscape(draftStorePrefix))) != "" {
		t.Errorf("the kept draft is still there after the page read it")
	}
}
