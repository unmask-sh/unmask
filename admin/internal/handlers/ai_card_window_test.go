package handlers

import (
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// Every other figure on the overview states the period it covers.  The AI /
// crawler card did not, anywhere -- not in the heading, the tabs, or the
// popover -- so its counts were the only ones on the page an operator had to
// take on trust.  They follow the page's window: the day, or the week on the
// dashboard's week tab (WinSuffix "_7d"), each label naming its period.
func TestAICrawlerCardStatesItsWindow(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/partial_ai_traffic_card.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)
	if !strings.Contains(tpl, `{{ t .Lang (printf "ai_traffic.window%s" $.WinSuffix) }}`) {
		t.Error("the card heading no longer shows the period its counts cover")
	}
	for _, lang := range []i18n.Lang{i18n.LangJA, i18n.LangEN} {
		if w := i18n.T(lang, "ai_traffic.window"); !strings.Contains(w, "24") {
			t.Errorf("%s window label is %q, which does not name the 24h period the queries use by default", lang, w)
		}
		if w := i18n.T(lang, "ai_traffic.window_7d"); !strings.Contains(w, "7") {
			t.Errorf("%s week window label is %q, which does not name the seven days", lang, w)
		}
	}
}
