package handlers

import (
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The freeze only works if the id survives the click.  Paging links must carry
// it; "first" must not, because it is the operator's way back to a log that is
// moving again.
func TestPagerLinksCarryTheFreezeExceptFirst(t *testing.T) {
	seek := buildHuntPagerSeek(i18n.LangEN, "1h", "", "", "", "", url.Values{},
		100, 100, true, true, "", 4242)

	for _, c := range []struct {
		name, got string
		want      bool
	}{
		{"next", seek.NextURL, true},
		{"prev", seek.PrevURL, true},
		{"first", seek.FirstURL, false},
	} {
		has := strings.Contains(c.got, "asof=4242")
		if has != c.want {
			verb := "must carry the freeze id"
			if !c.want {
				verb = "must drop the freeze id so it lands on the newest events"
			}
			t.Errorf("%s link %s: %q", c.name, verb, c.got)
		}
	}

	// Filters have to survive alongside it, or paging silently widens the hunt.
	if !strings.Contains(seek.NextURL, "range=1h") {
		t.Errorf("next link lost the range filter: %q", seek.NextURL)
	}
}

// A live view (no freeze taken) must not invent the parameter.
func TestPagerLinksOmitFreezeWhenLive(t *testing.T) {
	seek := buildHuntPagerSeek(i18n.LangEN, "1h", "", "", "", "", url.Values{},
		0, 100, false, true, "", 0)
	if strings.Contains(seek.NextURL, "asof") {
		t.Errorf("live view should page live, got %q", seek.NextURL)
	}
}
