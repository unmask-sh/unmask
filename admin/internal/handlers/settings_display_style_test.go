package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The display-style choice must appear exactly once per value.  Restructuring
// the block into radio cards left the previous plain-radio row in place, and
// the tab rendered FOUR radios in one group -- two of them orphaned labels that
// silently fought the others for the same name.  A duplicated form control is
// invisible in a diff and obvious on screen, which is the wrong way round.
func TestDisplayStyleHasOneRadioPerValue(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	for _, v := range []string{"visible", "invisible"} {
		re := regexp.MustCompile(`<input type="radio" name="challenge_display_style" value="` + v + `"`)
		if n := len(re.FindAllString(page, -1)); n != 1 {
			t.Errorf("challenge_display_style=%q is rendered %d times, want exactly 1", v, n)
		}
	}
	// Each card carries the settings it governs, so a timing can never be read
	// as belonging to the option above it.
	for _, id := range []string{"ch-mode-visible", "ch-mode-invisible"} {
		if !strings.Contains(page, `data-target="`+id+`"`) || !strings.Contains(page, `id="`+id+`"`) {
			t.Errorf("%s: the radio and the body it reveals are not wired together", id)
		}
	}
	// Both bodies stay on screen: the settings are what the mode DOES, so an
	// operator choosing between the two needs to read both.  Hiding the
	// unselected one takes the choice's own evidence away.
	for _, id := range []string{"ch-mode-visible", "ch-mode-invisible"} {
		i := strings.Index(page, `id="`+id+`"`)
		if i < 0 {
			t.Fatalf("%s body missing", id)
		}
		if seg := page[i : i+len(id)+40]; strings.Contains(seg, "display:none") {
			t.Errorf("%s is hidden when unselected; both modes must stay readable", id)
		}
	}
	// min_display_ms belongs to the visible card, the reveal timings to the
	// invisible one -- assert by position, since that is what the operator reads.
	vis := strings.Index(page, `id="ch-mode-visible"`)
	inv := strings.Index(page, `id="ch-mode-invisible"`)
	if vis < 0 || inv < 0 || vis > inv {
		t.Fatal("cannot locate the two mode bodies in order")
	}
	if i := strings.Index(page, `name="min_display_ms"`); i < vis || i > inv {
		t.Error("min_display_ms is not inside the visible card")
	}
	for _, f := range []string{"invisible_reveal_ms", "reveal_fade_ms"} {
		if i := strings.Index(page, `name="`+f+`"`); i < inv {
			t.Errorf("%s is not inside the invisible card", f)
		}
	}
}
