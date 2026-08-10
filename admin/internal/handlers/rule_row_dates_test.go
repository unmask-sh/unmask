package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var (
	rowTemplateRe = regexp.MustCompile(`(?s)<template class="rule-row-template">(.*?)</template>`)
	createdAtRe   = regexp.MustCompile(`name="([a-z0-9_]+)_created_at"`)
	updatedAtRe   = regexp.MustCompile(`name="[a-z0-9_]+_updated_at"`)
)

// Every rule list zips parallel form arrays by index, so a row that submits a
// created_at but no updated_at shortens one array against the others.  A row
// added from the template lands at the end (harmless on its own), but the ↑↓
// buttons can move it up -- and from there every later row reads the previous
// row's edit date.  Ten of the twelve templates were missing the field.
func TestRuleRowTemplatesCarryBothDates(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, m := range rowTemplateRe.FindAllStringSubmatch(string(b), -1) {
		blk := m[1]
		c := createdAtRe.FindStringSubmatch(blk)
		if c == nil {
			continue // list without dates at all -- nothing to keep aligned
		}
		if !updatedAtRe.MatchString(blk) {
			missing = append(missing, c[1])
		}
	}
	if len(missing) > 0 {
		t.Errorf("new-row templates submit created_at but not updated_at, so their lists misalign once the row is moved: %v", missing)
	}
}

// The JA4 rule list read ja4_extra_updated_at on save but never rendered it, on
// either the existing rows or the new-row template -- so the array was always
// empty and every JA4 rule's edit date reset to "never touched" on every save.
// It is the only list that had the field missing from its rendered rows too.
func TestEveryRuleListRoundTripsItsEditDate(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)
	// Each list that stores an edit date must render it where the row is drawn,
	// not only in the template that clones new rows.
	for _, name := range []string{
		"ja4_extra", "honeypot_url", "protected", "geo", "asn", "bp", "bypass",
	} {
		// Count the rendered inputs only -- a JS querySelector referencing the
		// same name is not a form field.
		created := strings.Count(tpl, `<input type="hidden" name="`+name+`_created_at"`)
		updated := strings.Count(tpl, `<input type="hidden" name="`+name+`_updated_at"`)
		if created > 0 && updated < created {
			t.Errorf("%s: %d created_at inputs but only %d updated_at -- a row that renders one without the other cannot round-trip its edit date",
				name, created, updated)
		}
	}
}
