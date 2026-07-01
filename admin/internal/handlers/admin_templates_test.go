package handlers

import "testing"

// TestAdminTemplatesParse parses every embedded admin *.html template through the
// real loader (with its custom funcs).  They are parsed lazily as one set on the
// first admin render, so a single malformed template (an unbalanced {{ }}, a
// dangling variable after an edit) breaks the ENTIRE admin UI -- and the docker
// e2e only renders the login/challenge paths, so a settings.html-only break can
// slip through.  This catches it in `go test`.
func TestAdminTemplatesParse(t *testing.T) {
	if _, err := loadDashboardTemplate(); err != nil {
		t.Fatalf("admin templates failed to parse (breaks the whole admin UI): %v", err)
	}
}
