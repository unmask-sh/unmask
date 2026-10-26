package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// The reload notice names the secret's block by a word of its own, in both
// languages, and the line it shows carries no part of the key.
func TestReloadNoticeNamesTheSecretBlock(t *testing.T) {
	h := &Handler{}
	changes := []nginxconf.RenderChange{{File: "http.inc", Block: "unmask_bv_secret", Changed: 1}}
	for lang, want := range map[i18n.Lang]string{i18n.LangEN: "secret key", i18n.LangJA: "秘密鍵"} {
		lines := h.renderChangeLines(lang, changes)
		if len(lines) != 1 || !strings.HasPrefix(lines[0], want+": ") {
			t.Errorf("%s: %q, want a line starting with %q", lang, lines, want)
		}
	}
}
