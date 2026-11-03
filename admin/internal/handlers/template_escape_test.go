package handlers

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// tf escapes a string argument and leaves one that is HTML already as it
// is, so its result is safe under safeHTML; numbers are formatted as they
// come.
func TestTfEscapesStringArguments(t *testing.T) {
	// setup.token.hint: `... <code class="cmd">sudo cat %s</code> ...`
	got := string(tfHTML(i18n.LangEN, "setup.token.hint", `/etc/x"><script>alert(1)</script>`))
	if strings.Contains(got, "<script>") || !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("a string argument went in unescaped: %s", got)
	}
	if !strings.Contains(got, `<code class="cmd">`) {
		t.Errorf("the message's own markup was lost: %s", got)
	}
	// reload_notice.msg: `... written at %s ...`, with a <time> the handler built.
	got = string(tfHTML(i18n.LangEN, "reload_notice.msg", template.HTML(`<time data-ts="1">x</time>`)))
	if !strings.Contains(got, `<time data-ts="1">x</time>`) {
		t.Errorf("an HTML argument was escaped: %s", got)
	}
	// bans.cdn_note: `%d of these ...`
	if got := string(tfHTML(i18n.LangEN, "bans.cdn_note", 3)); !strings.HasPrefix(got, "3 ") {
		t.Errorf("a number argument: %s", got)
	}
	// tfText formats and escapes nothing: the contextual escaper's job.
	if got := tfText(i18n.LangEN, "users.confirm.delete", "o'brien"); !strings.Contains(got, "o'brien") {
		t.Errorf("tfText changed its argument: %s", got)
	}
	// safeHTML takes both a string and tf's HTML.
	if safeHTMLAny("<b>x</b>") != "<b>x</b>" || safeHTMLAny(template.HTML("<i>y</i>")) != "<i>y</i>" || safeHTMLAny(nil) != "" || safeHTMLAny(7) != "7" {
		t.Error("safeHTML does not pass its argument through")
	}
}

// Through the real templates: `safeHTML (tf ...)` with a hostile argument
// renders the message's markup and the argument escaped, and a `tf`
// without safeHTML is not escaped twice.
func TestTfThroughTemplates(t *testing.T) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	// ban_dialog: <p class="ban-dialog-after">{{ safeHTML (tf .Lang "hunt.ban.after_note" .BasePath) }}</p>
	data := map[string]any{"Lang": i18n.LangEN, "BasePath": `/unmask"><script>alert(1)</script>`}
	if err := tmpl.ExecuteTemplate(&buf, "ban_dialog", data); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("the base path reached the page unescaped under safeHTML (tf ...)")
	}
	if !strings.Contains(out, `href="/unmask&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;/admin/bans/"`) {
		t.Errorf("the link was not built from the escaped argument:\n%s", out)
	}

	// reload_notice: tf with a cause the handler escaped (template.HTML):
	// escaped once, and the message's own markup kept.
	buf.Reset()
	n := &ReloadNotice{
		WrittenHTML: template.HTML(`<time data-ts="1">x</time>`),
		MsgKey:      "reload_notice.msg_saved",
		TitleKey:    "reload_notice.title",
		CauseHTML:   template.HTML(template.HTMLEscapeString("a <b> & c")),
	}
	if err := tmpl.ExecuteTemplate(&buf, "reload_notice", map[string]any{"Lang": i18n.LangEN, "BasePath": "/unmask", "ReloadNotice": n}); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	if !strings.Contains(out, `<time data-ts="1">x</time>`) {
		t.Errorf("the <time> the handler built was escaped:\n%s", out)
	}
	if !strings.Contains(out, "a &lt;b&gt; &amp; c") || strings.Contains(out, "&amp;lt;") {
		t.Errorf("the cause is not escaped exactly once:\n%s", out)
	}
}
