package handlers

import (
	"fmt"
	"html/template"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The i18n template functions and what they let through.
//
// Many i18n messages carry markup -- a <code>, a link -- and the templates
// render those through safeHTML, which marks its argument as HTML the
// escaper leaves alone.  A message with placeholders (tf) formatted the
// arguments as they came, so `safeHTML (tf ...)` put an argument into the
// page unescaped: fine for a number, a hole for a string that someone
// else chose (a hostname, a path, a name).  tf now escapes its string
// arguments and returns HTML, so the result is safe to mark whether or
// not the template does; an argument that is HTML already (a <time> the
// handler built, a cause it escaped) is passed as template.HTML and goes
// through as it is.
//
// Inside a script or an attribute the contextual escaper does the right
// thing by itself and an entity in a string argument would show as an
// entity: those sites use tfText, which formats and escapes nothing.

// tfHTML is the template function tf: the message for key with args
// formatted in, string arguments escaped, template.HTML ones as they are.
func tfHTML(lang i18n.Lang, key string, args ...any) template.HTML {
	esc := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case template.HTML:
			esc[i] = string(v)
		case string:
			esc[i] = template.HTMLEscapeString(v)
		default:
			esc[i] = a
		}
	}
	return template.HTML(i18n.Tf(lang, key, esc...)) //nolint:gosec // the arguments are escaped above; the message is the catalog's own
}

// tfText is tf for a script or an attribute: plain text, escaped by the
// contextual escaper where it lands.
func tfText(lang i18n.Lang, key string, args ...any) string {
	return i18n.Tf(lang, key, args...)
}

// safeHTMLAny is the template function safeHTML: its argument as HTML the
// escaper leaves alone -- a string the template vouches for, or HTML that
// already is (tf's result).
func safeHTMLAny(v any) template.HTML {
	switch s := v.(type) {
	case template.HTML:
		return s
	case string:
		return template.HTML(s) //nolint:gosec // the template's own vouching, as before
	case nil:
		return ""
	default:
		return template.HTML(fmt.Sprint(v)) //nolint:gosec // numbers and the like
	}
}
