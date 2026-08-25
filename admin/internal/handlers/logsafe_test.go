package handlers

import "testing"

// A value that came in over the wire must not be able to end the log line it
// is written into.  r.URL.Path is percent-decoded before a handler sees it, so
// a request for "/%0aadmin IP denied: ip=1.2.3.4" reaches log.Printf carrying a
// real newline -- and what follows is a line that looks exactly like one the
// daemon wrote.  The value is worth something to whoever wants the operator
// reading that log to reach the wrong conclusion.
func TestLogSafe(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/ordinary/path", "/ordinary/path"},
		{"", ""},
		{"/a\nadmin IP denied: ip=1.2.3.4", `/a\nadmin IP denied: ip=1.2.3.4`},
		{"/a\r\nb", `/a\r\nb`},
		{"/a\tb", `/a\tb`},
		{"/a\x00b", `/a\x00b`},
		{"/a\x1bb", `/a\x1bb`}, // ESC: a terminal would act on this one
		{"/a\x7fb", `/a\x7fb`},
		{"日本語/パス", "日本語/パス"}, // multi-byte is not a control character
	}
	for _, c := range cases {
		if got := LogSafe(c.in); got != c.want {
			t.Errorf("LogSafe(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	got := LogSafeAll([]string{"ok", "a\nb"})
	if len(got) != 2 || got[0] != "ok" || got[1] != `a\nb` {
		t.Errorf("LogSafeAll = %q", got)
	}
}
