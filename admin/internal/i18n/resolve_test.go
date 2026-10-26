package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The cookie wins, then the first supported language in Accept-Language;
// with neither -- no header, or a browser that asks for languages unmask
// does not have -- the page is English.
func TestResolveDefaultsToEnglish(t *testing.T) {
	req := func(accept string, cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
		if accept != "" {
			r.Header.Set("Accept-Language", accept)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: CookieName, Value: cookie})
		}
		return r
	}
	for _, c := range []struct {
		accept, cookie string
		want           Lang
	}{
		{"", "", LangEN},
		{"fr-FR,fr;q=0.9,de;q=0.8", "", LangEN},
		{"ja,en;q=0.8", "", LangJA},
		{"en-US,en;q=0.9,ja;q=0.8", "", LangEN},
		{"fr-FR,ja;q=0.5", "", LangJA},
		{"en", "ja", LangJA},
		{"", "xx", LangEN},
	} {
		if got := Resolve(req(c.accept, c.cookie)); got != c.want {
			t.Errorf("Accept-Language %q cookie %q: %q, want %q", c.accept, c.cookie, got, c.want)
		}
	}
	if got := Resolve(nil); got != LangEN {
		t.Errorf("nil request: %q", got)
	}
}
