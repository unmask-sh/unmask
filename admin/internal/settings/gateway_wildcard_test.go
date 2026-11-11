package settings

import "testing"

// nginx takes a `*` in a server name as a whole first or last label only; a
// gateway hostname with one elsewhere was saved and nginx refused the
// configuration ("invalid server name or wildcard").
func TestGatewayHostnameWildcard(t *testing.T) {
	for name, ok := range map[string]bool{
		"shop.example.com": true,
		"*.example.com":    true,
		"www.example.*":    true,
		"a*b.example.com":  false,
		"shop.*.com":       false,
		"*.example.*":      false,
		"*":                false,
		"*.":               false,
	} {
		if err := hostnameOK("hostname", name); (err == nil) != ok {
			t.Errorf("hostnameOK(%q) = %v, want ok=%v", name, err, ok)
		}
	}
}
