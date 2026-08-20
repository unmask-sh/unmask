package events

import "testing"

// The serve-time JA4 rides beacon payloads the way force_reason does, and the
// row decoration is the single lift-out point (decorateRowFromPayload) -- the
// partial-row-shape rule.  Missing here = the hunt badge silently off for
// every future event.
func TestDecorateRowServeJA4(t *testing.T) {
	var row Row
	decorateRowFromPayload(&row, `{"phase":"abandon","serve_ja4":"t13d1516h2_8daaf6152771_d8a2da3f94cd"}`)
	if row.ServeJA4 != "t13d1516h2_8daaf6152771_d8a2da3f94cd" {
		t.Errorf("ServeJA4 = %q, want the echoed fingerprint", row.ServeJA4)
	}

	var bare Row
	decorateRowFromPayload(&bare, `{"phase":"abandon"}`)
	if bare.ServeJA4 != "" {
		t.Errorf("an event without the field decorated to %q, want empty", bare.ServeJA4)
	}
}
