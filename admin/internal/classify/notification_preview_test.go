package classify

import "testing"

const (
	uaNotifExt    = "NotificationExtension/3 CFNetwork/3826.600.41.2.1 Darwin/24.6.0"
	uaNotifSvcExt = "NotificationServiceExtension/5 CFNetwork/3860.600.12 Darwin/25.5.0"
)

// The notification-preview tag exists for Apple's notification service
// extensions fetching a push notification's rich preview.  Its entries must
// be taggable (dashboards / drill-down label them) while joining NONE of the
// IsBot category buckets: search_ai would rescue on the UA string alone in
// forward-auth (these clients call from residential IPs -- the UA is the
// whole spoof surface), and the unmapped-tag "service" fallback would
// challenge-target the UA there while native stayed neutral.  The actual
// rescue is the guarded UA+JA4 composite in both wires.
func TestNotificationPreviewTagIsGuardedOnly(t *testing.T) {
	for _, ua := range []string{uaNotifExt, uaNotifSvcExt} {
		if got := LookupTag(ua); got != NotificationPreviewTag {
			t.Errorf("LookupTag(%q) = %q, want %q", ua, got, NotificationPreviewTag)
		}
		if got := IsBot(ua, "").String(); got == "search_ai" || got == "service" {
			t.Errorf("IsBot(%q) = %q -- the guarded tag must not join a category bucket", ua, got)
		}
	}
	// A UA that merely names the extension without the CFNetwork stack is not
	// the client this tag describes (and is the cheapest spoof shape).
	if got := LookupTag("NotificationExtension/3"); got == NotificationPreviewTag {
		t.Error("bare NotificationExtension/3 without CFNetwork must not match the tag")
	}
}
