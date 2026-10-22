package handlers

import (
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// fillPreviewVerify marks the UA-filter rows of the link-preview fetchers the
// name-and-network pair verifies (nginxconf/previewverify.go): the networks
// it checks against, and whether the check is live for the row -- the
// fetcher is passed and an ASN mmdb is configured to walk.
func fillPreviewVerify(v *upstreamView, s settings.Settings) {
	if v == nil {
		return
	}
	live := nginxconf.PreviewVerifiedPatterns(s.Nginx)
	asn := strings.TrimSpace(s.IPGeo.MMDBASNPath) != ""
	for gi := range v.Groups {
		for ri := range v.Groups[gi].Rows {
			row := &v.Groups[gi].Rows[ri]
			f := nginxconf.PreviewFetcherFor(row.Pattern)
			if f == nil {
				continue
			}
			row.PreviewASNs = f.ASNList()
			_, white := live[row.Pattern]
			row.PreviewActive = white && asn
		}
	}
}
