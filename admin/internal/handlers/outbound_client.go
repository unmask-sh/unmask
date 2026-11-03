package handlers

import "github.com/unmask-sh/unmask/admin/internal/outbound"

// outboundClient is the HTTP client behind the admin's own fetches of
// operator-configured or remote destinations -- the Community Bans hub
// proxies, the version check, the public-address probe.  Under the outbound
// policy (internal/outbound): the cloud metadata addresses and, by default,
// loopback are refused on the resolved address.  No timeout of its own:
// each request bounds itself with a context.
var outboundClient = outbound.Client(0)
