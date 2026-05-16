// Package feedserver: hub-side (= aggregator server) implementation for unmask.sh.
//
// Role:
//   - POST /api/feed/register : issue an anonymous token
//   - POST /api/feed/submit   : Bearer token + receive BAN reports (= insert into submissions)
//   - cron aggregates submissions → judge → emits feed.json
//
// Not used by ordinary installs (= client side).  Only enable Server on the
// unmask.sh production node by setting settings.FeedServer.Enabled=true + DBPath.
package feedserver

// SubmitRequest: same schema as sharedfeed.SubmitRequest (= JSON compatible).
// Defined in a separate package so the hub does not depend on the client package.
type SubmitRequest struct {
	IP      string `json:"ip"`
	JA4     string `json:"ja4,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// RegisterRequest / RegisterResponse: schema exchanged when the client
// POSTs to /api/feed/register.
type RegisterRequest struct {
	UnmaskVersion string `json:"unmask_version,omitempty"`
}

type RegisterResponse struct {
	Token string `json:"token"`
}

// Limits.
const (
	MaxCommentLen  = 280 // max length for the submitted comment (= clamped by rune count)
	MaxReasonLen   = 200 // max length for reason
	MaxJA4Len      = 64  // upper bound for the JA4 string (= typically 36 chars + safety margin)
	MaxIPLen       = 45  // max IPv6 textual length (= 8x4 + 7 separators)
	TokenByteLen   = 32  // raw token byte count (= hex 64 chars)
	RegisterRateMu = 60  // per-IP rate limit window for /register, in seconds (= 1 req / 60s)
)
