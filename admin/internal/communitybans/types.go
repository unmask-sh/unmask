// Package communitybans: client for the shared BAN feed.
//
// Role:
//   - register: at startup, fetch a token from the unmask.sh register endpoint.
//   - submit:   on BAN operations, if share=true POST (ip, ja4, reason, comment)
//     to unmask.sh.  The BAN itself still succeeds if the post fails.
//   - pull:     fetch the feed JSON every 1h and atomic-write
//     /etc/unmask/community-bans-*.map (= ipja4 / ja4 / ip).  nginx
//     then derives $community_bans_hit via include + map → on hit, lock
//     to CAPTCHA.
//
// Design principles:
//   - The judgment (= which of IP / JA4 / IP+JA4 to match against) is decided
//     on the server side (= unmask.sh).  The client is a dumb consumer that
//     only reads entry.Match.
//   - submit / subscribe are **independent opt-ins**.  Either alone is valid.
//   - Enforcement is always CAPTCHA (= reduces legal exposure + tolerates false positives).
//   - Until terms are accepted (= settings.CommunityBans.TermsAcceptedAt > 0),
//     submit is forcibly disabled.
package communitybans

// MatchKind: kind of match logic for a feed entry.
type MatchKind string

const (
	MatchIPJA4  MatchKind = "ip_ja4"
	MatchJA4    MatchKind = "ja4_only"
	MatchIPOnly MatchKind = "ip_only"
)

// SubmitRequest: client → unmask.sh submit payload.
type SubmitRequest struct {
	IP      string `json:"ip"`
	JA4     string `json:"ja4,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// RegisterRequest: client → unmask.sh register payload (= optional metadata).
type RegisterRequest struct {
	UnmaskVersion string `json:"unmask_version,omitempty"`
}

// RegisterResponse: unmask.sh → client.
type RegisterResponse struct {
	Token string `json:"token"`
}

// Comment: collects multiple submitters' free-form comments inside a feed entry.
type Comment struct {
	Text        string `json:"text"`
	SubmittedAt int64  `json:"submitted_at"`
}

// FeedEntry: one row of the feed JSON.  Judgement is decided on the server
// side; the client only routes into the right map based on match.
type FeedEntry struct {
	Match      MatchKind `json:"match"`
	IP         string    `json:"ip,omitempty"`
	JA4        string    `json:"ja4,omitempty"`
	Confidence float64   `json:"confidence,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Comments   []Comment `json:"comments,omitempty"`
	ExpiresAt  int64     `json:"expires_at,omitempty"`
}

// FeedDocument: the entire JSON returned by pull.
type FeedDocument struct {
	GeneratedAt int64       `json:"generated_at"`
	Version     int         `json:"version"`
	Entries     []FeedEntry `json:"entries"`
}
