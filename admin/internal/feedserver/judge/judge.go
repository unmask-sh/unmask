// Package judge: decide whether a (ip, ja4) feed entry should be published.
// For each pair we look at how many installs reported it, what comments are
// attached, how wide the time window is, etc., and decide whether to publish
// it on the feed as ip_ja4 / ja4_only / ip_only (= or to skip it).
//
// Four-mode structure:
//   heuristic_only : lightweight + deterministic.  No AI dependency.
//   ai_only        : leave it entirely to AI.  Yields no result when AI is unavailable.
//   and            : adopt only when both agree (= strict)
//   or             : adopt when either agrees (= lenient)
//   ai_primary     : prefer AI's verdict, fall back to heuristic when AI is unavailable
//
// AI judge is a stub in v0.1 (= always returns Skip).  Once AIEndpoint
// configuration arrives, the intent is to implement it in a separate file.
package judge

import (
	"context"
	"strings"
)

// MatchKind: feed entry match type.  Same string set as sharedfeed.MatchKind.
type MatchKind string

const (
	MatchNone   MatchKind = ""        // do not adopt (= keep out of the feed)
	MatchIPJA4  MatchKind = "ip_ja4"  // hit on "ip and ja4"
	MatchJA4    MatchKind = "ja4_only"
	MatchIPOnly MatchKind = "ip_only"
)

// Input: input for one (ip, ja4) aggregation.
type Input struct {
	IP            string
	JA4           string
	Reports       int      // submission count for this (ip, ja4)
	UniqueTokens  int      // number of reporting install tokens (= duplicates from the same install excluded)
	IPOnlyReports int      // total submissions for the same ip with different ja4 (= used for ip_only judgement)
	JA4OnlyReports int     // total submissions for the same ja4 with different ip (= used for ja4_only judgement)
	UniqueTokensIP int     // unique token count when aggregating by ip only
	UniqueTokensJA4 int    // unique token count when aggregating by ja4 only
	Comments      []string // free-text comments attached (= input for the AI judge)
	Reasons       []string // attached reasons
	FirstSeen     int64
	LastSeen      int64
}

// Decision: the judge's output.
type Decision struct {
	Match      MatchKind
	Confidence float64 // 0.0 to 1.0.  Embedded in the feed and shown in the client / browse UI.
	Source     string  // "heuristic" / "ai" / "combined" etc.  For auditing.
}

// Judger: one mode's worth of judger.
type Judger interface {
	Judge(ctx context.Context, in Input) Decision
}

// Heuristic: lightweight rule-based judge.
//   - the same (ip, ja4) reported by >= MinReportsIPJA4 unique installs -> ip_ja4
//   - the same ja4 reported by >= MinReportsJA4 unique installs across different ips -> ja4_only
//   - the same ip reported by >= MinReportsIP unique installs across different ja4s -> ip_only
//   - none of the above -> None
type Heuristic struct {
	MinReportsIPJA4 int
	MinReportsJA4   int
	MinReportsIP    int
}

func NewHeuristic(minReports int) *Heuristic {
	if minReports <= 0 {
		minReports = 1
	}
	return &Heuristic{
		MinReportsIPJA4: minReports,
		MinReportsJA4:   minReports * 2, // ja4_only has high inertia, use a higher threshold
		MinReportsIP:    minReports * 2,
	}
}

func (h *Heuristic) Judge(_ context.Context, in Input) Decision {
	// Priority: ip_only > ja4_only > ip_ja4 (= evaluate broader matches first
	// so "same ja4 across multiple IPs -> clearly a botnet" gets promoted to
	// ja4_only).
	if in.UniqueTokensIP >= h.MinReportsIP && in.IPOnlyReports >= h.MinReportsIP {
		return Decision{
			Match:      MatchIPOnly,
			Confidence: confidenceFromReports(in.UniqueTokensIP, h.MinReportsIP),
			Source:     "heuristic",
		}
	}
	if in.UniqueTokensJA4 >= h.MinReportsJA4 && in.JA4OnlyReports >= h.MinReportsJA4 && in.JA4 != "" {
		return Decision{
			Match:      MatchJA4,
			Confidence: confidenceFromReports(in.UniqueTokensJA4, h.MinReportsJA4),
			Source:     "heuristic",
		}
	}
	if in.UniqueTokens >= h.MinReportsIPJA4 && in.JA4 != "" {
		return Decision{
			Match:      MatchIPJA4,
			Confidence: confidenceFromReports(in.UniqueTokens, h.MinReportsIPJA4),
			Source:     "heuristic",
		}
	}
	if in.UniqueTokens >= h.MinReportsIPJA4 && in.JA4 == "" {
		// ja4 unknown -> treat as ip_only (= single-shot ip ban).  Use the normal threshold.
		return Decision{
			Match:      MatchIPOnly,
			Confidence: confidenceFromReports(in.UniqueTokens, h.MinReportsIPJA4),
			Source:     "heuristic",
		}
	}
	return Decision{Match: MatchNone, Source: "heuristic"}
}

// confidenceFromReports: map the report count to 0.5 (= min reports) ..
// 1.0 (= >= 4x min reports).
func confidenceFromReports(n, min int) float64 {
	if n <= min {
		return 0.5
	}
	v := 0.5 + 0.5*float64(n-min)/float64(min*3)
	if v > 1.0 {
		v = 1.0
	}
	return v
}

// AIStub: v0.1 stub of the AI judge.  Always returns MatchNone +
// Source="ai_unavailable".  The real implementation is deferred (= when
// AIEndpoint is set, swap to AIClient in a separate file).
type AIStub struct{}

func (a *AIStub) Judge(_ context.Context, _ Input) Decision {
	return Decision{Match: MatchNone, Source: "ai_unavailable"}
}

// CombinedJudge: compose two judgers per the mode.
//
// modes:
//   "heuristic_only" : Heuristic only
//   "ai_only"        : AI only
//   "and"            : both produced the same non-None MatchKind -> adopt
//   "or"             : prefer Heuristic; if None, use AI
//   "ai_primary"     : prefer AI; if None, use Heuristic
type CombinedJudge struct {
	Mode      string
	Heuristic Judger
	AI        Judger
}

func (c *CombinedJudge) Judge(ctx context.Context, in Input) Decision {
	mode := strings.TrimSpace(c.Mode)
	if mode == "" {
		mode = "heuristic_only"
	}
	switch mode {
	case "heuristic_only":
		if c.Heuristic == nil {
			return Decision{Match: MatchNone, Source: "no_judge"}
		}
		return c.Heuristic.Judge(ctx, in)
	case "ai_only":
		if c.AI == nil {
			return Decision{Match: MatchNone, Source: "no_ai"}
		}
		return c.AI.Judge(ctx, in)
	case "and":
		h := safeJudge(c.Heuristic, ctx, in)
		a := safeJudge(c.AI, ctx, in)
		if h.Match != MatchNone && h.Match == a.Match {
			return Decision{
				Match:      h.Match,
				Confidence: (h.Confidence + a.Confidence) / 2,
				Source:     "combined_and",
			}
		}
		return Decision{Match: MatchNone, Source: "and_disagree"}
	case "or":
		h := safeJudge(c.Heuristic, ctx, in)
		if h.Match != MatchNone {
			return h
		}
		return safeJudge(c.AI, ctx, in)
	case "ai_primary":
		a := safeJudge(c.AI, ctx, in)
		if a.Match != MatchNone {
			return a
		}
		return safeJudge(c.Heuristic, ctx, in)
	}
	return Decision{Match: MatchNone, Source: "unknown_mode"}
}

func safeJudge(j Judger, ctx context.Context, in Input) Decision {
	if j == nil {
		return Decision{Match: MatchNone, Source: "nil_judge"}
	}
	return j.Judge(ctx, in)
}
