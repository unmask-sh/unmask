package feedserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/feedserver/judge"
)

// FeedComment: an individual comment bundled into feed.json.  The token id
// of the commenter is not exposed (= keep "who" private).  Only text + submitted_at.
type FeedComment struct {
	Text        string `json:"text"`
	SubmittedAt int64  `json:"submitted_at"`
}

// FeedEntry: one hit entry.  Same schema as sharedfeed.FeedEntry (= JSON compatible).
type FeedEntry struct {
	Match      string        `json:"match"`
	IP         string        `json:"ip,omitempty"`
	JA4        string        `json:"ja4,omitempty"`
	Confidence float64       `json:"confidence"`
	Reason     string        `json:"reason,omitempty"`
	Comments   []FeedComment `json:"comments,omitempty"`
	ExpiresAt  int64         `json:"expires_at"`
}

// FeedDocument: top-level of feed.json.
type FeedDocument struct {
	GeneratedAt int64       `json:"generated_at"`
	Version     int         `json:"version"`
	Entries     []FeedEntry `json:"entries"`
}

// BuildAndWrite: aggregate the submissions table → run CombinedJudge →
// atomic-write the FeedDocument to a file.  Call from cron roughly every hour.
//
// On failure, leave the file alone and return the error (= the old feed.json
// stays in place, so clients still receive a non-degraded view).
func (s *Server) BuildAndWrite(ctx context.Context) error {
	doc, err := s.Build(ctx)
	if err != nil {
		return err
	}
	path := s.cfg.ResolvedFeedPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir feed dir: %w", err)
	}
	tmp := path + ".tmp"
	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal feed: %w", err)
	}
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	s.logf("feedserver: wrote %d entries to %s", len(doc.Entries), path)
	return nil
}

// Build: aggregate + judge only.  Does not write (= for tests / dry-run).
func (s *Server) Build(ctx context.Context) (FeedDocument, error) {
	expiryDays := s.cfg.ResolvedExpiryDays()
	cutoff := time.Now().Add(-time.Duration(expiryDays) * 24 * time.Hour).Unix()

	// 1) Aggregate per (ip, ja4) in one query.  Read comment / reason in a
	//    separate query after aggregation (= narrowed to top-N to keep load down).
	pairs, err := s.aggregatePairs(ctx, cutoff)
	if err != nil {
		return FeedDocument{}, err
	}

	// 2) Build per-ip and per-ja4 totals (= input for ip_only / ja4_only judgement).
	ipAgg := make(map[string]aggCount)  // ip → (reports, tokens)
	ja4Agg := make(map[string]aggCount) // ja4 → (reports, tokens)
	for _, p := range pairs {
		ipAgg[p.IP] = aggCount{
			Reports: ipAgg[p.IP].Reports + p.Reports,
			Tokens:  setUnion(ipAgg[p.IP].Tokens, p.Tokens),
		}
		if p.JA4 != "" {
			ja4Agg[p.JA4] = aggCount{
				Reports: ja4Agg[p.JA4].Reports + p.Reports,
				Tokens:  setUnion(ja4Agg[p.JA4].Tokens, p.Tokens),
			}
		}
	}

	jud := s.buildJudger()

	out := make([]FeedEntry, 0, len(pairs))
	dedupKey := make(map[string]bool) // emit the same ip_only / ja4_only entry only once
	for _, p := range pairs {
		ip := p.IP
		ja4 := p.JA4
		in := judge.Input{
			IP:              ip,
			JA4:             ja4,
			Reports:         p.Reports,
			UniqueTokens:    len(p.Tokens),
			IPOnlyReports:   ipAgg[ip].Reports,
			JA4OnlyReports:  ja4Agg[ja4].Reports,
			UniqueTokensIP:  len(ipAgg[ip].Tokens),
			UniqueTokensJA4: len(ja4Agg[ja4].Tokens),
			FirstSeen:       p.FirstSeen,
			LastSeen:        p.LastSeen,
		}
		d := jud.Judge(ctx, in)
		if d.Match == judge.MatchNone {
			continue
		}
		// dedup key (= emit the same ip / ja4 once per match kind)
		key := string(d.Match) + "|"
		switch d.Match {
		case judge.MatchIPJA4:
			key += ip + "|" + ja4
		case judge.MatchJA4:
			key += ja4
		case judge.MatchIPOnly:
			key += ip
		}
		if dedupKey[key] {
			continue
		}
		dedupKey[key] = true

		entry := FeedEntry{
			Match:      string(d.Match),
			Confidence: d.Confidence,
			ExpiresAt:  p.LastSeen + int64(expiryDays)*24*3600,
		}
		switch d.Match {
		case judge.MatchIPJA4:
			entry.IP, entry.JA4 = ip, ja4
		case judge.MatchJA4:
			entry.JA4 = ja4
		case judge.MatchIPOnly:
			entry.IP = ip
		}

		// fetch reason / comments via a separate query (= top 5).
		if cm, rs, err := s.fetchTopExtras(ctx, d.Match, ip, ja4, 5); err == nil {
			entry.Comments = cm
			if len(rs) > 0 {
				entry.Reason = rs[0]
			}
		}

		out = append(out, entry)
	}

	// Sort: by match kind → confidence desc → key.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Match != out[j].Match {
			return out[i].Match < out[j].Match
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].IP+out[i].JA4 < out[j].IP+out[j].JA4
	})

	return FeedDocument{
		GeneratedAt: time.Now().Unix(),
		Version:     1,
		Entries:     out,
	}, nil
}

// pairAgg: aggregation for a single pair.
type pairAgg struct {
	IP        string
	JA4       string
	Reports   int
	Tokens    map[int64]struct{}
	FirstSeen int64
	LastSeen  int64
}

type aggCount struct {
	Reports int
	Tokens  map[int64]struct{}
}

// aggregatePairs: aggregate feed_submissions per (ip, ja4).
// Exclude expired rows (= submitted_at < cutoff).
func (s *Server) aggregatePairs(ctx context.Context, cutoff int64) ([]pairAgg, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, ja4, token_id, submitted_at
		  FROM feed_submissions
		 WHERE submitted_at >= ?
		 ORDER BY submitted_at ASC
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("aggregate query: %w", err)
	}
	defer rows.Close()

	pairs := make(map[string]*pairAgg)
	for rows.Next() {
		var ip, ja4 string
		var tokenID int64
		var ts int64
		if err := rows.Scan(&ip, &ja4, &tokenID, &ts); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		key := ip + "|" + ja4
		p, ok := pairs[key]
		if !ok {
			p = &pairAgg{
				IP: ip, JA4: ja4,
				Tokens:    make(map[int64]struct{}),
				FirstSeen: ts, LastSeen: ts,
			}
			pairs[key] = p
		}
		p.Reports++
		p.Tokens[tokenID] = struct{}{}
		if ts < p.FirstSeen {
			p.FirstSeen = ts
		}
		if ts > p.LastSeen {
			p.LastSeen = ts
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]pairAgg, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, *p)
	}
	return out, nil
}

// fetchTopExtras: return representative comments / reasons for the adopted (match, ip, ja4).
// Duplicate comments inside a feed entry are harmless, but use LIMIT to
// prefer the most recent comments from each install.
func (s *Server) fetchTopExtras(ctx context.Context, match judge.MatchKind, ip, ja4 string, n int) ([]FeedComment, []string, error) {
	var where string
	args := []any{}
	switch match {
	case judge.MatchIPJA4:
		where = "ip = ? AND ja4 = ?"
		args = append(args, ip, ja4)
	case judge.MatchJA4:
		where = "ja4 = ?"
		args = append(args, ja4)
	case judge.MatchIPOnly:
		where = "ip = ?"
		args = append(args, ip)
	default:
		return nil, nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT comment, reason, submitted_at FROM feed_submissions
		  WHERE `+where+` AND (comment != '' OR reason != '')
		  ORDER BY submitted_at DESC LIMIT ?`,
		append(args, n)...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var cms []FeedComment
	var rs []string
	for rows.Next() {
		var c, r string
		var ts int64
		if err := rows.Scan(&c, &r, &ts); err != nil {
			return nil, nil, err
		}
		if c != "" {
			cms = append(cms, FeedComment{Text: c, SubmittedAt: ts})
		}
		if r != "" {
			rs = append(rs, r)
		}
	}
	return cms, rs, rows.Err()
}

// buildJudger: build a CombinedJudge per settings.FeedServer.JudgeMode.
// The AI side is a stub in v0.1 (= always MatchNone).
func (s *Server) buildJudger() judge.Judger {
	heur := judge.NewHeuristic(s.cfg.ResolvedMinReports())
	return &judge.CombinedJudge{
		Mode:      s.cfg.ResolvedJudgeMode(),
		Heuristic: heur,
		AI:        &judge.AIStub{},
	}
}

// PruneExpired: delete submissions older than ExpiryDays.  Intended to be
// called from the same cron job as BuildAndWrite.
func (s *Server) PruneExpired(ctx context.Context) (int64, error) {
	cutoff := time.Now().Add(-time.Duration(s.cfg.ResolvedExpiryDays()) * 24 * time.Hour).Unix()
	r, err := s.db.ExecContext(ctx, `DELETE FROM feed_submissions WHERE submitted_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return n, nil
}

// setUnion: destructively union two map[int64]struct{} sets.
func setUnion(a, b map[int64]struct{}) map[int64]struct{} {
	if a == nil {
		a = make(map[int64]struct{}, len(b))
	}
	for k := range b {
		a[k] = struct{}{}
	}
	return a
}

// EnsureSQL: re-export for development cases where you query *sql.DB directly.
// (= currently only used by the internal cron; kept around for tests).
var _ = sql.ErrNoRows
