// Local-mute helpers for the "共有 BAN" tab.
//
// A mute is install-local: the entry stays on the hub (= other installs keep
// enforcing it), but this install drops it before WriteMapFiles, even when
// subscribe_mode = fetch_apply.  The key shape encodes the match identity so
// one entry can be muted without collateral on a different match kind:
//
//	ip_only:<ip>
//	ja4_only:<ja4>
//	ip_ja4:<ip>|<ja4>
package communitybans

import "strings"

// MuteKey returns the canonical mute-list key for a feed entry.  Returns ""
// when neither IP nor JA4 is set (= nothing to identify the row by).
//
// The Match field is the primary discriminator; for legacy rows without a
// Match value the key is inferred from which of IP / JA4 is present.
func MuteKey(e FeedEntry) string {
	match := string(e.Match)
	if match == "" {
		switch {
		case e.IP != "" && e.JA4 != "":
			match = "ip_ja4"
		case e.IP != "":
			match = "ip_only"
		case e.JA4 != "":
			match = "ja4_only"
		default:
			return ""
		}
	}
	switch match {
	case "ip_only":
		if e.IP == "" {
			return ""
		}
		return "ip_only:" + e.IP
	case "ja4_only":
		if e.JA4 == "" {
			return ""
		}
		return "ja4_only:" + e.JA4
	case "ip_ja4":
		if e.IP == "" || e.JA4 == "" {
			return ""
		}
		return "ip_ja4:" + e.IP + "|" + e.JA4
	}
	return ""
}

// muteLookup builds a fast lookup set from the LocalMutes string slice.
// Empty / blank entries are dropped; duplicates collapse.
func muteLookup(mutes []string) map[string]bool {
	if len(mutes) == 0 {
		return nil
	}
	out := make(map[string]bool, len(mutes))
	for _, m := range mutes {
		m = strings.TrimSpace(m)
		if m != "" {
			out[m] = true
		}
	}
	return out
}

// excludeMutedEntries returns the entries that are NOT in the mute set, plus
// the count removed.  When the mute set is empty the input is returned as-is
// with zero skipped.
func excludeMutedEntries(entries []FeedEntry, mutes []string) ([]FeedEntry, int) {
	set := muteLookup(mutes)
	if len(set) == 0 {
		return entries, 0
	}
	kept := make([]FeedEntry, 0, len(entries))
	skipped := 0
	for _, e := range entries {
		if set[MuteKey(e)] {
			skipped++
			continue
		}
		kept = append(kept, e)
	}
	return kept, skipped
}
