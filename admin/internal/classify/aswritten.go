package classify

// The crawler list's patterns are matched without regard to case, by both
// engines: nginx's maps take them with "~*" and the matchers here compile
// them with "(?i)".  That is kinder than the list's authors meant -- they
// write the case they mean, "[wW]get" where either will do -- and it is what
// lets through a crawler whose vendor changed a capital since its entry was
// written, or whose name is found in the address its User-Agent gives.
//
// For a short name it is also what finds the name inside an unrelated word.
// The patterns below are matched as they are written, because read loosely
// each was seen to pass, on its name alone, something that is not that
// crawler:
//
//	Sonic     the tail of a television maker's name, in capitals in the
//	          User-Agent of its sets' browser, and of "Hypersonic"
//	Fetch\/   any client whose product token ends in "fetch/"
//	ICBot\/   any bot whose name ends in "icBot/"
//
// What passed on the first was not a television: the same pages were fetched
// from one address after another, a few requests each, under whichever
// User-Agent got through.  A name-only rescue is open to whoever sends the
// name (the UA filter says so, and stops it per crawler); this only keeps a
// name from being sent by accident, or found by trial.
//
// The rule is in the expression, not in the engine's flag: MatchExpr wraps
// such a pattern in a group that turns case folding off, which Go's regexp
// and PCRE read alike, so a list that mixes the two kinds is still one
// alternation here and one map there.  The pattern itself stays the name the
// crawler goes by everywhere else -- the per-crawler setting, the rows of the
// UA filter, the statistics.
var asWritten = map[string]bool{
	`Sonic`:   true,
	`Fetch\/`: true,
	`ICBot\/`: true,
}

// MatchExpr is the expression a crawler-list pattern is matched with, inside
// a case-insensitive match: the pattern, or for one that is matched as
// written (asWritten) the pattern in a group that restores case.  Every
// matcher built from the list here goes through it (joinAlt,
// buildCrawlerDetail), and so do the User-Agent maps the nginx configuration
// renders (nginxconf's "uarx").
func MatchExpr(pattern string) string {
	if asWritten[pattern] {
		return `(?-i:` + pattern + `)`
	}
	return pattern
}

// AsWrittenPatterns lists the patterns matched as written, for the tests
// that hold the list to the crawler list it names entries of.
func AsWrittenPatterns() []string {
	out := make([]string, 0, len(asWritten))
	for p := range asWritten {
		out = append(out, p)
	}
	return out
}
