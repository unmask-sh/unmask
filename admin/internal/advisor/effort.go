package advisor

import "strings"

// effortDefaults: the effort a model runs at when the request names none,
// from the providers' documentation (read 2026-10-12: the platform docs and
// the migration guides for Anthropic, each model's page on
// developers.openai.com for OpenAI).  "-" marks a model that takes no effort
// at all -- naming one is an error there.  A model not listed is unknown:
// the pick says "the model's own" and the request is sent as it is.
//
// Keys are model ids without a date suffix or a "-latest" alias, matched
// whole: a variant (a -pro, a -codex, a -chat) can run on a different
// default from its base model, so it is listed or unknown, never inherited.
var effortDefaults = map[string]string{
	// Anthropic
	"claude-fable-5-1":  "high",
	"claude-mythos-5-1": "high",
	"claude-fable-5":    "high",
	"claude-opus-5-5":   "medium",
	"claude-opus-5":     "high",
	"claude-sonnet-5-5": "high",
	"claude-sonnet-5":   "high",
	"claude-haiku-5-5":  "medium",
	"claude-opus-4-8":   "high",
	"claude-opus-4-7":   "high",
	"claude-opus-4-6":   "high",
	"claude-opus-4-5":   "high",
	"claude-sonnet-4-6": "high",
	"claude-sonnet-4-5": "-",
	"claude-sonnet-4":   "-",
	"claude-haiku-4-5":  "-",
	"claude-opus-4-1":   "-",
	"claude-opus-4":     "-",
	"claude-3-7-sonnet": "-",
	"claude-3-5-sonnet": "-",
	"claude-3-5-haiku":  "-",
	"claude-3-opus":     "-",
	"claude-3-sonnet":   "-",
	"claude-3-haiku":    "-",
	// OpenAI
	"gpt-6-astra":   "medium",
	"gpt-6.1-sol":   "medium",
	"gpt-6-sol":     "medium",
	"gpt-6-luna":    "medium",
	"gpt-5.6-sol":   "medium",
	"gpt-5.6-terra": "medium",
	"gpt-5.6-luna":  "medium",
	"gpt-5.5":       "medium",
	"gpt-5.5-pro":   "high",
	"gpt-5.4":       "none",
	"gpt-5.4-mini":  "none",
	"gpt-5.4-nano":  "none",
	"gpt-5.4-pro":   "medium",
	"gpt-5.2":       "none",
	"gpt-5.1":       "none",
	"gpt-5":         "medium",
	"gpt-5-mini":    "medium",
	"gpt-5-nano":    "medium",
	"gpt-5-pro":     "high",
	"o4-mini":       "medium",
	"o3":            "medium",
	"o3-mini":       "medium",
	"o1":            "medium",
	"gpt-4.1":       "-",
	"gpt-4.1-mini":  "-",
	"gpt-4.1-nano":  "-",
	"gpt-4o":        "-",
	"gpt-4o-mini":   "-",
	"gpt-4-turbo":   "-",
	"gpt-4":         "-",
	"gpt-3.5-turbo": "-",
}

// effortKey is a model id as effortDefaults keys it.
func effortKey(model string) string {
	id := strings.ToLower(strings.TrimSpace(model))
	id = strings.TrimSuffix(id, "-latest")
	return modelDateRE.ReplaceAllString(id, "")
}

// EffortDefault says what a model does with no effort named: def is the
// level it runs at, takes is false for a model that takes no effort at all,
// and known is false when the table does not know the model (then def is ""
// and takes is true -- nothing is held back from it).
func EffortDefault(model string) (def string, takes, known bool) {
	v, ok := effortDefaults[effortKey(model)]
	switch {
	case !ok:
		return "", true, false
	case v == "-":
		return "", false, true
	}
	return v, true, true
}

// TakesEffort is false only for a model known to refuse an effort.
func TakesEffort(model string) bool {
	_, takes, _ := EffortDefault(model)
	return takes
}

// effortToSend is the effort a request carries: the configured (or picked)
// one, unless the model is known to refuse it -- the request then goes out
// without, as the model would run anyway, rather than failing.
func effortToSend(model, effort string) string {
	if effort == "" || !TakesEffort(model) {
		return ""
	}
	return effort
}

// effortFor is the effort a request runs at: the one it carries, else the
// model's own default ("" for a model the table does not know, or one that
// takes no effort).
func effortFor(model, effort string) string {
	if e := effortToSend(model, effort); e != "" {
		return e
	}
	def, _, _ := EffortDefault(model)
	return def
}

// ThinksLong is true where a request runs at xhigh or max: the model may
// think for minutes before it answers, and a caller's time budget should
// allow it.
func ThinksLong(model, effort string) bool {
	switch effortFor(model, effort) {
	case "xhigh", "max":
		return true
	}
	return false
}

// maxTokensFor is max_tokens for a request whose reply needs about reply
// tokens.  Where the model thinks, the thinking counts against the same
// limit and grows with the effort: at xhigh and max the provider's
// guidance is 64K, or the answer is cut off mid-thought (seen at max: the
// review spent all of 8192 thinking and never wrote its JSON); high gets
// half of that, low and medium 16K.  A model that takes no effort, or one
// the table does not know running at its own default, keeps reply: the
// older models cap their output below these.
func maxTokensFor(model, effort string, reply int) int {
	n := reply
	switch effortFor(model, effort) {
	case "xhigh", "max":
		n = 64000
	case "high":
		n = 32000
	case "low", "medium":
		n = 16000
	}
	return max(n, reply)
}
