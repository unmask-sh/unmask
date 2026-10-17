package advisor

import (
	"fmt"
	"regexp"
	"strings"
)

// Price is a model's list price in USD per million tokens, input and output.
type Price struct {
	In  float64
	Out float64
}

// prices: the providers' published list prices, keyed by model id with any
// date suffix dropped (claude-opus-4-5-20251101 -> claude-opus-4-5).  A
// lookup takes the longest key that is the id or a dash-joined prefix of
// it, so a model's dated and -latest ids find it and gpt-5 does not stand
// in for gpt-5.2.  Batch, cache and long-context rates are not here: what
// the page shows is an estimate from these, and the provider's statement is
// the bill.
//
// Anthropic: claude.com/pricing and the platform docs, 2026-10-12.  Haiku
// 5.5 is its rate for prompts up to 100K tokens; a question's turns stay
// far under.  OpenAI: developers.openai.com/api/docs/pricing, 2026-10-12,
// the short-context column.
var prices = map[string]Price{
	// Anthropic
	"claude-fable-5-1":  {10, 50},
	"claude-mythos-5-1": {10, 50},
	"claude-fable-5":    {10, 50},
	"claude-opus-5-5":   {4, 20},
	"claude-opus-5":     {5, 25},
	"claude-sonnet-5-5": {2, 10},
	"claude-sonnet-5":   {2, 10},
	"claude-haiku-5-5":  {0.10, 0.50},
	"claude-opus-4-8":   {5, 25},
	"claude-opus-4-7":   {5, 25},
	"claude-opus-4-6":   {5, 25},
	"claude-opus-4-5":   {5, 25},
	"claude-opus-4-1":   {15, 75},
	"claude-opus-4":     {15, 75},
	"claude-sonnet-4-6": {3, 15},
	"claude-sonnet-4-5": {3, 15},
	"claude-sonnet-4":   {3, 15},
	"claude-haiku-4-5":  {1, 5},
	"claude-3-7-sonnet": {3, 15},
	"claude-3-5-sonnet": {3, 15},
	"claude-3-5-haiku":  {0.80, 4},
	"claude-3-opus":     {15, 75},
	"claude-3-haiku":    {0.25, 1.25},
	// OpenAI
	"gpt-6-astra":   {10, 50},
	"gpt-6.1-sol":   {2, 10},
	"gpt-6-luna":    {0.10, 0.50},
	"gpt-6-sol":     {2, 10},
	"gpt-5.6-sol":   {4, 20},
	"gpt-5.6-terra": {2, 12},
	"gpt-5.6-luna":  {0.20, 1.20},
	"gpt-5.5":       {5, 30},
	"gpt-5.5-pro":   {30, 180},
	"gpt-5.4":       {2.50, 15},
	"gpt-5.4-mini":  {0.75, 4.50},
	"gpt-5.4-nano":  {0.20, 1.25},
	"gpt-5.4-pro":   {30, 180},
	"gpt-5.3-codex": {1.75, 14},
	"gpt-5.2":       {1.75, 14},
	"gpt-5.2-pro":   {21, 168},
	"gpt-5.1":       {1.25, 10},
	"gpt-5":         {1.25, 10},
	"gpt-5-mini":    {0.25, 2},
	"gpt-5-nano":    {0.05, 0.40},
	"gpt-5-pro":     {15, 120},
	"gpt-4.1":       {2, 8},
	"gpt-4.1-mini":  {0.40, 1.60},
	"gpt-4.1-nano":  {0.10, 0.40},
	"gpt-4o":        {2.50, 10},
	"gpt-4o-mini":   {0.15, 0.60},
	"o1":            {15, 60},
	"o1-mini":       {1.10, 4.40},
	"o1-pro":        {150, 600},
	"o3-pro":        {20, 80},
	"o3":            {2, 8},
	"o3-mini":       {1.10, 4.40},
	"o4-mini":       {1.10, 4.40},
	"gpt-4-turbo":   {10, 30},
	"gpt-4":         {30, 60},
	"gpt-3.5-turbo": {0.50, 1.50},
}

// modelDateRE: the date a provider pins a model id with (-20251101,
// -2024-05-13).
var modelDateRE = regexp.MustCompile(`-(?:\d{8}|\d{4}-\d{2}-\d{2})$`)

// PriceFor finds a model's list price; ok is false for a model the table
// does not know -- a local one, or a provider's newer than the table.
func PriceFor(model string) (Price, bool) {
	id := strings.ToLower(strings.TrimSpace(model))
	if p, ok := prices[id]; ok {
		return p, true
	}
	id = modelDateRE.ReplaceAllString(id, "")
	best := ""
	for k := range prices {
		if len(k) > len(best) && (id == k || strings.HasPrefix(id, k+"-")) {
			best = k
		}
	}
	if best == "" {
		return Price{}, false
	}
	return prices[best], true
}

// Cost is what in input and out output tokens come to at the model's list
// price, in USD; ok is false when the price is unknown.
func Cost(model string, in, out int) (float64, bool) {
	return CostOf(model, Usage{Input: in, Output: out})
}

// The prompt cache's rates, as a share of the input rate: a token read from
// the cache is a tenth (Anthropic and OpenAI alike), a token written to it
// is Anthropic's one and a quarter (OpenAI writes for nothing and reports no
// writes).  Estimates, like the list prices they scale.
const (
	cacheReadRate  = 0.1
	cacheWriteRate = 1.25
)

// CostOf is Cost with the prompt cache told apart: the input tokens read
// from or written to it at their rates, the rest at the input rate.
func CostOf(model string, u Usage) (float64, bool) {
	p, ok := PriceFor(model)
	if !ok {
		return 0, false
	}
	full := u.Input - u.CacheRead - u.CacheWrite
	if full < 0 {
		full = 0
	}
	return (float64(full)*p.In + float64(u.CacheRead)*p.In*cacheReadRate + float64(u.CacheWrite)*p.In*cacheWriteRate + float64(u.Output)*p.Out) / 1e6, true
}

// FormatUSD writes a cost as the page shows it: to the cent from a tenth of
// a dollar up, to the thousandth below, and "<$0.001" under half of one.
func FormatUSD(usd float64) string {
	switch {
	case usd >= 0.1:
		return fmt.Sprintf("$%.2f", usd)
	case usd >= 0.0005:
		return fmt.Sprintf("$%.3f", usd)
	default:
		return "<$0.001"
	}
}
