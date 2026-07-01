package handlers

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// PagerData carries everything partial_pager_full needs.  Pages with
// pagination fill one of these in the data map under "Pager", and the
// template loads it via `{{ template "pager_full" .Pager }}`.
//
// BaseURL must already include the leading "?" and end with "&" so the
// template can append "page=N" without thinking about separators.
//
// Matches the parent repo's default: a single page still renders (= the user
// gets "[1]" + count, not a silent gap).  Set HideIfOnePage=true on pages
// that prefer to hide the pager entirely when there's only one page.
type PagerData struct {
	Lang          i18n.Lang
	Current       int
	TotalPages    int
	PerPage       int
	TotalRows     int
	BaseURL       string
	Round         int // ±N around current (default 2)
	Outer         int // anchored at head/tail (default 1)
	ShowInfo      bool
	HideIfOnePage bool
}

// buildPagerData wraps the common page → PagerData fill so callers don't
// re-spell the defaults.
func buildPagerData(lang i18n.Lang, current, totalPages, perPage, totalRows int, baseURL string) PagerData {
	return PagerData{
		Lang:       lang,
		Current:    current,
		TotalPages: totalPages,
		PerPage:    perPage,
		TotalRows:  totalRows,
		BaseURL:    baseURL,
		Round:      2,
		Outer:      1,
		ShowInfo:   true,
	}
}

// buildQueryBase joins non-empty key=value pairs into a "?k=v&" prefix that
// the pager appends "page=N" to.  Empty values are skipped (= no q= when the
// search box is blank).
func buildQueryBase(pairs ...[2]string) string {
	var sb strings.Builder
	sb.WriteByte('?')
	for _, kv := range pairs {
		if kv[1] == "" {
			continue
		}
		sb.WriteString(url.QueryEscape(kv[0]))
		sb.WriteByte('=')
		sb.WriteString(url.QueryEscape(kv[1]))
		sb.WriteByte('&')
	}
	return sb.String()
}

// buildBansBaseURL is the community-bans-specific shorthand for buildQueryBase.
// Keeps the bans handler readable -- the same shape can be reused by other
// pages by adding their own helper next to this one.
func buildBansBaseURL(q, match, sortKey, order string) string {
	return buildQueryBase(
		[2]string{"q", q},
		[2]string{"match", match},
		[2]string{"sort", sortKey},
		[2]string{"order", order},
	)
}

// PagerSeekData feeds partial_pager_seek (= 先頭 / 前へ / 次へ).  Used by
// large-table pages where exact totals are expensive (= audit, hunt event
// log).  Range is an already-rendered caption string so callers can drop
// localised count text in without the template having to know the shape.
type PagerSeekData struct {
	Lang        i18n.Lang
	FirstURL    string
	PrevURL     string
	NextURL     string
	HasPrev     bool
	HasNext     bool
	IsFirstPage bool
	ShowInfo    bool
	Range       string
}

// buildPagerSeekData fills a PagerSeekData from the offset-paginated common
// inputs.  baseURL is the "?" + base-query prefix (already includes the
// trailing "&" -- so the helper can append "offset=N" cleanly).  curOffset
// of <=0 marks the first page.
func buildPagerSeekData(lang i18n.Lang, baseURL string, curOffset, perPage int, hasPrev, hasNext bool, rangeText string) PagerSeekData {
	prev := ""
	if hasPrev {
		off := curOffset - perPage
		if off < 0 {
			off = 0
		}
		if off == 0 {
			prev = baseURL[:len(baseURL)-1] // strip the trailing "&" so the URL stays clean
			if prev == "?" {
				prev = "?"
			}
		} else {
			prev = baseURL + "offset=" + itoa(off)
		}
	}
	next := ""
	if hasNext {
		next = baseURL + "offset=" + itoa(curOffset+perPage)
	}
	first := baseURL
	if len(first) > 0 && first[len(first)-1] == '&' {
		first = first[:len(first)-1]
	}
	if first == "" {
		first = "?"
	}
	return PagerSeekData{
		Lang:        lang,
		FirstURL:    first,
		PrevURL:     prev,
		NextURL:     next,
		HasPrev:     hasPrev,
		HasNext:     hasNext,
		IsFirstPage: curOffset <= 0,
		ShowInfo:    rangeText != "",
		Range:       rangeText,
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
