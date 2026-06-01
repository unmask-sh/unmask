package dashboard

import (
	"reflect"
	"time"
)

// DisplayLayout is the format the dashboard renders LastSeen / Date cells in.
// "MST" is Go's TZ abbreviation placeholder; time.Time.Format substitutes
// whatever short name loc resolves to (= "UTC", "JST", "PDT", ...).
const DisplayLayout = "2006-01-02 15:04 MST"

// ApplyDisplayLoc rewrites every (LastSeen / Date) string cell on every row
// in `rows` so it reflects loc instead of whatever the SQL driver emitted
// (= UTC at storage time).  Pairs the textual field with its TS sibling:
//
//	LastSeen   ← time.Unix(LastSeenTS, 0).In(loc).Format(DisplayLayout)
//	Date       ← time.Unix(DateTS, 0).In(loc).Format(DisplayLayout)
//
// Rows whose TS sibling is zero / negative are left alone (= "never seen"
// cells stay empty for the template's {{if}} branch).  Accepts either a
// []T slice of structs or any other shape silently (= no-op).
func ApplyDisplayLoc(rows any, loc *time.Location) {
	if loc == nil {
		return
	}
	v := reflect.ValueOf(rows)
	if !v.IsValid() || v.Kind() != reflect.Slice {
		return
	}
	pairs := [...]struct{ ts, str string }{
		{"LastSeenTS", "LastSeen"},
		{"DateTS", "Date"},
	}
	for i := 0; i < v.Len(); i++ {
		e := v.Index(i)
		// Slice elements are addressable, so struct fields can be set
		// in-place; map values are not, which is why this guard exists.
		if e.Kind() != reflect.Struct || !e.CanAddr() {
			continue
		}
		for _, p := range pairs {
			ts := e.FieldByName(p.ts)
			if !ts.IsValid() || ts.Kind() != reflect.Int64 || ts.Int() <= 0 {
				continue
			}
			str := e.FieldByName(p.str)
			if !str.IsValid() || str.Kind() != reflect.String || !str.CanSet() {
				continue
			}
			str.SetString(time.Unix(ts.Int(), 0).In(loc).Format(DisplayLayout))
		}
	}
}
