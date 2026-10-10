package aitools

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// The config.yml side of "where is this set": every key the settings file
// carries, flattened to its dotted path with the current value, so an answer
// can name the key beside the admin's field.  Secrets are only said to be
// set.

var secretKeyRE = regexp.MustCompile(`(?i)(secret|password|passwd|token|api_key|apikey|_key$|^key$|dsn)`)

type configKey struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// flattenConfig walks v (the settings struct) by its yaml tags.
func flattenConfig(v any) []configKey {
	var out []configKey
	flattenInto(reflect.ValueOf(v), "", &out, 0)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func flattenInto(v reflect.Value, prefix string, out *[]configKey, depth int) {
	if depth > 8 {
		return
	}
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := f.Tag.Get("yaml")
			name := strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				if f.Anonymous {
					flattenInto(v.Field(i), prefix, out, depth+1)
					continue
				}
				name = strings.ToLower(f.Name)
			}
			key := name
			if prefix != "" {
				key = prefix + "." + name
			}
			flattenInto(v.Field(i), key, out, depth+1)
		}
	case reflect.Map:
		if v.Len() == 0 {
			return
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface()) })
		for _, k := range keys {
			flattenInto(v.MapIndex(k), prefix+"."+fmt.Sprint(k.Interface()), out, depth+1)
		}
	case reflect.Slice, reflect.Array:
		if v.Len() == 0 {
			return
		}
		if v.Type().Elem().Kind() == reflect.Struct || v.Type().Elem().Kind() == reflect.Pointer || v.Type().Elem().Kind() == reflect.Map {
			for i := 0; i < v.Len() && i < 20; i++ {
				flattenInto(v.Index(i), fmt.Sprintf("%s[%d]", prefix, i), out, depth+1)
			}
			return
		}
		var parts []string
		for i := 0; i < v.Len() && i < 40; i++ {
			parts = append(parts, fmt.Sprint(v.Index(i).Interface()))
		}
		if v.Len() > 40 {
			parts = append(parts, fmt.Sprintf("... %d in all", v.Len()))
		}
		*out = append(*out, configKey{Key: prefix, Value: redact(prefix, strings.Join(parts, ", "))})
	default:
		if prefix == "" {
			return
		}
		*out = append(*out, configKey{Key: prefix, Value: redact(prefix, fmt.Sprint(v.Interface()))})
	}
}

func redact(key, val string) string {
	if val != "" && secretKeyRE.MatchString(key) {
		return "(set; not shown)"
	}
	if len([]rune(val)) > 160 {
		return string([]rune(val)[:160]) + "…"
	}
	return val
}

// configKeysMatching returns the keys whose path or value carries any of
// the words, a dotted or underscored path reading as words.
func configKeysMatching(keys []configKey, words []string) []configKey {
	var out []configKey
	for _, k := range keys {
		hay := strings.ToLower(strings.NewReplacer(".", " ", "_", " ", "[", " ", "]", " ").Replace(k.Key) + " " + k.Key + " " + k.Value)
		for _, w := range words {
			if strings.Contains(hay, w) {
				out = append(out, k)
				break
			}
		}
		if len(out) >= 30 {
			break
		}
	}
	return out
}

// queryWords lower-cases and splits a query the way the admin's outline
// search does, for the same hits on either side.
func queryWords(q string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ',' || r == '、' || r == '・' || r == '?' || r == '？' || r == '/' || r == '(' || r == ')'
	}) {
		w = strings.Trim(w, ".:;\"'")
		if w == "" || (len([]rune(w)) < 2 && w < "\u0080") {
			continue
		}
		out = append(out, w)
	}
	return out
}
