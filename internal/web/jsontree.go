package web

import (
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"sort"
	"strings"
)

// jsonTree turns a JSON document into a nested <dl> for the Data tab.
// Objects become dl/dt/dd, arrays become ul, scalars are escaped text.
// Null and empty values are dimmed so the eye lands on what's populated.
func jsonTree(raw string) template.HTML {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return template.HTML("<pre class=\"log\">" + html.EscapeString(raw) + "</pre>") // #nosec G203
	}
	var b strings.Builder
	renderNode(&b, v)
	return template.HTML(b.String()) // #nosec G203 -- all leaves go through html.EscapeString
}

func renderNode(b *strings.Builder, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString(`<dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">`)
		for _, k := range keys {
			b.WriteString(`<dt class="text-muted-foreground">`)
			b.WriteString(html.EscapeString(k))
			b.WriteString(`</dt><dd>`)
			renderNode(b, x[k])
			b.WriteString(`</dd>`)
		}
		b.WriteString(`</dl>`)
	case []any:
		if len(x) == 0 {
			b.WriteString(`<span class="text-muted-foreground">[]</span>`)
			return
		}
		if allScalars(x) {
			parts := make([]string, len(x))
			for i, e := range x {
				parts[i] = html.EscapeString(scalarString(e))
			}
			b.WriteString(strings.Join(parts, ", "))
			return
		}
		b.WriteString(`<ul class="list-disc pl-5">`)
		for _, e := range x {
			b.WriteString(`<li>`)
			renderNode(b, e)
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul>`)
	case nil:
		b.WriteString(`<span class="text-muted-foreground">null</span>`)
	default:
		s := scalarString(x)
		if s == "" {
			b.WriteString(`<span class="text-muted-foreground">""</span>`)
		} else {
			b.WriteString(html.EscapeString(s))
		}
	}
}

func allScalars(xs []any) bool {
	for _, e := range xs {
		switch e.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func scalarString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case bool:
		return fmt.Sprintf("%t", x)
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", x)
	}
}
