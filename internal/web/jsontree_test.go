package web

import (
	"strings"
	"testing"
)

func TestJSONTree(t *testing.T) {
	out := string(jsonTree(`{"a":1,"b":null,"c":["x","y"],"d":{"e":"<f>"}}`))
	for _, want := range []string{
		`<dt class="text-muted-foreground">a</dt><dd>1</dd>`,
		`>null<`,
		`x, y`,
		`&lt;f&gt;`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
}

func TestJSONTreeBadInput(t *testing.T) {
	out := string(jsonTree("not json"))
	if !strings.Contains(out, "not json") {
		t.Errorf("should fall back to pre: %s", out)
	}
}
