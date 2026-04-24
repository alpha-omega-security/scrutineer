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

func TestPrettyJSON(t *testing.T) {
	got := prettyJSON(`{"a":1,"b":[2,3]}`)
	want := "{\n  \"a\": 1,\n  \"b\": [\n    2,\n    3\n  ]\n}"
	if got != want {
		t.Errorf("indent:\ngot  %q\nwant %q", got, want)
	}
	if prettyJSON("# heading\nnot json") != "# heading\nnot json" {
		t.Error("non-JSON input should pass through unchanged")
	}
}
