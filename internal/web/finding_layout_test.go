package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFindingShowMetadataPrecedesActions(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	if err := s.DB.Model(&f).Updates(map[string]any{
		"location":         "src/handlers/request.go:42",
		"disclosure_draft": "## Summary\n\nSaved disclosure text.",
	}).Error; err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	previous := -1
	for _, marker := range []string{
		`<dt class="text-muted-foreground font-semibold">Severity</dt>`,
		`<code class="break-all">src/handlers/request.go:42</code>`,
		"Awaiting verification",
		`id="verification-run"`,
		`id="disclosure"`,
		"Saved disclosure text.",
	} {
		position := strings.Index(body, marker)
		if position < 0 || position <= previous {
			t.Fatalf("missing or out-of-order page content: %q", marker)
		}
		previous = position
	}
	for _, marker := range []string{`id="verification-run"`, `id="disclosure"`} {
		if count := strings.Count(body, marker); count != 1 {
			t.Errorf("%s occurs %d times, want 1", marker, count)
		}
	}
}
