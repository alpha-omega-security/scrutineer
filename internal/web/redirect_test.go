package web

import (
	"net/http/httptest"
	"testing"
)

// TestRedirect_htmxRefreshesOnSamePageFragment pins HX-Refresh on an htmx
// redirect that only adds a fragment to the current page, and nowhere else.
func TestRedirect_htmxRefreshesOnSamePageFragment(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	for _, tt := range []struct {
		name, current, target, want string
	}{
		{"same page with fragment", "http://localhost/findings/7", "/findings/7#exposure", "true"},
		{"same page already on a fragment", "http://localhost/findings/7#notes", "/findings/7#exposure", "true"},
		{"other page with fragment", "http://localhost/scans/3", "/repositories/1#rt3", ""},
		{"same page without fragment", "http://localhost/findings/7", "/findings/7", ""},
		{"no current URL", "", "/findings/7#exposure", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/findings/7/exposure", nil)
			r.Header.Set("HX-Request", "true")
			if tt.current != "" {
				r.Header.Set("HX-Current-URL", tt.current)
			}
			w := httptest.NewRecorder()
			s.redirect(w, r, tt.target)
			if got := w.Header().Get("HX-Redirect"); got != tt.target {
				t.Errorf("HX-Redirect = %q, want %q", got, tt.target)
			}
			if got := w.Header().Get("HX-Refresh"); got != tt.want {
				t.Errorf("HX-Refresh = %q, want %q", got, tt.want)
			}
		})
	}
}
