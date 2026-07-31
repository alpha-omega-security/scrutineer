package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// A template error raised after some output has already been produced must
// still yield a clean 500. Executing straight into the ResponseWriter commits
// a 200 plus the partial HTML before the error is known, so the http.Error
// that follows cannot change the status and only appends plain text to a
// half-rendered page (#573).
func TestRenderTemplateErrorAfterPartialOutput(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const marker = "PARTIAL-OUTPUT-MARKER"
	_, err := s.tmpl.New("boom_test.html").
		Funcs(map[string]any{
			"boom": func() (string, error) { return "", errors.New("boom") },
		}).
		// The padding matters: bufio in net/http only flushes to the recorder
		// once enough bytes accumulate, so a short prefix could pass by luck
		// rather than because the fix works.
		Parse(`<!doctype html><title>t</title><div>` + marker +
			strings.Repeat("x", 8<<10) + `</div>{{ boom }}`)
	if err != nil {
		t.Fatalf("parse test template: %v", err)
	}

	w := httptest.NewRecorder()
	s.render(w, localReq("GET", "/"), "boom_test.html", nil)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if got := w.Body.String(); strings.Contains(got, marker) {
		t.Errorf("response carries partially rendered HTML; body starts: %q", got[:min(len(got), 120)])
	}
	if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want the plain-text error type, not HTML", ct)
	}
}

// The success path is unchanged apart from now being able to declare its
// length, since the whole body is known before anything is written.
func TestRenderSuccessSetsHTMLHeaders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const body = "<!doctype html><title>ok</title><p>hello</p>"
	if _, err := s.tmpl.New("ok_test.html").Parse(body); err != nil {
		t.Fatalf("parse test template: %v", err)
	}

	w := httptest.NewRecorder()
	s.render(w, localReq("GET", "/"), "ok_test.html", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != body {
		t.Errorf("body = %q, want %q", got, body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cl := w.Header().Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(body))
	}
}

// Buffers are pooled and reused, so a large page must not leave its bytes
// visible to the next render.
func TestRenderPooledBufferDoesNotLeakBetweenPages(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const leak = "LEAK-FROM-FIRST-PAGE"
	if _, err := s.tmpl.New("big_test.html").Parse(leak + strings.Repeat("y", 4<<10)); err != nil {
		t.Fatalf("parse big template: %v", err)
	}
	if _, err := s.tmpl.New("small_test.html").Parse("small"); err != nil {
		t.Fatalf("parse small template: %v", err)
	}

	s.render(httptest.NewRecorder(), localReq("GET", "/"), "big_test.html", nil)

	w := httptest.NewRecorder()
	s.render(w, localReq("GET", "/"), "small_test.html", nil)
	if got := w.Body.String(); got != "small" {
		t.Errorf("body = %q, want %q — pooled buffer was not reset", got, "small")
	}
}
