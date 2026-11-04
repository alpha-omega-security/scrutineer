package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
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

// TestFindingLifecycleSteps pins the progress line to the main track, split at
// the finding's status, and its absence off the track.
func TestFindingLifecycleSteps(t *testing.T) {
	var got []string
	for _, st := range findingLifecycleSteps(db.FindingReady) {
		got = append(got, st.Name+"="+st.State)
	}
	want := "new=done enriched=done triaged=done ready=current reported=todo acknowledged=todo fixed=todo published=todo"
	if strings.Join(got, " ") != want {
		t.Errorf("steps = %q, want %q", strings.Join(got, " "), want)
	}
	for _, status := range []db.FindingLifecycle{db.FindingRejected, db.FindingDuplicate, "bogus"} {
		if steps := findingLifecycleSteps(status); steps != nil {
			t.Errorf("%s: steps = %v, want none", status, steps)
		}
	}
}

// TestFindingShowGroupsSectionsIntoTabs pins each section to its tab panel and
// the lifecycle line to on-track statuses.
func TestFindingShowGroupsSectionsIntoTabs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	render := func() string {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body)
		}
		return w.Body.String()
	}
	if body := render(); !strings.Contains(body, "No analysis recorded for this finding yet.") {
		t.Error("finding without analysis does not say so on the Analysis tab")
	}

	if err := s.DB.Model(&f).Updates(map[string]any{"trace": "Trace text.", "status": db.FindingReady}).Error; err != nil {
		t.Fatal(err)
	}
	body := render()
	if strings.Contains(body, "No analysis recorded for this finding yet.") {
		t.Error("finding with a trace still says it has no analysis")
	}
	panels := []string{`id="fp-analysis"`, `id="fp-remediation"`, `id="fp-disclosure"`, `id="fp-activity"`}
	sections := map[string][]string{
		`id="fp-analysis"`:    {"Step 1: Trace"},
		`id="fp-remediation"`: {"Fix validation"},
		`id="fp-disclosure"`:  {`id="disclosure"`, `id="disclosure-fields"`, `id="communications"`, `id="references"`},
		`id="fp-activity"`:    {`id="notes"`, `id="reviews"`, `id="labels"`, "History"},
	}
	for i, panel := range panels {
		start := strings.Index(body, panel)
		end := len(body)
		if i+1 < len(panels) {
			end = strings.Index(body, panels[i+1])
		}
		if start < 0 || end < start {
			t.Fatalf("panel %s missing or out of order", panel)
		}
		for _, section := range sections[panel] {
			if !strings.Contains(body[start:end], section) {
				t.Errorf("%s is not inside %s", section, panel)
			}
		}
	}
	current, _, _ := strings.Cut(body[strings.Index(body, `aria-current="step"`)+1:], "</li>")
	if !strings.Contains(body, `aria-label="Lifecycle"`) || !strings.Contains(current, "ready") {
		t.Errorf("ready finding does not mark ready as the current lifecycle step: %q", current)
	}

	if err := s.DB.Model(&f).Update("status", db.FindingRejected).Error; err != nil {
		t.Fatal(err)
	}
	body = render()
	if strings.Contains(body, `aria-label="Lifecycle"`) {
		t.Error("rejected finding still shows the lifecycle line")
	}
	if !strings.Contains(body, `">rejected</span>`) {
		t.Error("rejected finding lost its status badge")
	}
}
