package main

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	shaFix  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaNeg1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaNeg2 = "cccccccccccccccccccccccccccccccccccccccc"
)

func TestRepoKey(t *testing.T) {
	if got := repoKey("Foo-Bar/Baz.Qux"); got != "foo-bar_baz.qux" {
		t.Fatalf("repoKey: got %q", got)
	}
}

func TestParseCommitLog(t *testing.T) {
	raw := shaFix + "\x1f2024-01-02T00:00:00Z\x1fAlice\x1ffix: bounds check\x1fbody\nmore\x1e\n" +
		"short\x1fonly\x1e\n" +
		shaNeg1 + "\x1f2024-01-03T00:00:00Z\x1fBob\x1frefactor\x1f\x1e"
	recs, err := parseCommitLog(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 well-formed records, got %d", len(recs))
	}
	if recs[0].SHA != shaFix || recs[0].Subject != "fix: bounds check" || !strings.Contains(recs[0].Body, "more") {
		t.Fatalf("record 0 misparsed: %+v", recs[0])
	}
}

func TestParseCommitLogHostileSeparator(t *testing.T) {
	// A commit body containing 0x1e truncates its own record; the next
	// well-formed record must still parse.
	raw := shaFix + "\x1f2024\x1fA\x1fs\x1fbefore\x1eafter\x1e" +
		shaNeg1 + "\x1f2024\x1fB\x1ft\x1f\x1e"
	recs, err := parseCommitLog(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Body != "before" || recs[1].SHA != shaNeg1 {
		t.Fatalf("hostile separator not contained: %+v", recs)
	}
}

func TestMatchMessagesProductionSemantics(t *testing.T) {
	terms, err := matchMessages("../../skills", []string{"go"}, []string{"Fix a\nBounds", "ésecurity", "xss"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(terms[0], "security-shaped-fix") || len(terms[1]) != 0 || len(terms[2]) != 0 {
		t.Fatalf("unexpected production matching: %v", terms)
	}
}

func TestOSVGitFixes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "osv"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := `{"id":"OSV-1","affected":[{"name":"Pkg","ranges":[` +
		`{"type":"GIT","repo":"https://github.com/old/pkg","events":[{"introduced":"0"},{"fixed":"` + shaFix + `"}]},` +
		`{"type":"SEMVER","events":[{"fixed":"1.0.1"}]}]}]}` + "\n" +
		`{"id":"OSV-2","affected":[{"name":"other","ranges":[{"type":"GIT","events":[{"fixed":"` + shaNeg1 + `"}]}]}]}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "osv", "PyPI.jsonl"), []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	pop := map[[2]string]population{{"pypi", "pkg"}: {Ecosystem: "pypi", Name: "Pkg", Repo: "owner/pkg"}}
	ls, err := osvGitFixes(filepath.Join(dir, "osv"), pop)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 1 || ls[0].SHA != shaFix || ls[0].RepoKey != "owner_pkg" || ls[0].Class != "advised" {
		t.Fatalf("unexpected labels: %+v", ls)
	}
}

func TestSampleNegatives(t *testing.T) {
	recs := []logRecord{{SHA: shaFix}, {SHA: shaNeg1}, {SHA: shaNeg2}}
	rng := rand.New(rand.NewSource(1))
	neg := sampleNegatives(recs, map[string]bool{shaFix: true}, "o/r", "o_r", 5, rng)
	if len(neg) != 2 {
		t.Fatalf("want 2 negatives, got %d", len(neg))
	}
	for _, l := range neg {
		if l.SHA == shaFix || l.Class != "negative" {
			t.Fatalf("negative set includes positive or wrong class: %+v", l)
		}
	}
	rng2 := rand.New(rand.NewSource(1))
	neg2 := sampleNegatives([]logRecord{{SHA: shaFix}, {SHA: shaNeg1}, {SHA: shaNeg2}}, map[string]bool{shaFix: true}, "o/r", "o_r", 5, rng2)
	if neg[0].SHA != neg2[0].SHA {
		t.Fatal("sampling not deterministic under fixed seed")
	}
}

func TestScorePrefilterAndSummarise(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "commits"), 0o755); err != nil {
		t.Fatal(err)
	}
	log := shaFix + "\x1f2024\x1fA\x1fFix path traversal\x1fReported-by: X\x1e" +
		shaNeg1 + "\x1f2024\x1fB\x1fdocs: typo\x1f\x1e"
	if err := os.WriteFile(filepath.Join(dir, "commits", "o_r.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	writeHistoryFixture(t, filepath.Join(dir, "population.json"), `[{"ecosystem":"go","name":"fixture","repo":"o/r"}]`)
	labels := []label{
		{SHA: shaFix, Repo: "o/r", RepoKey: "o_r", Class: "advised"},
		{SHA: shaNeg1, Repo: "o/r", RepoKey: "o_r", Class: "negative"},
		{SHA: shaNeg2, Repo: "o/r", RepoKey: "o_r", Class: "advised"},
	}
	rows, err := scorePrefilter(dir, labels, "../../skills")
	if err != nil {
		t.Fatal(err)
	}
	var adv, advIn, advMatch int
	for _, r := range rows {
		if r.Class != "advised" {
			if r.Matched {
				t.Fatalf("negative matched: %+v", r)
			}
			continue
		}
		adv++
		if r.InLog {
			advIn++
		}
		if r.Matched {
			advMatch++
		}
	}
	if adv != 2 || advIn != 1 || advMatch != 1 {
		t.Fatalf("advised agg: total=%d in_log=%d matched=%d", adv, advIn, advMatch)
	}
	var buf bytes.Buffer
	pats, err := loadPatterns("../../skills")
	if err != nil {
		t.Fatal(err)
	}
	if err := summarise(&buf, rows, pats); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "advised") || !strings.Contains(buf.String(), "recall(in_log)=1.000") {
		t.Fatalf("summary missing recall line:\n%s", buf.String())
	}
}

func TestWriteReadJSONL(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	in := []label{{SHA: shaFix, RepoKey: "o_r", Class: "advised"}}
	if err := writeJSONL(root, "labels.jsonl", in); err != nil {
		t.Fatal(err)
	}
	out, err := readLabels(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].SHA != shaFix {
		t.Fatalf("round-trip: %+v", out)
	}
}

func TestLoadPatternsLive(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "skills", "history", "scripts", "history_candidates.py")); err != nil {
		t.Skip("skills tree not available")
	}
	pats, err := loadPatterns(filepath.Join("..", "..", "skills"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pats) < 4 {
		t.Fatalf("expected at least the 4 base patterns, got %d", len(pats))
	}
	var base int
	for _, p := range pats {
		if p.Ecosystem == "" {
			base++
		}
	}
	if base < 4 {
		t.Fatalf("expected 4+ base patterns, got %d", base)
	}
	msg := "Fix a potential\noverflow in parse"
	terms, err := matchMessages("../../skills", nil, []string{msg})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(terms[0], "security-shaped-fix") {
		t.Fatalf("security-shaped-fix did not match across newline; terms=%v", terms)
	}
}

func TestBuildLabelsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"osv", "commits"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pop, _ := json.Marshal([]population{{Ecosystem: "pypi", Name: "pkg", Repo: "owner/pkg", Host: "GitHub"}})
	if err := os.WriteFile(filepath.Join(dir, "population.json"), pop, 0o644); err != nil {
		t.Fatal(err)
	}
	osv := `{"id":"OSV-1","affected":[{"name":"pkg","ranges":[{"type":"GIT","events":[{"fixed":"` + shaFix + `"}]}]}]}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "osv", "PyPI.jsonl"), []byte(osv), 0o644); err != nil {
		t.Fatal(err)
	}
	log := shaFix + "\x1f2024\x1fA\x1fs\x1f\x1e" + shaNeg1 + "\x1f2024\x1fB\x1ft\x1f\x1e" + shaNeg2 + "\x1f2024\x1fC\x1fu\x1f\x1e"
	if err := os.WriteFile(filepath.Join(dir, "commits", "owner_pkg.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	ls, err := buildLabels(dir, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	var pos, neg int
	for _, l := range ls {
		switch l.Class {
		case "advised":
			pos++
		case "negative":
			neg++
		}
	}
	if pos != 1 || neg != 2 {
		t.Fatalf("want 1 advised + 2 negatives, got %d/%d", pos, neg)
	}
}
