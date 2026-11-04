package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHistoryEvalProcess(_ *testing.T) {
	if os.Getenv("SCRUTINEER_HISTORY_EVAL_PROCESS") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("history-eval", flag.ExitOnError)
	os.Args = append([]string{os.Args[0]}, strings.Split(os.Getenv("SCRUTINEER_HISTORY_EVAL_ARGS"), "\n")...)
	main()
	os.Exit(0)
}

func historyEvalCLI(t *testing.T, data, out, mode string) (string, error) {
	t.Helper()
	skills, err := filepath.Abs("../../skills")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHistoryEvalProcess$")
	cmd.Env = append(os.Environ(), "SCRUTINEER_HISTORY_EVAL_PROCESS=1",
		"SCRUTINEER_HISTORY_EVAL_ARGS="+strings.Join([]string{"-data", data, "-out", out, "-mode", mode, "-skills", skills, "-neg-per-repo", "0"}, "\n"))
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func historyCorpus(t *testing.T, ecosystems ...string) string {
	t.Helper()
	data := t.TempDir()
	for _, path := range []string{"commits", "osv"} {
		if err := os.Mkdir(filepath.Join(data, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var pop []population
	for _, ecosystem := range ecosystems {
		pop = append(pop, population{Ecosystem: ecosystem, Name: "fixture", Repo: "fixture/repo", Host: "GitHub"})
	}
	encoded, err := json.Marshal(pop)
	if err != nil {
		t.Fatal(err)
	}
	writeHistoryFixture(t, filepath.Join(data, "population.json"), string(encoded))
	writeHistoryFixture(t, filepath.Join(data, "osv/Go.jsonl"), fmt.Sprintf(`{"id":"fixture-advisory","affected":[{"name":"fixture","ranges":[{"type":"GIT","events":[{"fixed":%q}]}]}]}`, shaFix)+"\n")
	return data
}

func writeHistoryFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func historyLogRecord(sha, subject, body string) string {
	return strings.Join([]string{sha, "2026-01-01", "Fixture", subject, body}, "\x1f") + "\x1e"
}

func TestCLIPrefilterUsesProductionMatching(t *testing.T) {
	cases := []struct {
		name       string
		ecosystems []string
		subject    string
		matched    bool
	}{
		{name: "Go excludes web patterns", ecosystems: []string{"go"}, subject: "xss"},
		{name: "JavaScript includes web patterns", ecosystems: []string{"npm"}, subject: "xss", matched: true},
		{name: "repository ecosystem union", ecosystems: []string{"go", "npm"}, subject: "xss", matched: true},
		{name: "unknown ecosystem uses base", ecosystems: []string{"hex"}, subject: "xss"},
		{name: "Unicode word boundary", ecosystems: []string{"go"}, subject: "ésecurity"},
		{name: "base pattern", ecosystems: []string{"go"}, subject: "SECURITY", matched: true},
		{name: "multiline pattern", ecosystems: []string{"go"}, subject: "Fix a potential\noverflow", matched: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, out := historyCorpus(t, tc.ecosystems...), t.TempDir()
			writeHistoryFixture(t, filepath.Join(data, "commits/fixture_repo.log"), historyLogRecord(shaFix, tc.subject, ""))
			writeHistoryFixture(t, filepath.Join(out, "labels.jsonl"), fmt.Sprintf(`{"sha":%q,"repo":"fixture/repo","repo_key":"fixture_repo","class":"unadvised"}`, shaFix)+"\n")
			if output, err := historyEvalCLI(t, data, out, "prefilter"); err != nil {
				t.Fatalf("CLI: %v\n%s", err, output)
			}
			encoded, err := os.ReadFile(filepath.Join(out, "prefilter.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var row prefilterRow
			if err := json.Unmarshal(encoded, &row); err != nil {
				t.Fatal(err)
			}
			if !row.InLog || row.Matched != tc.matched {
				t.Fatalf("row = %+v; want matched=%v", row, tc.matched)
			}
		})
	}
}

func TestCLIRejectsOversizedLogRecord(t *testing.T) {
	for _, mode := range []string{"labels", "prefilter"} {
		t.Run(mode, func(t *testing.T) {
			data, out := historyCorpus(t, "go"), t.TempDir()
			writeHistoryFixture(t, filepath.Join(data, "commits/fixture_repo.log"),
				historyLogRecord(shaNeg1, "docs", "")+historyLogRecord(shaNeg2, "oversized", strings.Repeat("x", maxLogRecord))+historyLogRecord(shaFix, "security fix", ""))
			writeHistoryFixture(t, filepath.Join(out, "labels.jsonl"), fmt.Sprintf(`{"sha":%q,"repo_key":"fixture_repo","class":"advised"}`, shaFix)+"\n")
			target := "labels.jsonl"
			if mode == "prefilter" {
				target = "prefilter.jsonl"
				writeHistoryFixture(t, filepath.Join(out, target), "preserved output")
			}
			before, err := os.ReadFile(filepath.Join(out, target))
			if err != nil {
				t.Fatal(err)
			}
			output, err := historyEvalCLI(t, data, out, mode)
			if err == nil || !strings.Contains(output, "record exceeds") {
				t.Fatalf("CLI should report oversized record: %v\n%s", err, output)
			}
			after, err := os.ReadFile(filepath.Join(out, target))
			if err != nil || string(after) != string(before) {
				t.Fatalf("failed run changed previous output: %q, %v", after, err)
			}
		})
	}
}

func TestCLIOutputPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	data := historyCorpus(t, "go")
	writeHistoryFixture(t, filepath.Join(data, "commits/fixture_repo.log"), historyLogRecord(shaFix, "security", ""))
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			testCLIOutputPermissions(t, data, existing)
		})
	}
}

func testCLIOutputPermissions(t *testing.T, data string, existing bool) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	if existing {
		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"labels.jsonl", "prefilter.jsonl"} {
			writeHistoryFixture(t, filepath.Join(out, name), "old output")
			if err := os.Chmod(filepath.Join(out, name), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, mode := range []string{"labels", "prefilter"} {
		if output, err := historyEvalCLI(t, data, out, mode); err != nil {
			t.Fatalf("CLI: %v\n%s", err, output)
		}
	}
	for _, name := range []string{".", "labels.jsonl", "prefilter.jsonl"} {
		info, err := os.Stat(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if name == "." {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%04o, want %04o", name, info.Mode().Perm(), want)
		}
	}
}

func TestCLIRejectsOversizedLogFile(t *testing.T) {
	data, out := historyCorpus(t, "go"), t.TempDir()
	f, err := os.Create(filepath.Join(data, "commits/fixture_repo.log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxLogBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := historyEvalCLI(t, data, out, "labels")
	if err == nil || !strings.Contains(output, "commit log exceeds") {
		t.Fatalf("CLI should report oversized log file: %v\n%s", err, output)
	}
}
