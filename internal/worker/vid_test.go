package worker

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"scrutineer/internal/db"
)

func writeSrcFile(t *testing.T, srcDir, rel string) {
	t.Helper()
	p := filepath.Join(srcDir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("code\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// stubVid writes an executable that prints out and exits with code,
// recording its argv (one per line) to args.txt next to it.
func stubVid(t *testing.T, out string, code int) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "vid")
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\necho %q\nexit %d\n",
		filepath.Join(dir, "args.txt"), out, code)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

func TestVidSinks(t *testing.T) {
	srcDir := t.TempDir()
	writeSrcFile(t, srcDir, "a.rb")
	writeSrcFile(t, srcDir, "lib/b.js")

	// A repo can carry hostile symlinks; lexically-local paths whose
	// target resolves outside the checkout must be dropped, while
	// symlinks staying inside it are fine.
	outside := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(outside, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(srcDir, "evil.rb")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.rb", filepath.Join(srcDir, "alias.rb")); err != nil {
		t.Fatal(err)
	}

	locations := "a.rb:12\n" + // plain
		"./a.rb:12\n" + // ./ prefix dedupes with the plain form
		"lib/b.js:42:7\n" + // column stripped
		"a.rb:30-40\n" + // range collapses to first line
		"missing.rb:1\n" + // not on disk
		"../escape.rb:1\n" + // escapes the checkout
		"evil.rb:1\n" + // symlink escaping the checkout
		"alias.rb:7\n" + // symlink staying inside the checkout
		"lib:1\n" + // a directory
		"no-line.rb\n" + // no line spec
		"\n"
	got := vidSinks(srcDir, locations)
	want := []string{"a.rb:12", "lib/b.js:42", "a.rb:30", "alias.rb:7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("vidSinks = %v, want %v", got, want)
	}
}

func TestComputeVID(t *testing.T) {
	srcDir := t.TempDir()
	writeSrcFile(t, srcDir, "a.rb")
	w := &Worker{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	w.VIDCommand = stubVid(t, "VID-aaaa-bbbb-cccc-dddd-eeee-ffff", 0)
	if got := w.computeVID(srcDir, "a.rb:12"); got != "VID-aaaa-bbbb-cccc-dddd-eeee-ffff" {
		t.Errorf("computeVID = %q", got)
	}
	args, err := os.ReadFile(filepath.Join(filepath.Dir(w.VIDCommand), "args.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(args) != "a.rb:12\n" {
		t.Errorf("vid argv = %q, want %q", args, "a.rb:12\n")
	}

	w.VIDCommand = stubVid(t, "VID-aaaa-bbbb-cccc-dddd-eeee-ffff", 1)
	if got := w.computeVID(srcDir, "a.rb:12"); got != "" {
		t.Errorf("failed run should yield empty VID, got %q", got)
	}

	w.VIDCommand = stubVid(t, "not a vid", 0)
	if got := w.computeVID(srcDir, "a.rb:12"); got != "" {
		t.Errorf("malformed output should yield empty VID, got %q", got)
	}

	w.VIDCommand = filepath.Join(t.TempDir(), "absent")
	if got := w.computeVID(srcDir, "a.rb:12"); got != "" {
		t.Errorf("missing binary should yield empty VID, got %q", got)
	}

	w.VIDCommand = stubVid(t, "VID-aaaa-bbbb-cccc-dddd-eeee-ffff", 0)
	if got := w.computeVID(srcDir, "missing.rb:1"); got != "" {
		t.Errorf("no resolvable sinks should yield empty VID, got %q", got)
	}
}

func TestParseFindingsOutput_setsAndRefreshesVID(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
	}

	report := `{"findings":[{"id":"F1","title":"a","severity":"High","cwe":"CWE-1","location":"a.rb:1"}]}`

	s1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone, Commit: "c1"}
	gdb.Create(s1)
	writeSrcFile(t, filepath.Join(w.scanWorkRoot(s1), "src"), "a.rb")
	w.VIDCommand = stubVid(t, "VID-1111-1111-1111-1111-1111-1111", 0)
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var f db.Finding
	if err := gdb.First(&f).Error; err != nil {
		t.Fatal(err)
	}
	if f.VID != "VID-1111-1111-1111-1111-1111-1111" {
		t.Errorf("VID = %q, want VID-1111...", f.VID)
	}

	// Re-observation refreshes the VID from the new checkout.
	s2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone, Commit: "c2"}
	gdb.Create(s2)
	writeSrcFile(t, filepath.Join(w.scanWorkRoot(s2), "src"), "a.rb")
	w.VIDCommand = stubVid(t, "VID-2222-2222-2222-2222-2222-2222", 0)
	if err := w.parseFindingsOutput(&db.Skill{}, s2, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 1 {
		t.Fatalf("expected dedup to 1 finding, got %d", n)
	}
	if err := gdb.First(&f).Error; err != nil {
		t.Fatal(err)
	}
	if f.VID != "VID-2222-2222-2222-2222-2222-2222" {
		t.Errorf("re-seen VID = %q, want VID-2222...", f.VID)
	}

	// A scan that cannot compute (no src staged) keeps the stored VID.
	s3 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone, Commit: "c3"}
	gdb.Create(s3)
	if err := w.parseFindingsOutput(&db.Skill{}, s3, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if err := gdb.First(&f).Error; err != nil {
		t.Fatal(err)
	}
	if f.VID != "VID-2222-2222-2222-2222-2222-2222" {
		t.Errorf("VID after uncomputable scan = %q, want unchanged VID-2222...", f.VID)
	}
}
