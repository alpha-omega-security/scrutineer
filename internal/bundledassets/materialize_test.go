package bundledassets

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"
)

func TestMaterialize(t *testing.T) {
	bundle := fstest.MapFS{
		"embed.go":             {Data: []byte("package ignored")},
		"alpha/SKILL.md":       {Data: []byte("alpha skill")},
		"alpha/schema.json":    {Data: []byte(`{"type":"object"}`)},
		"alpha/scripts/run.sh": {Data: []byte("#!/bin/sh\n")},
	}
	dataDir := t.TempDir()

	dir, hash, err := Materialize(bundle, dataDir, "bundled-test")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" || filepath.Base(dir) != hash {
		t.Fatalf("dir=%q hash=%q, want content-addressed directory", dir, hash)
	}
	if _, err := os.Stat(filepath.Join(dir, "embed.go")); !os.IsNotExist(err) {
		t.Fatalf("root Go source was materialized: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "alpha", "SKILL.md")); err != nil || string(got) != "alpha skill" {
		t.Fatalf("read materialized skill: got %q, err=%v", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "alpha", "scripts", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != bundleScriptPerm {
		t.Fatalf("script mode = %o, want %o", info.Mode().Perm(), bundleScriptPerm)
	}

	dir2, hash2, err := Materialize(bundle, dataDir, "bundled-test")
	if err != nil {
		t.Fatal(err)
	}
	if dir2 != dir || hash2 != hash {
		t.Fatalf("second materialization = (%q, %q), want (%q, %q)", dir2, hash2, dir, hash)
	}
}

func TestMaterializeAuxiliaryChangeChangesHash(t *testing.T) {
	first := fstest.MapFS{
		"alpha/SKILL.md":        {Data: []byte("same")},
		"alpha/references/a.md": {Data: []byte("one")},
	}
	second := fstest.MapFS{
		"alpha/SKILL.md":        {Data: []byte("same")},
		"alpha/references/a.md": {Data: []byte("two")},
	}
	dataDir := t.TempDir()

	dir1, hash1, err := Materialize(first, dataDir, "bundled-test")
	if err != nil {
		t.Fatal(err)
	}
	dir2, hash2, err := Materialize(second, dataDir, "bundled-test")
	if err != nil {
		t.Fatal(err)
	}
	if hash1 == hash2 || dir1 == dir2 {
		t.Fatalf("auxiliary change did not change bundle identity: (%q, %q) vs (%q, %q)", dir1, hash1, dir2, hash2)
	}
}

func TestEmbeddedAssetsHashUsesUnambiguousFraming(t *testing.T) {
	oneFile := fstest.MapFS{
		"a/x": {Data: []byte("one\x00a/y\x00two")},
	}
	twoFiles := fstest.MapFS{
		"a/x": {Data: []byte("one")},
		"a/y": {Data: []byte("two")},
	}
	_, oneHash, err := embeddedAssets(oneFile)
	if err != nil {
		t.Fatal(err)
	}
	_, twoHash, err := embeddedAssets(twoFiles)
	if err != nil {
		t.Fatal(err)
	}
	if oneHash == twoHash {
		t.Fatalf("different file trees produced the same framed hash %s", oneHash)
	}
}

func TestMaterializeRejectsEmptyFilesystem(t *testing.T) {
	_, _, err := Materialize(fstest.MapFS{"embed.go": {Data: []byte("ignored")}}, t.TempDir(), "bundled-test")
	if err == nil {
		t.Fatal("empty embedded filesystem succeeded")
	}
}

func TestEmbeddedAssetsRejectNonRegularFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"alpha/SKILL.md": {Data: []byte("skill"), Mode: fs.ModeSymlink},
	}
	if _, _, err := embeddedAssets(fsys); err == nil {
		t.Fatal("non-regular embedded asset succeeded")
	}
}

func TestMaterializeCleansOnlyStaleExtractionDirectories(t *testing.T) {
	bundle := fstest.MapFS{
		"alpha/SKILL.md": {Data: []byte("alpha skill")},
	}
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "bundled-test")
	stale := filepath.Join(root, ".extract-stale")
	recent := filepath.Join(root, ".extract-recent")
	oldBundle := filepath.Join(root, "old-content-hash")
	for _, dir := range []string{stale, recent, oldBundle} {
		if err := os.MkdirAll(dir, bundleDirPerm); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Now().Add(-staleExtractAge - time.Hour)
	if err := os.Chtimes(stale, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	if _, _, err := Materialize(bundle, dataDir, "bundled-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale extraction directory was not removed: %v", err)
	}
	for _, dir := range []string{recent, oldBundle} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("retained directory %s: %v", dir, err)
		}
	}
}
