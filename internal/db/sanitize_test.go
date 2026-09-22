package db

import (
	"strings"
	"testing"
)

func TestSanitizePGText(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"clean", "hello world", "hello world"},
		{"empty", "", ""},
		{"nul stripped", "a\x00b\x00c", "abc"},
		{"invalid utf8 replaced", "a\xffb", "a�b"},
		{"both", "x\x00\xffy", "x�y"},
	}
	for _, tc := range cases {
		if got := SanitizePGText(tc.in); got != tc.want {
			t.Errorf("%s: SanitizePGText(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestTextSanitizerCallback exercises the Create/Update callback end to end.
// Open() uses SQLite (which tolerates NUL), so the callback is not auto-wired;
// we register it manually to prove it scrubs both a struct Save and a column
// Update — the two write forms that carry raw scan output on the live path.
func TestTextSanitizerCallback(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := registerTextSanitizer(gdb); err != nil {
		t.Fatal(err)
	}

	repo := Repository{URL: "https://example.com/x", Name: "x"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	// Struct Save (the finalizeScan path): NUL + invalid UTF-8 in log/report/error.
	scan := Scan{
		RepositoryID: repo.ID,
		Kind:         "skill",
		Status:       ScanDone,
		Log:          "start\x00middle\xffend",
		Report:       `{"ok":true}` + "\x00",
		Error:        "boom\x00",
	}
	if err := gdb.Save(&scan).Error; err != nil {
		t.Fatalf("struct save with NUL text failed: %v", err)
	}
	var got Scan
	if err := gdb.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"log": got.Log, "report": got.Report, "error": got.Error} {
		if strings.ContainsRune(v, 0) {
			t.Errorf("%s still contains a NUL byte after save: %q", name, v)
		}
	}
	if got.Log != "startmiddle�end" {
		t.Errorf("log = %q, want NUL stripped and invalid UTF-8 replaced", got.Log)
	}

	// Column Update (the streaming log-flush path): Update("log", value) sets a
	// map destination, which the callback must also scrub.
	if err := gdb.Model(&Scan{}).Where("id = ?", scan.ID).
		Update("log", "flush\x00tail").Error; err != nil {
		t.Fatalf("column update with NUL text failed: %v", err)
	}
	got = Scan{}
	if err := gdb.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(got.Log, 0) || got.Log != "flushtail" {
		t.Errorf("after column update log = %q, want %q", got.Log, "flushtail")
	}
}
