package db

import "testing"

func TestNormaliseLocation(t *testing.T) {
	cases := map[string]string{
		"src/users.rb:42":     "src/users.rb",
		"src/users.rb:42:7":   "src/users.rb",
		"src/users.rb":        "src/users.rb",
		"./src/users.rb:1":    "src/users.rb",
		"  Src/Users.rb:10  ": "src/users.rb",
		"":                    "",
	}
	for in, want := range cases {
		if got := normaliseLocation(in); got != want {
			t.Errorf("normaliseLocation(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprintFinding(t *testing.T) {
	base := FingerprintFinding("security-deep-dive", "", "CWE-89", "src/users.rb:42", "SQLi")

	if base != FingerprintFinding("security-deep-dive", "", "CWE-89", "src/users.rb:77", "SQLi rephrased") {
		t.Errorf("line drift / title change must not change fingerprint")
	}
	if base != FingerprintFinding("Security-Deep-Dive", "", "cwe-89", "./SRC/users.rb", "x") {
		t.Errorf("skill/cwe/location case must not change fingerprint")
	}
	if base == FingerprintFinding("security-deep-dive", "", "CWE-89", "src/admin.rb:42", "SQLi") {
		t.Errorf("different file must change fingerprint")
	}
	if base == FingerprintFinding("security-deep-dive", "", "CWE-79", "src/users.rb:42", "SQLi") {
		t.Errorf("different CWE must change fingerprint")
	}
	if base == FingerprintFinding("semgrep", "", "CWE-89", "src/users.rb:42", "SQLi") {
		t.Errorf("different skill must change fingerprint")
	}
	if base == FingerprintFinding("security-deep-dive", "core", "CWE-89", "src/users.rb:42", "SQLi") {
		t.Errorf("different sub-path must change fingerprint")
	}

	// With neither CWE nor location, title is the discriminator.
	a := FingerprintFinding("freeform", "", "", "", "Hardcoded secret")
	b := FingerprintFinding("freeform", "", "", "", "Hardcoded Secret")
	c := FingerprintFinding("freeform", "", "", "", "Weak crypto")
	if a != b {
		t.Errorf("title fallback should be case-insensitive")
	}
	if a == c {
		t.Errorf("different title must change fingerprint when it is the only key")
	}
}

func TestBackfillFindingFingerprints(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	r := Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&r)
	s := Scan{RepositoryID: r.ID, Kind: "skill", SkillName: "security-deep-dive", Status: ScanDone, Commit: "abc"}
	gdb.Create(&s)
	f := Finding{ScanID: s.ID, RepositoryID: r.ID, Commit: "abc", CWE: "CWE-89", Location: "src/users.rb:42", Title: "SQLi"}
	gdb.Create(&f)

	BackfillFindingFingerprints(gdb)

	var got Finding
	gdb.First(&got, f.ID)
	want := FingerprintFinding("security-deep-dive", "", "CWE-89", "src/users.rb:42", "SQLi")
	if got.Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", got.Fingerprint, want)
	}
	if got.LastSeenScanID != s.ID || got.LastSeenCommit != "abc" || got.SeenCount != 1 {
		t.Errorf("last-seen backfill: scan=%d commit=%q seen=%d", got.LastSeenScanID, got.LastSeenCommit, got.SeenCount)
	}

	// Idempotent: a second run does not bump SeenCount.
	BackfillFindingFingerprints(gdb)
	gdb.First(&got, f.ID)
	if got.SeenCount != 1 {
		t.Errorf("backfill not idempotent: seen=%d", got.SeenCount)
	}
}
