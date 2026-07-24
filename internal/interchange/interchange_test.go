package interchange

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestFindingHashDeterministic(t *testing.T) {
	h1 := FindingHash("salt", "https://github.com/acme/lib", "", "src/parse.go:42", "CWE-79")
	h2 := FindingHash("salt", "https://github.com/acme/lib", "", "src/parse.go:42", "CWE-79")
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s vs %s", h1, h2)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h1) {
		t.Fatalf("hash is not 64 lowercase hex chars: %q", h1)
	}
}

func TestFindingHashNormalisation(t *testing.T) {
	base := FindingHash("s", "https://github.com/acme/lib", "", "src/parse.go", "CWE-79")
	cases := []struct {
		name     string
		repo     string
		subPath  string
		location string
		cwe      string
	}{
		{"repo case", "https://github.com/ACME/Lib", "", "src/parse.go", "CWE-79"},
		{"repo trailing slash", "https://github.com/acme/lib/", "", "src/parse.go", "CWE-79"},
		{"repo double trailing slash", "https://github.com/acme/lib//", "", "src/parse.go", "CWE-79"},
		{"repo .git suffix", "https://github.com/acme/lib.git", "", "src/parse.go", "CWE-79"},
		{"line suffix", "https://github.com/acme/lib", "", "src/parse.go:42", "CWE-79"},
		{"line:col suffix", "https://github.com/acme/lib", "", "src/parse.go:42:7", "CWE-79"},
		{"range suffix", "https://github.com/acme/lib", "", "src/parse.go:10-20", "CWE-79"},
		{"dot-slash prefix", "https://github.com/acme/lib", "", "./src/parse.go", "CWE-79"},
		{"backslashes", "https://github.com/acme/lib", "", `src\parse.go`, "CWE-79"},
		{"location case", "https://github.com/acme/lib", "", "SRC/Parse.go", "CWE-79"},
		{"multiline location", "https://github.com/acme/lib", "", "src/parse.go:42\nsecond line", "CWE-79"},
		{"sub_path prefix", "https://github.com/acme/lib", "src", "parse.go:42", "CWE-79"},
		{"sub_path slashes", "https://github.com/acme/lib", "/src/", "parse.go", "CWE-79"},
		{"cwe case and space", "https://github.com/acme/lib", "", "src/parse.go", " cwe-79 "},
	}
	for _, c := range cases {
		if got := FindingHash("s", c.repo, c.subPath, c.location, c.cwe); got != base {
			t.Errorf("%s: expected canonical hash %s, got %s", c.name, base, got)
		}
	}
}

func TestFindingHashCWEList(t *testing.T) {
	base := FindingHash("s", "https://github.com/acme/lib", "", "src/parse.go", "CWE-79,CWE-89")
	for name, cwe := range map[string]string{
		"spacing":        " CWE-79 , CWE-89 ",
		"order":          "CWE-89,CWE-79",
		"case":           "cwe-89,cwe-79",
		"empty elements": "CWE-79,,CWE-89,",
	} {
		if got := FindingHash("s", "https://github.com/acme/lib", "", "src/parse.go", cwe); got != base {
			t.Errorf("%s: CWE list %q must hash like the canonical list", name, cwe)
		}
	}
	if FindingHash("s", "https://github.com/acme/lib", "", "src/parse.go", "CWE-79") == base {
		t.Error("a shorter CWE list must not collide with the full list")
	}
}

func TestFindingHashDistinct(t *testing.T) {
	base := FindingHash("s", "https://github.com/acme/lib", "", "src/parse.go", "CWE-79")
	cases := []struct {
		name string
		hash string
	}{
		{"salt", FindingHash("other", "https://github.com/acme/lib", "", "src/parse.go", "CWE-79")},
		{"repo", FindingHash("s", "https://github.com/acme/other", "", "src/parse.go", "CWE-79")},
		{"location", FindingHash("s", "https://github.com/acme/lib", "", "src/other.go", "CWE-79")},
		{"cwe", FindingHash("s", "https://github.com/acme/lib", "", "src/parse.go", "CWE-89")},
		{"empty cwe", FindingHash("s", "https://github.com/acme/lib", "", "src/parse.go", "")},
	}
	for _, c := range cases {
		if c.hash == base {
			t.Errorf("%s: expected a different hash than %s", c.name, base)
		}
	}
}

func validStatements() map[string]Statement {
	audited := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return map[string]Statement{
		"certificate": NewCertificate(CertificatePredicate{
			Repository:  "https://github.com/acme/lib",
			Advisory:    "GHSA-xxxx-yyyy-zzzz",
			AdvisoryURL: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
			Status:      "fixed",
			Commit:      "abc123",
			AuditedAt:   audited,
		}),
		"claim": NewClaim(strings.Repeat("ab", 32), ClaimPredicate{
			Contact: "security@example.com",
		}),
		"optout": NewOptOut(OptOutPredicate{
			Repository:  "https://github.com/acme/lib",
			RequestedAt: audited,
			Reason:      "maintainer asked to be left alone",
		}),
		"route": NewRoute(RoutePredicate{
			Repository: "https://github.com/acme/lib",
			Channel:    "https://github.com/acme/lib/security/policy",
			VerifiedAt: audited,
		}),
	}
}

func TestStatementsValidate(t *testing.T) {
	for name, st := range validStatements() {
		raw, err := json.Marshal(st)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if err := Validate(raw); err != nil {
			t.Errorf("%s: expected valid statement, got %v\n%s", name, err, raw)
		}
	}
}

func TestStatementShape(t *testing.T) {
	hash := strings.Repeat("cd", 32)
	claim := NewClaim(hash, ClaimPredicate{Contact: "security@example.com"})
	if len(claim.Subject) != 1 || claim.Subject[0].Digest["sha256"] != hash {
		t.Fatalf("claim subject must carry the finding hash as sha256 digest: %+v", claim.Subject)
	}
	cert := NewCertificate(CertificatePredicate{
		Repository: "https://github.com/ACME/Lib.git",
		Advisory:   "GHSA-xxxx-yyyy-zzzz",
		Status:     "fixed",
		AuditedAt:  time.Now().UTC(),
	})
	pred, ok := cert.Predicate.(CertificatePredicate)
	if !ok {
		t.Fatalf("certificate predicate has unexpected type %T", cert.Predicate)
	}
	if pred.Repository != "https://github.com/acme/lib" {
		t.Fatalf("constructor must canonicalise the repository URL, got %q", pred.Repository)
	}
	variant := NewCertificate(CertificatePredicate{
		Repository: "https://github.com/acme/lib",
		Advisory:   " ghsa-xxxx-yyyy-zzzz ",
		Status:     "fixed",
		AuditedAt:  time.Now().UTC(),
	})
	if cert.Subject[0].Digest["sha256"] != variant.Subject[0].Digest["sha256"] {
		t.Fatal("advisory id case and padding must not change the certificate subject digest")
	}
}

func TestValidateAcceptsForeignSubjectFields(t *testing.T) {
	raw := []byte(`{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [{
			"name": "finding",
			"uri": "https://example.com/finding",
			"mediaType": "application/json",
			"digest": {"sha256": "` + strings.Repeat("ab", 32) + `", "sha512": "beef"}
		}],
		"predicateType": "https://github.com/alpha-omega-security/scrutineer/interchange/claim/v1",
		"predicate": {"contact": "security@example.com"}
	}`)
	if err := Validate(raw); err != nil {
		t.Fatalf("spec-legal in-toto subject extensions must validate, got %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	valid := validStatements()
	mutate := func(t *testing.T, st Statement, fn func(m map[string]any)) []byte {
		t.Helper()
		raw, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		fn(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"not json", []byte("{")},
		{"wrong _type", mutate(t, valid["claim"], func(m map[string]any) { m["_type"] = "https://in-toto.io/Statement/v0.1" })},
		{"missing subject", mutate(t, valid["claim"], func(m map[string]any) { delete(m, "subject") })},
		{"empty subject", mutate(t, valid["claim"], func(m map[string]any) { m["subject"] = []any{} })},
		{"unknown predicateType", mutate(t, valid["claim"], func(m map[string]any) { m["predicateType"] = "https://example.com/other/v1" })},
		{"digest not hex", mutate(t, valid["claim"], func(m map[string]any) {
			m["subject"] = []any{map[string]any{"name": "finding", "digest": map[string]any{"sha256": "nope"}}}
		})},
		{"claim without contact", mutate(t, valid["claim"], func(m map[string]any) { m["predicate"] = map[string]any{} })},
		{"certificate leaking severity", mutate(t, valid["certificate"], func(m map[string]any) {
			m["predicate"].(map[string]any)["severity"] = "critical"
		})},
		{"certificate leaking cvss", mutate(t, valid["certificate"], func(m map[string]any) {
			m["predicate"].(map[string]any)["cvss_score"] = 9.8
		})},
		{"certificate not fixed", mutate(t, valid["certificate"], func(m map[string]any) {
			m["predicate"].(map[string]any)["status"] = "vulnerable"
		})},
		{"certificate bad timestamp", mutate(t, valid["certificate"], func(m map[string]any) {
			m["predicate"].(map[string]any)["audited_at"] = "yesterday"
		})},
		{"optout bad timestamp", mutate(t, valid["optout"], func(m map[string]any) {
			m["predicate"].(map[string]any)["requested_at"] = "2026-13-45"
		})},
		{"optout without repository", mutate(t, valid["optout"], func(m map[string]any) {
			delete(m["predicate"].(map[string]any), "repository")
		})},
		{"route without channel", mutate(t, valid["route"], func(m map[string]any) {
			delete(m["predicate"].(map[string]any), "channel")
		})},
	}
	for _, c := range cases {
		if err := Validate(c.raw); err == nil {
			t.Errorf("%s: expected validation error, got nil\n%s", c.name, c.raw)
		}
	}
}
