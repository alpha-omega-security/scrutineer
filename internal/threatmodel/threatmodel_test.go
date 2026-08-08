package threatmodel

import (
	"strings"
	"testing"
)

const modelWithControls = `{
  "spec_version": 1,
  "repository": "https://example.test/repo",
  "controls": [
    {
      "id": "admin-auth",
      "kind": "authorization",
      "protects": {
        "paths": ["internal/admin/**"],
        "entry_points": ["admin-api"]
      },
      "assumptions": ["requests reach this package only through the authenticated router"],
      "provenance": "documented",
      "source": "docs/SECURITY.md:12"
    },
    {
      "id": "parser-sandbox",
      "kind": "sandbox",
      "protects": { "paths": ["internal/parse/*.go"] },
      "provenance": "inferred"
    }
  ]
}`

func mustParse(t *testing.T, raw string) *Model {
	t.Helper()
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

// A threat model that predates controls, or one from a repository with no
// override at all, has to parse clean. The package is additive to documents
// nothing else in Go has ever read.
func TestParseModelWithoutControls(t *testing.T) {
	for name, raw := range map[string]string{
		"empty string":     "",
		"whitespace":       "   \n\t ",
		"no controls key":  `{"spec_version": 1, "entry_points": []}`,
		"controls omitted": `{"spec_version": 1, "trust_boundaries": [{"component": "c"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			m := mustParse(t, raw)
			if len(m.Controls) != 0 {
				t.Fatalf("got %d controls, want 0", len(m.Controls))
			}
			if err := m.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if got := m.MatchPath("internal/admin/users.go"); got != nil {
				t.Fatalf("MatchPath on empty model = %v, want nil", got)
			}
		})
	}
}

// Unknown top-level sections must not break parsing: the document is owned by
// the skill's schema, and this package reads one field out of it.
func TestParseIgnoresUnknownFields(t *testing.T) {
	m := mustParse(t, modelWithControls)
	if len(m.Controls) != 2 {
		t.Fatalf("got %d controls, want 2", len(m.Controls))
	}
	admin := m.Controls[0]
	if admin.ID != "admin-auth" || admin.Kind != KindAuthorization {
		t.Fatalf("first control = %+v", admin)
	}
	if admin.Source != "docs/SECURITY.md:12" || admin.Provenance != ProvenanceDocumented {
		t.Fatalf("provenance/source not parsed: %+v", admin)
	}
	if len(admin.Assumptions) != 1 {
		t.Fatalf("assumptions = %v", admin.Assumptions)
	}
	if got := m.Controls[1].Protects.EntryPoints; len(got) != 0 {
		t.Fatalf("second control entry_points = %v, want none", got)
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse(`{"controls": [`); err == nil {
		t.Fatal("want error for truncated document")
	}
}

func TestMatchPath(t *testing.T) {
	m := mustParse(t, modelWithControls)
	for name, tc := range map[string]struct {
		path string
		want []string
	}{
		"file under doublestar":     {"internal/admin/users.go", []string{"admin-auth"}},
		"nested under doublestar":   {"internal/admin/roles/grant.go", []string{"admin-auth"}},
		"directory itself":          {"internal/admin", []string{"admin-auth"}},
		"leading ./ is tolerated":   {"./internal/admin/users.go", []string{"admin-auth"}},
		"single star stays shallow": {"internal/parse/json.go", []string{"parser-sandbox"}},
		"single star not nested":    {"internal/parse/deep/json.go", nil},
		"unprotected path":          {"internal/web/server.go", nil},
		"empty path":                {"", nil},
	} {
		t.Run(name, func(t *testing.T) {
			got := IDs(m.MatchPath(tc.path))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("MatchPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// A path matched by two of a control's own globs yields that control once:
// the matched set is a set of controls, not of pattern hits.
func TestMatchPathDoesNotDuplicateOneControl(t *testing.T) {
	m := mustParse(t, `{"controls": [{
	  "id": "c1", "kind": "other", "provenance": "inferred",
	  "protects": {"paths": ["internal/**", "internal/admin/*.go"]}
	}]}`)
	got := m.MatchPath("internal/admin/users.go")
	if len(got) != 1 || got[0].ID != "c1" {
		t.Fatalf("MatchPath = %v, want exactly one c1", IDs(got))
	}
}

func TestMatchEntryPoint(t *testing.T) {
	m := mustParse(t, modelWithControls)
	if got := IDs(m.MatchEntryPoint("admin-api")); len(got) != 1 || got[0] != "admin-auth" {
		t.Fatalf("MatchEntryPoint(admin-api) = %v", got)
	}
	// Exact comparison: a near miss is an authoring error, not a match.
	for _, name := range []string{"admin-API", "admin", "admin-api ", ""} {
		if got := m.MatchEntryPoint(name); got != nil {
			t.Fatalf("MatchEntryPoint(%q) = %v, want nil", name, IDs(got))
		}
	}
}

// A control scoped only by entry point must not match a path, and vice versa.
// The two scopes are independent inputs to different consumers.
func TestScopesDoNotLeakIntoEachOther(t *testing.T) {
	m := mustParse(t, `{"controls": [
	  {"id": "ep-only", "kind": "csrf", "provenance": "inferred", "protects": {"entry_points": ["mutating-routes"]}},
	  {"id": "path-only", "kind": "sandbox", "provenance": "inferred", "protects": {"paths": ["internal/wasm/**"]}}
	]}`)
	if got := m.MatchPath("internal/wasm/run.go"); len(got) != 1 || got[0].ID != "path-only" {
		t.Fatalf("MatchPath = %v", IDs(got))
	}
	if got := m.MatchEntryPoint("mutating-routes"); len(got) != 1 || got[0].ID != "ep-only" {
		t.Fatalf("MatchEntryPoint = %v", IDs(got))
	}
}

func TestValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		raw     string
		wantErr string
	}{
		"valid": {modelWithControls, ""},
		"missing id": {
			`{"controls": [{"kind": "other", "provenance": "inferred", "protects": {"paths": ["a/**"]}}]}`,
			"id is required",
		},
		"duplicate id": {
			`{"controls": [
			  {"id": "c", "kind": "other", "provenance": "inferred", "protects": {"paths": ["a/**"]}},
			  {"id": "c", "kind": "other", "provenance": "inferred", "protects": {"paths": ["b/**"]}}
			]}`,
			"duplicate id",
		},
		"missing kind": {
			`{"controls": [{"id": "c", "provenance": "inferred", "protects": {"paths": ["a/**"]}}]}`,
			"kind is required",
		},
		"bad provenance": {
			`{"controls": [{"id": "c", "kind": "other", "provenance": "guessed", "protects": {"paths": ["a/**"]}}]}`,
			"provenance must be",
		},
		"no scope": {
			`{"controls": [{"id": "c", "kind": "other", "provenance": "inferred", "protects": {}}]}`,
			"at least one of paths or entry_points",
		},
		"empty path": {
			`{"controls": [{"id": "c", "kind": "other", "provenance": "inferred", "protects": {"paths": [""]}}]}`,
			"is empty",
		},
		"malformed glob": {
			`{"controls": [{"id": "c", "kind": "other", "provenance": "inferred", "protects": {"paths": ["internal/[admin/**"]}}]}`,
			"is not a valid glob",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := mustParse(t, tc.raw).Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate = nil, want error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("Validate = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// An unrecognised kind is explicitly allowed: the schema calls kind an open
// enum, and a control this build cannot interpret still scopes and matches.
func TestValidateAllowsUnknownKind(t *testing.T) {
	m := mustParse(t, `{"controls": [{"id": "c", "kind": "attestation", "provenance": "documented",
	  "source": "docs/SECURITY.md:1", "protects": {"paths": ["internal/**"]}}]}`)
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := IDs(m.MatchPath("internal/x.go")); len(got) != 1 {
		t.Fatalf("MatchPath = %v", got)
	}
}

func TestIDsAreSortedAndDeduped(t *testing.T) {
	got := IDs([]Control{{ID: "b"}, {ID: "a"}, {ID: "b"}})
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("IDs = %v", got)
	}
	if IDs(nil) != nil {
		t.Fatal("IDs(nil) should be nil")
	}
}

// Validate tolerates a nil receiver so callers can validate whatever Parse
// handed back without a nil check at every call site.
func TestNilModel(t *testing.T) {
	var m *Model
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate on nil: %v", err)
	}
	if m.MatchPath("a.go") != nil || m.MatchEntryPoint("e") != nil {
		t.Fatal("matching on nil model should return nil")
	}
}
