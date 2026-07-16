package repoconfig

import (
	"slices"
	"strings"
	"testing"
)

func TestNormalise(t *testing.T) {
	raw := `focus_areas:
  - name: parser
    paths: [src/parse/**]
    surface: accepts arbitrary bytes
known_bugs:
  - GHSA-xxxx-yyyy
attack_surface: stdin is attacker controlled
skip: [tests/**]
`
	normalised, cfg, err := Normalise(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(normalised, "focus_areas:") || cfg.FocusAreas[0].Name != "parser" {
		t.Fatalf("normalised=%q config=%+v", normalised, cfg)
	}
	if cfg.Skip[0] != "tests/**" || cfg.AttackSurface == "" || cfg.KnownBugs[0] != "GHSA-xxxx-yyyy" {
		t.Fatalf("config=%+v", cfg)
	}
}

func TestFocusAreaJSONRoundTrip(t *testing.T) {
	raw, err := EncodeFocusAreaJSON(FocusArea{
		Name: "XML parser", Paths: []string{"  lib\\xml*.c  "}, Surface: "untrusted XML",
	})
	if err != nil {
		t.Fatal(err)
	}
	area, err := DecodeFocusAreaJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := area.Paths, []string{"lib/xml*.c"}; !slices.Equal(got, want) {
		t.Errorf("paths = %q, want %q", got, want)
	}
	if _, err := DecodeFocusAreaJSON(`{"name":"bad","paths":["../private/**"],"surface":"bad"}`); err == nil {
		t.Error("invalid focus area was accepted")
	}
}

func TestParseRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"unknown field", "unknown: value", "field unknown"},
		{"focus missing paths", "focus_areas:\n  - name: parser\n    surface: bytes", "paths is required"},
		{"absolute skip", "skip: [/tmp/**]", "relative"},
		{"windows volume", "skip: ['C:/tmp/**']", "relative"},
		{"parent skip", "skip: [../vendor/**]", "relative"},
		{"bad glob", "skip: ['[broken']", "valid glob"},
		{"blank known bug", "known_bugs: [' ']", "is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseNormalisesBackslashPatterns(t *testing.T) {
	cfg, err := Parse(`skip: ['tests\**']`)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Skip[0]; got != "tests/**" {
		t.Fatalf("skip = %q, want tests/**", got)
	}
}

func TestParseEmpty(t *testing.T) {
	cfg, err := Parse(" \n")
	if err != nil || !cfg.Empty() {
		t.Fatalf("Parse empty = %+v, %v", cfg, err)
	}
}
