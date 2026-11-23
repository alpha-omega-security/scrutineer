package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/verification"
)

func TestVerificationFeedbackContextAndRecipe(t *testing.T) {
	for _, name := range []string{"verify", "critic"} {
		t.Run(name, func(t *testing.T) {
			scan := db.Scan{SkillName: name, FindingID: new(uint(1)), VerificationFeedback: "Check the first-party parser"}
			dir := t.TempDir()
			document, err := buildSkillContext("", "", "", &scan, &db.Repository{}, nil, nil, nil, scanLimits(t.Context()))
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSkillContext(dir, "", document); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "context.json"))
			if err != nil {
				t.Fatal(err)
			}
			var ctx skillContext
			if err := json.Unmarshal(raw, &ctx); err != nil {
				t.Fatal(err)
			}
			if (ctx.Scrutineer.VerificationFeedback == scan.VerificationFeedback) != (name == "verify") {
				t.Fatalf("wrong feedback staging: %s", raw)
			}
			if name == "verify" {
				raw, err := buildScanRecipe(&scan, "claude", "", "")
				if err != nil {
					t.Fatal(err)
				}
				var recipe ScanRecipe
				if err := json.Unmarshal([]byte(raw), &recipe); err != nil || recipe.VerificationFeedback != scan.VerificationFeedback {
					t.Fatalf("recipe dropped feedback: %s err=%v", raw, err)
				}
			}
		})
	}
}

func TestBuildSkillContextRejectsInvalidVerificationFeedback(t *testing.T) {
	for name, feedback := range map[string]string{
		"too long":     strings.Repeat("x", verification.MaxFeedbackBytes+1),
		"invalid UTF8": string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			scan := db.Scan{SkillName: verifySkillName, FindingID: new(uint(1)), VerificationFeedback: feedback}
			if _, err := buildSkillContext("", "", "", &scan, &db.Repository{}, nil, nil, nil, scanLimits(t.Context())); err == nil {
				t.Fatal("invalid verification feedback accepted")
			}
		})
	}
}
