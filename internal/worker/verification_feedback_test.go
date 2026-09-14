package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

func TestVerificationFeedbackContextAndRecipe(t *testing.T) {
	for _, name := range []string{"verify", "critic"} {
		t.Run(name, func(t *testing.T) {
			scan := db.Scan{SkillName: name, FindingID: new(uint(1)), VerificationFeedback: "Check the first-party parser"}
			dir := t.TempDir()
			if err := stageContext(dir, "", "", "", "", &scan, &db.Repository{}); err != nil {
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
