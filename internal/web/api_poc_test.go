package web

import (
	"os"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

func TestAPIValidateReportPoCFences(t *testing.T) {
	skill, err := skills.ParseFile("../../skills/audit-injection/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../poc/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	s, done := newTestServer(t)
	defer done()
	scan := seedScanWithSkill(t, s, skill.SchemaJSON)
	if err := s.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Update("name", "audit-injection").Error; err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, report, want string
	}{
		{"named file", string(raw), ""},
		{"dash header", strings.Replace(string(raw), "```text filename=input.txt", "--- input.txt ---", 1), "/findings/0/validation"},
		{"unnamed file", strings.Replace(string(raw), "text filename=input.txt", "sh", 1), "filename=relative/path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := postValidate(t, s, scan.ID, scan.APIToken, tc.report)
			if code != 200 || out["valid"] != (tc.want == "") {
				t.Fatalf("response = %d, %+v", code, out)
			}
			if tc.want != "" {
				detail, _ := out["errors"].(string)
				if !strings.Contains(detail, tc.want) {
					t.Fatalf("errors = %q, want %q", detail, tc.want)
				}
			}
		})
	}
}
