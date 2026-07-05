package web

import (
	"net/http"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

type benchmarkRow struct {
	Repo               db.Repository
	Scan               *db.Scan
	Expected           int
	Matched            int
	Findings           int
	Recall             float64
	Precision          float64
	F1                 float64
	Skill              string
	Model              string
	HarnessSHA         string
	SkillSchemaVersion int
}

type benchmarkTotals struct {
	Expected  int
	Matched   int
	Findings  int
	Recall    float64
	Precision float64
	F1        float64
}

func (s *Server) benchmark(w http.ResponseWriter, r *http.Request) {
	skill := strings.TrimSpace(r.URL.Query().Get("skill"))
	model := strings.TrimSpace(r.URL.Query().Get("model"))
	harness := strings.TrimSpace(r.URL.Query().Get("harness"))
	rows, totals := loadBenchmarkRows(s.DB, skill, model, harness)
	s.render(w, r, "benchmark.html", map[string]any{
		"Rows":    rows,
		"Totals":  totals,
		"Skill":   skill,
		"Model":   model,
		"Harness": harness,
	})
}

func loadBenchmarkRows(gdb *gorm.DB, skill, model, harness string) ([]benchmarkRow, benchmarkTotals) {
	var repos []db.Repository
	gdb.Joins("JOIN expected_findings ef ON ef.repository_id = repositories.id").
		Group("repositories.id").
		Order("repositories.name").
		Find(&repos)

	rows := make([]benchmarkRow, 0, len(repos))
	var totals benchmarkTotals
	for _, repo := range repos {
		var expected []db.ExpectedFinding
		gdb.Where("repository_id = ?", repo.ID).Order("file, cwe").Find(&expected)
		row := benchmarkRow{Repo: repo, Expected: len(expected)}
		scan := latestBenchmarkScan(gdb, repo.ID, skill, model, harness)
		if scan != nil {
			matches := expectedMatchesForRows(gdb, repo.ID, scan.ID, expected)
			row.Scan = scan
			row.Matched = matches.MatchedTotal
			row.Findings = matches.FindingTotal
			row.Skill = scan.SkillName
			row.Model = scan.Model
			row.HarnessSHA = scan.SkillsRepoSHA
			row.SkillSchemaVersion = scan.SkillSchemaVersion
			row.Recall = ratio(row.Matched, row.Expected)
			row.Precision = ratio(row.Matched, row.Findings)
			row.F1 = f1(row.Recall, row.Precision)
		}
		totals.Expected += row.Expected
		totals.Matched += row.Matched
		totals.Findings += row.Findings
		rows = append(rows, row)
	}
	totals.Recall = ratio(totals.Matched, totals.Expected)
	totals.Precision = ratio(totals.Matched, totals.Findings)
	totals.F1 = f1(totals.Recall, totals.Precision)
	return rows, totals
}

func latestBenchmarkScan(gdb *gorm.DB, repoID uint, skill, model, harness string) *db.Scan {
	q := gdb.Where("repository_id = ? AND status = ?", repoID, db.ScanDone)
	if skill != "" {
		q = q.Where("skill_name = ?", skill)
	} else {
		q = q.Where("skill_name IN ?", []string{deepDiveSkillName, vulnScanSkillName})
	}
	if model != "" {
		q = q.Where("model = ?", model)
	}
	if harness != "" {
		q = q.Where("skills_repo_sha = ?", harness)
	}
	var scan db.Scan
	if err := q.Order("id desc").First(&scan).Error; err != nil {
		return nil
	}
	return &scan
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

func f1(recall, precision float64) float64 {
	if recall == 0 || precision == 0 {
		return 0
	}
	const harmonicMeanScale = 2
	return harmonicMeanScale * recall * precision / (recall + precision)
}
