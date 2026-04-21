package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// orgReport renders a consolidated markdown document covering every
// finding across every repository owned by the given login. Structure
// mirrors the per-repo report: header, severity summary, then one
// section per repository with the full six-step prose for each finding.
// Served as text/markdown with a filename hint.
func (s *Server) orgReport(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("login")
	if owner == "" {
		http.NotFound(w, r)
		return
	}
	var repos []db.Repository
	s.DB.Where("owner = ?", owner).Order("name").Find(&repos)
	if len(repos) == 0 {
		http.NotFound(w, r)
		return
	}

	body := renderOrgReport(s.DB, owner, repos)
	filename := fmt.Sprintf("scrutineer-%s-findings-%s.md",
		sanitiseFilename(owner),
		time.Now().UTC().Format("20060102"))
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write([]byte(body))
}

// renderOrgReport composes the full markdown document. Repos with no
// findings appear in the count but are omitted from the body so the
// document is scannable and doesn't accumulate empty sections.
func renderOrgReport(gdb *gorm.DB, owner string, repos []db.Repository) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# scrutineer findings report: %s\n\n", owner)
	fmt.Fprintf(&b, "Generated %s\n\n", time.Now().UTC().Format(time.RFC3339))

	repoIDs := make([]uint, 0, len(repos))
	for _, r := range repos {
		repoIDs = append(repoIDs, r.ID)
	}
	var findings []db.Finding
	gdb.Where("repository_id IN ?", repoIDs).
		Order("severity, id").Find(&findings)

	bySeverity := map[string]int{}
	byStatus := map[string]int{}
	byRepo := map[uint][]db.Finding{}
	for _, f := range findings {
		bySeverity[f.Severity]++
		byStatus[string(f.Status)]++
		byRepo[f.RepositoryID] = append(byRepo[f.RepositoryID], f)
	}

	writeOrgSummary(&b, repos, findings, bySeverity, byStatus, byRepo)

	// Per-repo sections, alphabetical within the ones that have
	// findings. Repos without findings stay visible in the top-level
	// coverage table but get no section of their own.
	reposByID := make(map[uint]db.Repository, len(repos))
	for _, r := range repos {
		reposByID[r.ID] = r
	}
	repoIDsWithFindings := make([]uint, 0, len(byRepo))
	for id := range byRepo {
		repoIDsWithFindings = append(repoIDsWithFindings, id)
	}
	sort.Slice(repoIDsWithFindings, func(i, j int) bool {
		return reposByID[repoIDsWithFindings[i]].Name < reposByID[repoIDsWithFindings[j]].Name
	})
	for _, id := range repoIDsWithFindings {
		repo := reposByID[id]
		rf := byRepo[id]
		writeOrgRepoSection(&b, gdb, repo, rf)
	}

	return b.String()
}

func writeOrgSummary(b *strings.Builder, repos []db.Repository, findings []db.Finding,
	bySeverity, byStatus map[string]int, byRepo map[uint][]db.Finding) {
	fmt.Fprintf(b, "## Summary\n\n")
	fmt.Fprintf(b, "- Repositories: %d\n", len(repos))
	fmt.Fprintf(b, "- Repositories with findings: %d\n", len(byRepo))
	fmt.Fprintf(b, "- Total findings: %d\n\n", len(findings))

	if len(bySeverity) > 0 {
		fmt.Fprintf(b, "### Severity breakdown\n\n| Severity | Count |\n|---|---|\n")
		for _, s := range []string{"Critical", "High", "Medium", "Low"} {
			if n := bySeverity[s]; n > 0 {
				fmt.Fprintf(b, "| %s | %d |\n", s, n)
			}
		}
		b.WriteString("\n")
	}
	if len(byStatus) > 0 {
		fmt.Fprintf(b, "### Status breakdown\n\n| Status | Count |\n|---|---|\n")
		for _, s := range []string{"new", "enriched", "triaged", "ready", "reported", "acknowledged", "fixed", "published", "rejected", "duplicate"} {
			if n := byStatus[s]; n > 0 {
				fmt.Fprintf(b, "| %s | %d |\n", s, n)
			}
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(b, "### Coverage\n\n| Repository | Findings |\n|---|---|\n")
	for _, r := range repos {
		fmt.Fprintf(b, "| %s | %d |\n", r.Name, len(byRepo[r.ID]))
	}
	b.WriteString("\n")
}

func writeOrgRepoSection(b *strings.Builder, gdb *gorm.DB, repo db.Repository, findings []db.Finding) {
	fmt.Fprintf(b, "---\n\n## %s\n\n", repo.Name)
	if repo.URL != "" {
		fmt.Fprintf(b, "%s\n\n", repo.URL)
	}
	if repo.Description != "" {
		fmt.Fprintf(b, "%s\n\n", escapeMD(repo.Description))
	}
	fmt.Fprintf(b, "%d finding(s).\n\n", len(findings))

	fmt.Fprintf(b, "| # | Severity | Status | Title | Location |\n|---|---|---|---|---|\n")
	for _, f := range findings {
		fmt.Fprintf(b, "| %d | %s | %s | %s | `%s` |\n",
			f.ID, f.Severity, f.Status, escapeMD(f.Title), f.Location)
	}
	b.WriteString("\n")

	for _, f := range findings {
		writeReportFinding(b, gdb, f, nil)
	}
}
