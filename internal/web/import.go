package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/ingest"
)

// importMaxBody caps the upload size. SARIF from large monorepo scans
// can run to a few megabytes; 16 MiB leaves headroom without letting an
// errant POST exhaust memory.
const importMaxBody = 16 << 20

// handleImport ingests an externally-produced report (SARIF or the
// minimal JSON shape) and turns it into Repository + Scan + Finding
// rows. The repository is taken from the report's own provenance when
// present; otherwise the caller must pass ?repo=<url>. Each ingest
// batch becomes one Scan row with Kind "import" so the findings have a
// parent and show up in the scans list alongside skill runs.
//
// Response is JSON regardless of Accept so curl callers get structured
// output; a browser upload form can be layered on later.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importMaxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeAPIError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("body exceeds %d bytes", importMaxBody))
			return
		}
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("read body: %v", err))
		return
	}
	if len(body) == 0 {
		writeAPIError(w, http.StatusBadRequest, "empty body")
		return
	}
	results, format, err := ingest.Parse(body)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	repoOverride := r.URL.Query().Get("repo")
	out := make([]map[string]any, 0, len(results))
	for _, res := range results {
		summary, err := s.importResult(res, repoOverride)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		out = append(out, summary)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"format":  string(format),
		"results": out,
	})
}

func (s *Server) importResult(res ingest.Result, repoOverride string) (map[string]any, error) {
	repoURL := res.RepoURL
	if repoOverride != "" {
		repoURL = repoOverride
	}
	if repoURL == "" {
		return nil, fmt.Errorf("repository unknown: report has no provenance and no ?repo= supplied")
	}
	input, err := ParseRepoInput(repoURL)
	if err != nil {
		return nil, fmt.Errorf("repository %q: %w", repoURL, err)
	}
	repo := db.Repository{
		URL:     input.CloneURL,
		Name:    input.Name,
		Owner:   input.Owner,
		HTMLURL: DefaultHTMLURL(input.CloneURL),
	}
	if input.Owner != "" {
		repo.FullName = input.Owner + "/" + input.Name
	}
	if err := s.DB.Where(db.Repository{URL: input.CloneURL}).FirstOrCreate(&repo).Error; err != nil {
		return nil, err
	}

	now := time.Now()
	scan := db.Scan{
		RepositoryID:  repo.ID,
		Kind:          "import",
		Status:        db.ScanDone,
		SkillName:     res.Tool,
		Commit:        res.Commit,
		StartedAt:     &now,
		FinishedAt:    &now,
		FindingsCount: len(res.Findings),
	}
	scan.StatusPriority = db.StatusPriorityFor(scan.Status)
	if err := s.DB.Create(&scan).Error; err != nil {
		return nil, err
	}

	created, observed := s.importFindings(&scan, res)
	s.Log.Info("import",
		"repo", repo.URL, "tool", res.Tool, "scan", scan.ID,
		"created", len(created), "observed", observed)

	return map[string]any{
		"repository_id": repo.ID,
		"repository":    repo.URL,
		"scan_id":       scan.ID,
		"tool":          res.Tool,
		"created":       len(created),
		"observed":      observed,
		"finding_ids":   created,
	}, nil
}

// importFindings mirrors the worker's fingerprint-then-upsert loop so an
// import behaves like a scan: re-importing the same report bumps
// SeenCount on existing rows instead of inserting duplicates.
func (s *Server) importFindings(scan *db.Scan, res ingest.Result) (created []uint, observed int) {
	seen := map[string]bool{}
	for _, in := range res.Findings {
		f := db.Finding{
			ScanID:         scan.ID,
			RepositoryID:   scan.RepositoryID,
			Commit:         scan.Commit,
			Title:          in.Title,
			Severity:       in.Severity,
			Confidence:     firstNonEmpty(in.Confidence, "low"),
			CWE:            in.CWE,
			Location:       in.Location,
			Trace:          appendFixDescription(in.Description, in.SuggestedFix),
			ImportedFrom:   res.Tool,
			LastSeenScanID: scan.ID,
			LastSeenCommit: scan.Commit,
			SeenCount:      1,
		}
		f.Fingerprint = db.FingerprintFinding(res.Tool, "", f.CWE, f.Location, f.Title)

		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true

		var existing db.Finding
		err := s.DB.Where("repository_id = ? AND fingerprint = ?", scan.RepositoryID, f.Fingerprint).
			Order("id").First(&existing).Error
		if err == nil {
			s.DB.Model(&db.Finding{}).Where("id = ?", existing.ID).Updates(map[string]any{
				"last_seen_scan_id":   scan.ID,
				"last_seen_commit":    scan.Commit,
				"seen_count":          existing.SeenCount + 1,
				"missed_count":        0,
				"last_missed_scan_id": 0,
			})
			s.DB.Create(&db.FindingHistory{
				FindingID: existing.ID,
				Field:     "observed",
				NewValue:  fmt.Sprintf("import scan %d (%s)", scan.ID, res.Tool),
				Source:    db.SourceTool,
				By:        res.Tool,
			})
			observed++
			continue
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			s.Log.Error("import: lookup existing finding", "err", err)
			continue
		}
		if err := s.DB.Create(&f).Error; err != nil {
			s.Log.Error("import: create finding", "err", err)
			continue
		}
		created = append(created, f.ID)
	}
	return created, observed
}

// appendFixDescription folds an ingested fix description into the Trace
// markdown rather than writing Finding.SuggestedFix, which is reserved for
// diffs that have passed gatePatch (see finding_patch.go).
func appendFixDescription(desc, fix string) string {
	fix = strings.TrimSpace(fix)
	if fix == "" {
		return desc
	}
	if desc == "" {
		return "## Suggested fix\n\n" + fix
	}
	return desc + "\n\n## Suggested fix\n\n" + fix
}
