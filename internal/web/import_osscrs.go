package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"scrutineer/internal/db"
	"scrutineer/internal/ingest"
	"scrutineer/internal/osscrs"
	"scrutineer/internal/poc"
)

// ossCRSMaxBody is above importMaxBody because `oss-crs archive` also packs
// the run's seed corpus, which the adapter skips while streaming.
const ossCRSMaxBody = 256 << 20

const ossCRSProducer = "oss-crs"

const maxOSSCRSRunLen = 200

type ossCRSArtifact struct {
	db.ImportArtifact
	Stored bool `json:"stored"`
}

type ossCRSImportResponse struct {
	Format       string           `json:"format"`
	Run          string           `json:"run"`
	ScanID       uint             `json:"scan_id"`
	RepositoryID uint             `json:"repository_id"`
	Results      []map[string]any `json:"results"`
	Artifacts    []ossCRSArtifact `json:"artifacts"`
	Skipped      []osscrs.Skipped `json:"skipped"`
	Unresolved   []string         `json:"unresolved_attachments"`
	Warnings     []string         `json:"warnings"`
}

// handleImportOSSCRS imports one `oss-crs archive` tarball. The archive
// carries neither the target repository nor the revision, so both are
// required from the operator. Bug candidates go through the SARIF import
// path, and every PoV, patch and report is retained in import_artifacts,
// associated with a finding only when a candidate names it in
// result.attachments.
func (s *Server) handleImportOSSCRS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	repoURL, commit, run := strings.TrimSpace(q.Get("repo")), strings.TrimSpace(q.Get("commit")), strings.TrimSpace(q.Get("run"))
	if repoURL == "" || commit == "" {
		writeAPIError(w, http.StatusBadRequest, "repo and commit are required: an oss-crs archive carries no target provenance")
		return
	}
	if len(run) > maxOSSCRSRunLen || strings.ContainsFunc(run, unicode.IsControl) {
		writeAPIError(w, http.StatusBadRequest, "run: must be at most 200 printable characters")
		return
	}
	revalidate, err := importRevalidate(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	archive, err := osscrs.Read(http.MaxBytesReader(w, r.Body, ossCRSMaxBody))
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		writeAPIError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d bytes", ossCRSMaxBody))
		return
	}
	if errors.Is(err, osscrs.ErrTooLarge) {
		writeAPIError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	for i := range archive.Candidates {
		if archive.Candidates[i].Commit == "" {
			archive.Candidates[i].Commit = commit
		}
	}

	var (
		repo       db.Repository
		scan       db.Scan
		imported   []importedResult
		artifacts  []ossCRSArtifact
		unresolved []string
		warnings   []string
	)
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		if repo, err = ensureImportRepoWith(tx, repoURL); err != nil {
			return err
		}
		if imported, err = s.importResultsWith(tx, archive.Candidates, ingest.FormatSARIF, repoURL); err != nil {
			return err
		}
		links, missing, err := ossCRSLinks(tx, repo.ID, archive)
		if err != nil {
			return err
		}
		unresolved = missing
		now := time.Now()
		scan = db.Scan{
			RepositoryID: repo.ID,
			Kind:         "import",
			Status:       db.ScanDone,
			SkillName:    ossCRSProducer,
			Commit:       commit,
			StartedAt:    &now,
			FinishedAt:   &now,
		}
		scan.StatusPriority = db.StatusPriorityFor(scan.Status)
		scan.Log = ossCRSLog(run, archive, unresolved)
		if err := tx.Create(&scan).Error; err != nil {
			return err
		}
		if artifacts, err = storeOSSCRSArtifacts(tx, scan, archive.Artifacts, links); err != nil {
			return err
		}
		warnings, err = captureOSSCRSPoVs(tx, scan, archive.Artifacts, links)
		return err
	})
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.enqueueImportedRepoMetadata(context.Background(), repo)
	writeJSON(w, http.StatusCreated, ossCRSImportResponse{
		Format:       ossCRSProducer,
		Run:          run,
		ScanID:       scan.ID,
		RepositoryID: scan.RepositoryID,
		Results:      s.finishImport(imported, revalidate),
		Artifacts:    nonNil(artifacts),
		Skipped:      nonNil(archive.Skipped),
		Unresolved:   nonNil(unresolved),
		Warnings:     nonNil(warnings),
	})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ossCRSLinks resolves each candidate's attachments to the findings the
// import created or observed, keyed by archive path. Attachments naming no
// retained artifact are returned so the operator sees them.
func ossCRSLinks(tx *gorm.DB, repoID uint, archive osscrs.Archive) (map[string][]uint, []string, error) {
	retained := map[string]bool{}
	for _, a := range archive.Artifacts {
		retained[a.Path] = true
	}
	byFingerprint := map[string][]string{}
	var fingerprints, missing []string
	for _, res := range archive.Candidates {
		for _, f := range res.Findings {
			if len(f.Attachments) == 0 {
				continue
			}
			fp := importFingerprint(res.Tool, f)
			if _, ok := byFingerprint[fp]; !ok {
				fingerprints = append(fingerprints, fp)
			}
			for _, p := range f.Attachments {
				if !retained[p] {
					missing = append(missing, p)
					continue
				}
				byFingerprint[fp] = append(byFingerprint[fp], p)
			}
		}
	}
	existing, err := existingByFingerprint(tx, repoID, fingerprints)
	if err != nil {
		return nil, nil, err
	}
	links := map[string][]uint{}
	for _, fp := range fingerprints {
		finding, ok := existing[fp]
		if !ok {
			// Dropped by the import caps, so its attachments stay unassociated.
			continue
		}
		for _, p := range byFingerprint[fp] {
			if !slices.Contains(links[p], finding.ID) {
				links[p] = append(links[p], finding.ID)
			}
		}
	}
	slices.Sort(missing)
	return links, slices.Compact(missing), nil
}

// storeOSSCRSArtifacts keeps the first copy of each artifact's bytes per
// repository and finding, so a repeat import, or a second archive path with
// the same bytes, reports Stored false instead of duplicating them.
func storeOSSCRSArtifacts(tx *gorm.DB, scan db.Scan, artifacts []osscrs.Artifact, links map[string][]uint) ([]ossCRSArtifact, error) {
	var out []ossCRSArtifact
	for _, a := range artifacts {
		findingIDs := links[a.Path]
		if len(findingIDs) == 0 {
			findingIDs = []uint{0}
		}
		for _, findingID := range findingIDs {
			row := db.ImportArtifact{
				RepositoryID: scan.RepositoryID, FindingID: findingID, Kind: a.Kind, SHA256: a.SHA256,
				ScanID: scan.ID, Path: a.Path, Bytes: len(a.Data), Data: a.Data,
			}
			res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
			if res.Error != nil {
				return nil, fmt.Errorf("store %s: %w", a.Path, res.Error)
			}
			if res.RowsAffected == 1 {
				out = append(out, ossCRSArtifact{ImportArtifact: row, Stored: true})
				continue
			}
			var existing db.ImportArtifact
			if err := tx.Omit("data").Where("repository_id = ? AND finding_id = ? AND kind = ? AND sha256 = ?",
				row.RepositoryID, row.FindingID, row.Kind, row.SHA256).First(&existing).Error; err != nil {
				return nil, fmt.Errorf("load stored %s: %w", a.Path, err)
			}
			out = append(out, ossCRSArtifact{ImportArtifact: existing})
		}
	}
	return out, nil
}

// captureOSSCRSPoVs hands each finding's associated PoVs to the captured-PoC
// store, which verify stages and the disclosure bundle prefers. The first
// capture wins, as it does for a scan workspace capture.
func captureOSSCRSPoVs(tx *gorm.DB, scan db.Scan, artifacts []osscrs.Artifact, links map[string][]uint) ([]string, error) {
	byFinding := map[uint][]poc.File{}
	var findingIDs []uint
	for _, a := range artifacts {
		if a.Kind != osscrs.KindPoV {
			continue
		}
		for _, id := range links[a.Path] {
			if _, ok := byFinding[id]; !ok {
				findingIDs = append(findingIDs, id)
			}
			byFinding[id] = append(byFinding[id], poc.File{Path: a.Path, Data: a.Data, SHA256: a.SHA256})
		}
	}
	var warnings []string
	for _, id := range findingIDs {
		files := byFinding[id]
		if err := poc.ValidateFiles(files); err != nil {
			warnings = append(warnings, fmt.Sprintf("finding %d: PoVs not captured: %v", id, err))
			continue
		}
		data, err := json.Marshal(files)
		if err != nil {
			return nil, err
		}
		row := db.FindingPoC{FindingID: id, ScanID: scan.ID, Commit: scan.Commit, Files: data}
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "finding_id"}}, DoNothing: true}).Create(&row).Error; err != nil {
			return nil, fmt.Errorf("capture PoVs for finding %d: %w", id, err)
		}
	}
	return warnings, nil
}

func ossCRSLog(run string, archive osscrs.Archive, unresolved []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "oss-crs run: %s\n", run)
	fmt.Fprintf(&b, "bug candidate runs: %d, artifacts: %d\n", len(archive.Candidates), len(archive.Artifacts))
	for _, sk := range archive.Skipped {
		fmt.Fprintf(&b, "skipped %s (%d files): %s\n", sk.Path, sk.Files, sk.Reason)
	}
	for _, p := range unresolved {
		fmt.Fprintf(&b, "unresolved attachment: %s\n", p)
	}
	return b.String()
}

func (s *Server) apiListImportArtifacts(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.loadExportRepositoryByID(w, r)
	if !ok {
		return
	}
	var rows []db.ImportArtifact
	if err := s.DB.Select("id", "repository_id", "finding_id", "kind", "sha256", "scan_id", "path", "bytes", "created_at").
		Where("repository_id = ?", repo.ID).Order("id").Find(&rows).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) apiDownloadImportArtifact(w http.ResponseWriter, r *http.Request) {
	id, ok := exportPathID(w, r, "artifact")
	if !ok {
		return
	}
	var row db.ImportArtifact
	if err := s.DB.First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeAPIError(w, http.StatusNotFound, "artifact not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(row.Path)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(row.Data)
}
