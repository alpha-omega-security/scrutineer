package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
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
	if body, err = s.maybeDecrypt(body); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	revalidate, err := importRevalidate(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	results, format, err := ingest.Parse(body)
	if errors.Is(err, ingest.ErrUnrecognised) {
		s.importFallback(w, r, body)
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	repoOverride := r.URL.Query().Get("repo")
	out := make([]map[string]any, 0, len(results))
	for _, res := range results {
		summary, err := s.importResult(res, repoOverride, revalidate)
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

// importRevalidate reads the ?revalidate= toggle that controls whether
// each newly-imported finding is fed into the revalidate -> verify funnel.
// Absent means true: the default behaviour, since an external tool's
// severity is an unvalidated claim worth the cheap pre-sort. An explicit
// false (or 0) imports the findings as-is and enqueues nothing — for
// callers ingesting already-audited findings, such as a trusted sharing
// bundle that already carries the full audit narrative. A malformed value
// is a 400 rather than a silent fall-back to true, so a caller that meant
// to disable the funnel never gets billed for it by a typo.
func importRevalidate(r *http.Request) (bool, error) {
	v := r.URL.Query().Get("revalidate")
	if v == "" {
		return true, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("revalidate: must be true or false, got %q", v)
	}
	return b, nil
}

// ingestSkillName is the skill that normalises reports no deterministic
// parser recognises.
const ingestSkillName = "ingest"

// importFallback routes a payload that matched no supported format to the
// ingest skill. The raw bytes ride on the Scan row and the worker stages
// them into the workspace at import/report, where the skill reads them.
// Nothing parsed, so there is no provenance to take a repository from;
// ?repo= is required.
func (s *Server) importFallback(w http.ResponseWriter, r *http.Request, body []byte) {
	repoURL := r.URL.Query().Get("repo")
	if repoURL == "" {
		writeAPIError(w, http.StatusUnprocessableEntity,
			ingest.ErrUnrecognised.Error()+"; pass ?repo= to route the payload to the ingest skill instead")
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", ingestSkillName, true).First(&skill).Error; err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity,
			ingest.ErrUnrecognised.Error()+"; the ingest skill is not available to take it")
		return
	}
	repo, err := s.ensureImportRepo(repoURL)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	scanID, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{ImportPayload: body})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Log.Info("import: routed unrecognised payload to ingest skill",
		"repo", repo.URL, "scan", scanID, "bytes", len(body))
	writeJSON(w, http.StatusAccepted, map[string]any{
		"format":        "unrecognised",
		"repository_id": repo.ID,
		"repository":    repo.URL,
		"scan_id":       scanID,
		"skill":         ingestSkillName,
		"status":        "queued",
	})
}

// ensureImportRepo resolves a repository URL from an import request to a
// Repository row, creating it on first sight.
func (s *Server) ensureImportRepo(repoURL string) (db.Repository, error) {
	input, err := ParseRepoInput(repoURL)
	if err != nil {
		return db.Repository{}, fmt.Errorf("repository %q: %w", repoURL, err)
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
		return db.Repository{}, err
	}
	return repo, nil
}

func (s *Server) importResult(res ingest.Result, repoOverride string, revalidate bool) (map[string]any, error) {
	repoURL := res.RepoURL
	if repoOverride != "" {
		repoURL = repoOverride
	}
	if repoURL == "" {
		return nil, fmt.Errorf("repository unknown: report has no provenance and no ?repo= supplied")
	}
	repo, err := s.ensureImportRepo(repoURL)
	if err != nil {
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

	created, observed := s.importFindings(&scan, res, revalidate)
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
func (s *Server) importFindings(scan *db.Scan, res ingest.Result, revalidate bool) (created []uint, observed int) {
	seen := map[string]bool{}
	for _, in := range res.Findings {
		// A bundle may carry a per-finding commit (findings from scans at
		// different revisions); fall back to the scan/bundle commit, which is
		// all the other formats supply.
		commit := firstNonEmpty(in.Commit, scan.Commit)
		f := db.Finding{
			ScanID:         scan.ID,
			RepositoryID:   scan.RepositoryID,
			Commit:         commit,
			SubPath:        in.SubPath,
			Title:          in.Title,
			Severity:       in.Severity,
			Confidence:     firstNonEmpty(in.Confidence, "low"),
			CWE:            in.CWE,
			Location:       in.Location,
			Locations:      in.Locations,
			VID:            in.VID,
			Reachability:   in.Reachability,
			QualityTier:    in.QualityTier,
			Trace:          appendFixDescription(in.Description, in.SuggestedFix, in.FixCommit),
			Boundary:       in.Boundary,
			Validation:     in.Validation,
			PriorArt:       in.PriorArt,
			Reach:          in.Reach,
			Rating:         in.Rating,
			ImportedFrom:   res.Tool,
			LastSeenScanID: scan.ID,
			LastSeenCommit: commit,
			SeenCount:      1,
		}
		// Include the sub-path so two findings at the same CWE/location/title
		// in different monorepo sub-projects do not collide on one fingerprint.
		// Other formats leave SubPath empty, so their fingerprint is unchanged.
		f.Fingerprint = db.FingerprintFinding(res.Tool, f.SubPath, f.CWE, f.Location, f.Title)

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
		// Imported findings carry an external tool's unvalidated severity
		// claim, so revalidate runs over every newly-imported finding
		// regardless of severity (not just High/Critical, as it does for
		// security-deep-dive output). ?revalidate=false skips this — and the
		// verify it chains into — for callers importing already-audited
		// findings such as a trusted sharing bundle.
		if revalidate {
			fcopy := f
			// Imports have no parent scan and hence no resolved profile to carry;
			// revalidate detects fresh, and its resolved profile then carries into
			// the chained verify (autoChainVerifyAfterRevalidate). See #548.
			s.enqueueRevalidateForFinding(context.Background(), &fcopy, "")
		}
	}
	return created, observed
}

// maybeDecrypt transparently decrypts an age-encrypted body. If the body
// is not encrypted (no age header), it is returned unchanged — so
// unencrypted imports keep working regardless of whether identities are
// configured.
//
// The live DB stays plaintext by design (it is inside the trust boundary);
// only the exported sharing artifact is encrypted.
//
// No revocation: removing someone from the recipients file only blocks
// future exports; anything they already received stays decryptable.
//
// No sender authentication: a recipient can verify the bundle wasn't
// tampered with, but not cryptographically prove who produced it.
func (s *Server) maybeDecrypt(body []byte) ([]byte, error) {
	const ageBinaryMagic = "age-encryption.org/v1\n"
	var src io.Reader
	switch {
	case bytes.HasPrefix(body, []byte(armor.Header)):
		src = armor.NewReader(bytes.NewReader(body))
	case bytes.HasPrefix(body, []byte(ageBinaryMagic)):
		src = bytes.NewReader(body)
	default:
		return body, nil // not encrypted — pass straight through
	}
	if len(s.EncIdentities) == 0 {
		return nil, errors.New("encrypted import received but no identity configured (-identity-file)")
	}
	r, err := age.Decrypt(src, s.EncIdentities...)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return io.ReadAll(r)
}

// appendFixDescription folds an ingested fix description into the Trace
// markdown rather than writing Finding.SuggestedFix, which is reserved for
// diffs that have passed gatePatch (see finding_patch.go). When the source
// also supplied the base commit the fix applies to, it is noted alongside so
// the operator can rebase before promoting the diff.
func appendFixDescription(desc, fix, fixCommit string) string {
	fix = strings.TrimSpace(fix)
	if fix == "" {
		return desc
	}
	section := "## Suggested fix\n\n"
	if fixCommit = strings.TrimSpace(fixCommit); fixCommit != "" {
		section += "Applies to commit `" + fixCommit + "`.\n\n"
	}
	section += fix
	if desc == "" {
		return section
	}
	return desc + "\n\n" + section
}
