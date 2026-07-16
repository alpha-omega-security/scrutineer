package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// validateFix composes the fix-validation pipeline into one operation.
// Given a repository, a candidate fix ref, and one or more finding
// ids that must share a baseline (producing) scan, it:
//
//  1. enqueues a finding-scoped verify against the fix ref for each finding,
//     so the reproduction is re-run where the fix lives; and
//  2. re-runs the baseline scan's skill against the fix ref as the anchor
//     scan, marked with BaselineScanID so onScanFinalized computes the
//     fingerprint diff (resolved/surviving/new) and writes the single
//     validation report once the re-scan finalizes.
//
// The findings must come from one baseline scan so the re-scan uses one skill
// and the fingerprint diff is apples-to-apples (same skill is part of the
// fingerprint). Verify scans carry PrioFinding, so they run ahead of the
// PrioScan anchor and their verdicts are usually ready when the report is
// assembled.
func (s *Server) validateFix(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}

	ref := strings.TrimSpace(r.FormValue("ref"))
	if ref == "" {
		s.validateFixReject(w, r, repo.ID, "a fix ref is required")
		return
	}
	if err := worker.ValidateGitRef(ref); err != nil {
		s.validateFixReject(w, r, repo.ID, fmt.Sprintf("invalid fix ref: %v", err))
		return
	}

	findingIDs, err := parseFindingIDs(r)
	if err != nil {
		s.validateFixReject(w, r, repo.ID, err.Error())
		return
	}

	var findings []db.Finding
	if err := s.DB.Where("id IN ? AND repository_id = ?", findingIDs, repo.ID).Find(&findings).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(findings) != len(findingIDs) {
		s.validateFixReject(w, r, repo.ID, "some findings were not found on this repository")
		return
	}
	baselineScanID := findings[0].ScanID
	for _, f := range findings {
		if f.ScanID != baselineScanID {
			s.validateFixReject(w, r, repo.ID, "all findings must come from the same baseline scan")
			return
		}
	}

	var baseline db.Scan
	if err := s.DB.First(&baseline, baselineScanID).Error; err != nil {
		http.Error(w, "baseline scan not found", http.StatusInternalServerError)
		return
	}
	if baseline.SkillID == nil {
		s.validateFixReject(w, r, repo.ID, "baseline scan has no skill to re-run against the fix ref")
		return
	}

	model := r.FormValue("model")
	s.enqueueValidateFixVerify(r, repo.ID, findings, ref, model)

	anchorID, err := s.enqueueSkillWith(r.Context(), repo.ID, *baseline.SkillID, ScanOpts{
		Model:          model,
		Ref:            ref,
		SubPath:        baseline.SubPath,
		BaselineScanID: &baselineScanID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", anchorID))
}

// enqueueValidateFixVerify runs the verify skill finding-scoped against the
// fix ref for each targeted finding. A missing verify skill degrades to "no
// reproduction-level check" rather than failing the operation; a verify for
// the same finding against the same ref already in flight is skipped so a
// re-submit does not pile up duplicates.
func (s *Server) enqueueValidateFixVerify(r *http.Request, repoID uint, findings []db.Finding, ref, model string) {
	var verifySkill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", verifySkillName, true).First(&verifySkill).Error; err != nil {
		return
	}
	for _, f := range findings {
		fid := f.ID
		if s.hasOpenScan("finding_id = ? AND skill_id = ? AND ref = ?", fid, verifySkill.ID, ref) {
			continue
		}
		if _, err := s.enqueueSkillWith(r.Context(), repoID, verifySkill.ID, ScanOpts{
			Model:     model,
			FindingID: &fid,
			Ref:       ref,
		}); err != nil {
			s.Log.Warn("validate-fix: enqueue verify", "finding", fid, "ref", ref, "err", err)
		}
	}
}

func (s *Server) validateFixReject(w http.ResponseWriter, r *http.Request, repoID uint, msg string) {
	setFlash(w, Flash{Category: errorKey, Title: msg})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d", repoID))
}

// parseFindingIDs reads the finding_ids form values, which may arrive as
// repeated fields and/or comma-separated lists, into a de-duplicated slice.
// An empty or malformed set is an error so the caller can flash it.
func parseFindingIDs(r *http.Request) ([]uint, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("could not parse form: %w", err)
	}
	seen := map[uint]bool{}
	var ids []uint
	for _, field := range r.Form["finding_ids"] {
		for raw := range strings.SplitSeq(field, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			n, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid finding id %q", raw)
			}
			if id := uint(n); !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("at least one finding id is required")
	}
	return ids, nil
}

// onScanFinalized is the single OnScanFinalized hook: it computes the
// fix-validation report for anchor scans and runs the existing post-deep-dive
// dedup pass for everything else. Both inspect committed state, so order does
// not matter; autoEnqueueFindingDedup already skips anchor scans.
func (s *Server) onScanFinalized(scan *db.Scan) {
	s.autoUpdateThreatModel(scan)
	s.autoSeedRepoScanConfig(scan)
	s.autoEnqueueFocusAreaDeepDives(scan)
	s.autoComputeFixValidation(scan)
	s.autoEnqueueFindingDedup(scan)
}

// autoComputeFixValidation is the anchor half of onScanFinalized. For a scan
// marked with BaselineScanID it diffs the baseline scan's findings against the
// re-scan by fingerprint, folds in the verify verdicts, and stores the JSON
// report on the scan so the existing report view renders it. Errors are logged
// and swallowed: a failed report must not fail the re-scan itself.
func (s *Server) autoComputeFixValidation(scan *db.Scan) {
	if scan == nil || scan.BaselineScanID == nil {
		return
	}
	baselineID := *scan.BaselineScanID

	var baseline []db.Finding
	if err := s.DB.Where("scan_id = ?", baselineID).Find(&baseline).Error; err != nil {
		s.Log.Warn("fix-validation: load baseline findings", "scan", scan.ID, "baseline", baselineID, "err", err)
		return
	}
	var fixNew []db.Finding
	if err := s.DB.Where("scan_id = ?", scan.ID).Find(&fixNew).Error; err != nil {
		s.Log.Warn("fix-validation: load fix findings", "scan", scan.ID, "err", err)
		return
	}

	report := buildFixValidationReport(*scan, baselineID, baseline, fixNew, s.fixValidationVerdicts(baseline, scan.Ref))
	payload, err := json.Marshal(report)
	if err != nil {
		s.Log.Warn("fix-validation: marshal report", "scan", scan.ID, "err", err)
		return
	}
	if err := s.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("report", string(payload)).Error; err != nil {
		s.Log.Warn("fix-validation: store report", "scan", scan.ID, "err", err)
	}
}

// fixValidationVerdicts collects, for each baseline finding that had a verify
// run against the fix ref, that verify's reproduction-level verdict. Findings
// with no verify-against-ref scan are omitted; one whose verify has not yet
// finished is reported pending. One query (not one per finding) keeps the
// not-found case quiet and cheap; the latest scan per finding wins.
func (s *Server) fixValidationVerdicts(baseline []db.Finding, ref string) []fixValidationVerify {
	if len(baseline) == 0 {
		return nil
	}
	ids := make([]uint, len(baseline))
	titleByID := make(map[uint]string, len(baseline))
	for i, f := range baseline {
		ids[i] = f.ID
		titleByID[f.ID] = f.Title
	}

	var scans []db.Scan
	if err := s.DB.Select("finding_id, status, report").
		Where("finding_id IN ? AND skill_name = ? AND ref = ?", ids, verifySkillName, ref).
		Order("id desc").
		Find(&scans).Error; err != nil {
		s.Log.Warn("fix-validation: load verify verdicts", "ref", ref, "err", err)
		return nil
	}

	seen := map[uint]bool{}
	var out []fixValidationVerify
	for _, sc := range scans {
		if sc.FindingID == nil || seen[*sc.FindingID] {
			continue
		}
		seen[*sc.FindingID] = true
		status := verifyStatusPending
		if sc.Status == db.ScanDone {
			if st := parseVerifyStatus(sc.Report); st != "" {
				status = st
			}
		}
		out = append(out, fixValidationVerify{FindingID: *sc.FindingID, Title: titleByID[*sc.FindingID], Status: status})
	}
	return out
}
