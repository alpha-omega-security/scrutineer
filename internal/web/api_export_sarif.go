package web

import (
	"bytes"
	"cmp"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/git-pkgs/sarif"

	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
)

const (
	sarifSchemaURI      = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifFallbackRuleID = "scrutineer/finding"
)

// sarifFindingColumns keeps disclosure drafts, recipients and federation
// contacts out of the query, so they cannot reach a report handed to other
// tools.
const sarifFindingColumns = `id, "commit", last_seen_commit, sub_path, model, fingerprint, vid,
	finding_id, title, severity, confidence, status, cwe, location, locations,
	reachability, quality_tier, imported_from,
	trace, boundary, validation, prior_art, reach, rating`

func (s *Server) apiExportRepoSARIF(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	var findings []db.Finding
	q := s.DB.Select(sarifFindingColumns).Where("repository_id = ?", repo.ID).Order("id desc")
	if err := applyFindingFilters(q, r).Find(&findings).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var verifications []db.FindingVerification
	if err := s.DB.Select("finding_id, scan_id, status, score").
		Where(`id IN (SELECT MAX(finding_verifications.id) FROM finding_verifications
			JOIN findings ON findings.id = finding_verifications.finding_id
			WHERE findings.repository_id = ? GROUP BY finding_verifications.finding_id)`, repo.ID).
		Find(&verifications).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	latest := make(map[uint]db.FindingVerification, len(verifications))
	for _, v := range verifications {
		latest[v.FindingID] = v
	}

	repositoryURL := bundleRepositoryURL(r.Context(), repo)
	if repo.IsLocal() && repositoryURL == repo.URL {
		repositoryURL = sarifFileURI(repo.LocalPath())
		if s.Log != nil {
			s.Log.Warn("sarif export: local repository has no portable origin; repositoryUri carries the host path",
				"repository_id", repo.ID)
		}
	}
	report := buildSARIF(repositoryURL, s.Version, findings, latest)
	if err := sarif.Validate(report); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var buf bytes.Buffer
	if err := sarif.Dump(report, &buf, false); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// sarifFileURI renders a local path as an RFC 8089 file URI for
// repositoryUri, which the schema requires to be a valid URI. The stored
// file://<path> form is not one on Windows, where the drive letter parses as a
// host and port (file://C:\x) and fails validation. Escaping also keeps
// spaces and other reserved characters out of the URI on every platform.
func sarifFileURI(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// buildSARIF emits one run per observed revision because SARIF records
// version control provenance per run. Location is refreshed on every
// re-observation, so it belongs to LastSeenCommit, not the first-seen Commit.
func buildSARIF(repositoryURL, version string, findings []db.Finding, verifications map[uint]db.FindingVerification) *sarif.Log {
	byRevision := map[string][]db.Finding{}
	for _, f := range findings {
		rev := cmp.Or(f.LastSeenCommit, f.Commit)
		byRevision[rev] = append(byRevision[rev], f)
	}
	if len(byRevision) == 0 {
		byRevision[""] = nil
	}
	report := &sarif.Log{Version: "2.1.0", SchemaURI: sarifSchemaURI}
	for _, rev := range slices.Sorted(maps.Keys(byRevision)) {
		report.Runs = append(report.Runs, sarifRevisionRun(repositoryURL, rev, version, byRevision[rev], verifications))
	}
	return report
}

func sarifRevisionRun(repositoryURL, revision, version string, findings []db.Finding, verifications map[uint]db.FindingVerification) sarif.Run {
	run := sarif.NewRun()
	run.Tool = sarif.NewTool()
	run.Tool.Driver = sarif.NewToolComponent()
	run.Tool.Driver.Name = "scrutineer"
	run.Tool.Driver.Version = version
	run.Tool.Driver.InformationURI = "https://github.com/alpha-omega-security/scrutineer"
	run.VersionControlProvenance = []sarif.VersionControlDetails{{RepositoryURI: repositoryURL, RevisionID: revision}}
	// OSS-CRS rejects a run whose results key is absent, and the library
	// omits a nil slice.
	run.Results = []sarif.Result{}
	rules := map[string]bool{}
	for _, f := range findings {
		res := sarifResult(f, verifications)
		rules[res.RuleID] = true
		run.Results = append(run.Results, res)
	}
	for _, id := range slices.Sorted(maps.Keys(rules)) {
		rule := sarif.NewReportingDescriptor()
		rule.ID = id
		tags := []string{"security"}
		if strings.HasPrefix(id, "CWE-") {
			tags = append(tags, "external/cwe/"+strings.ToLower(id))
		}
		rule.Properties = sarif.PropertyBag{"tags": tags}
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
	}
	return run
}

func sarifResult(f db.Finding, verifications map[uint]db.FindingVerification) sarif.Result {
	res := sarif.NewResult()
	cwe, _, _ := strings.Cut(f.CWE, ",")
	res.RuleID = cmp.Or(findingnorm.CWE(cwe), sarifFallbackRuleID)
	res.Level = sarifLevel(f.Severity)
	res.Message = sarif.Message{Text: cmp.Or(strings.TrimSpace(f.Title), res.RuleID)}
	if loc, ok := sarifLocation(f.SubPath, f.Location); ok {
		res.Locations = []sarif.Location{loc}
	}
	for _, hit := range f.LocationList() {
		if hit == strings.TrimSpace(f.Location) {
			continue
		}
		if loc, ok := sarifLocation(f.SubPath, hit); ok {
			res.RelatedLocations = append(res.RelatedLocations, loc)
		}
	}
	if f.Fingerprint != "" {
		res.Fingerprints = map[string]string{"scrutineer/v1": f.Fingerprint}
	}
	if f.Status == db.FindingRejected || f.Status == db.FindingDuplicate {
		res.Suppressions = []sarif.Suppression{{Kind: "external", State: "accepted", Justification: string(f.Status)}}
	}

	// Audit evidence is the candidate's own argument. Verification is the
	// separate verify skill outcome, so a finding no verify run has graded
	// says so explicitly.
	verification := map[string]any{statusKey: "unverified"}
	if v, ok := verifications[f.ID]; ok {
		verification = map[string]any{statusKey: v.Status, "verify_scan_id": v.ScanID}
		if v.Score != nil {
			verification["score"] = *v.Score
		}
	}
	evidence := withoutEmpty(map[string]any{
		"trace": f.Trace, "boundary": f.Boundary, "validation": f.Validation,
		"prior_art": f.PriorArt, "reach": f.Reach, "rating": f.Rating,
	})
	props := withoutEmpty(map[string]any{
		"finding_id": f.FindingID, "first_seen_commit": f.Commit, "sub_path": f.SubPath,
		"vid": f.VID, "model": f.Model, "imported_from": f.ImportedFrom, "severity": f.Severity,
		"confidence": f.Confidence, "cwe": f.CWE, "reachability": f.Reachability, "quality_tier": f.QualityTier,
	})
	props["id"] = f.ID
	props[statusKey] = string(f.Status)
	props["verification"] = verification
	if len(evidence) > 0 {
		props["evidence"] = evidence
	}
	res.Properties = sarif.PropertyBag{"scrutineer": props}
	return res
}

func withoutEmpty(m map[string]any) map[string]any {
	maps.DeleteFunc(m, func(_ string, v any) bool { return v == "" })
	return m
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "low":
		return "note"
	}
	return "warning"
}

// sarifLocation rebases a finding location onto the repository root. It
// reports false for locations that do not name a repository file.
func sarifLocation(subPath, location string) (sarif.Location, bool) {
	p := findingnorm.FindingPath(subPath, location)
	if p == "" {
		return sarif.Location{}, false
	}
	artifact := sarif.NewArtifactLocation()
	artifact.URI = (&url.URL{Path: p}).String()
	loc := sarif.NewLocation()
	loc.PhysicalLocation = sarif.PhysicalLocation{ArtifactLocation: artifact, Region: sarifRegion(location)}
	return loc, true
}

func sarifRegion(location string) sarif.Region {
	m := locRE.FindStringSubmatch(strings.TrimSpace(location))
	if m == nil {
		return sarif.Region{}
	}
	startLine, endLine, _ := strings.Cut(m[2], "-")
	start, _ := strconv.Atoi(startLine)
	if start < 1 {
		return sarif.Region{}
	}
	region := sarif.NewRegion()
	region.StartLine = start
	if end, _ := strconv.Atoi(endLine); end > start {
		region.EndLine = end
	}
	if column, _ := strconv.Atoi(m[3]); column > 0 {
		region.StartColumn = column
	}
	return region
}
