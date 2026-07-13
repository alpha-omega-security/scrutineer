package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const exportPrefix = "/api/v1"

func (s *Server) exportHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repositories/{id}/findings", s.apiExportRepoFindings)
	mux.HandleFunc("GET /repositories", s.apiExportRepositories)
	mux.HandleFunc("GET /findings", s.apiExportFindings)
	mux.HandleFunc("GET /scans", s.apiExportScans)
	mux.HandleFunc("POST /import", s.handleImport)
	// Audit endpoints return instance-wide findings and review aggregates,
	// so they live behind the host-only boundary with the other operator
	// exports rather than under per-scan bearer auth (#454).
	mux.HandleFunc("GET /audit/queue", s.apiAuditQueue)
	mux.HandleFunc("GET /audit/metrics", s.apiAuditMetrics)
	return mux
}

// repositoryExportRow is the selected Repositories-tab projection used by the
// JSONL export. It keeps large blob/cache columns out of the query and computes
// FindingsCount with deepDiveFindingsCountSQL so the value matches the UI
// Findings column.
type repositoryExportRow struct {
	ID                 uint
	URL                string
	Name               string
	FullName           string
	Owner              string
	Languages          string
	Stars              int
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastScanID         *uint
	LastScanKind       string
	LastScanStatus     db.ScanStatus
	LastScanSkillName  string
	LastScanCommit     string
	LastScanCreatedAt  *time.Time
	LastScanFinishedAt *time.Time
	FindingsCount      int
}

// apiExportRepositories streams the Repositories-tab data set as NDJSON for
// local automation. The export includes scalar repository columns and a latest
// scan summary, deliberately omitting metadata, ecosystems caches, and other
// large text blobs.
func (s *Server) apiExportRepositories(w http.ResponseWriter, r *http.Request) {
	if !validateExportFormat(w, r) {
		return
	}
	q := s.DB.Table("repositories").
		Select(`repositories.id,
			repositories.url,
			repositories.name,
			repositories.full_name,
			repositories.owner,
			repositories.languages,
			repositories.stars,
			repositories.created_at,
			repositories.updated_at,
			last_scans.id AS last_scan_id,
			last_scans.kind AS last_scan_kind,
			last_scans.status AS last_scan_status,
			last_scans.skill_name AS last_scan_skill_name,
			last_scans."commit" AS last_scan_commit,
			last_scans.created_at AS last_scan_created_at,
			last_scans.finished_at AS last_scan_finished_at,
			(` + deepDiveFindingsCountSQL + `) AS findings_count`).
		Joins(`LEFT JOIN scans AS last_scans ON last_scans.id = (
			SELECT id FROM scans
			WHERE repository_id = repositories.id
			ORDER BY id DESC
			LIMIT 1
		)`).
		Order("repositories.updated_at desc")
	streamJSONL(w, q, repositoryExport)
}

func (s *Server) apiExportRepoFindings(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "" && format != "jsonl" && format != "bundle" {
		writeAPIError(w, http.StatusBadRequest, "unsupported format: jsonl or bundle")
		return
	}
	// encrypt only applies to the bundle format. Rejecting it here is a
	// safety guard: without it, encrypt=1 on the default (NDJSON) path would
	// be silently ignored and return plaintext — a request that asked for
	// encryption must never get cleartext back.
	if r.URL.Query().Get("encrypt") != "" && format != "bundle" {
		writeAPIError(w, http.StatusBadRequest, "encrypt requires format=bundle")
		return
	}
	// scope=findings curates the bundle to the Findings bucket (deep-dive,
	// vuln-scan, imports), dropping per-repo scanner noise. Like encrypt it only
	// applies to the bundle format; reject it elsewhere rather than silently
	// returning the full set a caller asked to narrow.
	scope := r.URL.Query().Get("scope")
	if scope != "" && scope != "findings" {
		writeAPIError(w, http.StatusBadRequest, "unsupported scope: findings")
		return
	}
	if scope != "" && format != "bundle" {
		writeAPIError(w, http.StatusBadRequest, "scope requires format=bundle")
		return
	}
	// include=all promotes the bundle to the archival superset (the operator's
	// enrichment, disclosure work product, and notes/comms/refs child records).
	// Like encrypt and scope it only applies to the bundle format; reject it
	// elsewhere rather than silently returning the lean default a caller asked
	// to widen.
	include := r.URL.Query().Get("include")
	if include != "" && include != "all" {
		writeAPIError(w, http.StatusBadRequest, "unsupported include: all")
		return
	}
	if include != "" && format != "bundle" {
		writeAPIError(w, http.StatusBadRequest, "include requires format=bundle")
		return
	}

	id, _ := strconv.Atoi(r.PathValue("id"))
	var repo db.Repository
	if err := s.DB.First(&repo, id).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "repository not found")
		return
	}

	if format == "bundle" {
		s.apiExportRepoBundle(w, r, &repo)
		return
	}
	q := s.DB.Model(&db.Finding{}).
		Where("scan_id IN (?)", s.DB.Model(&db.Scan{}).Select("id").Where("repository_id = ?", id)).
		Order("id desc")
	q = applyFindingFilters(q, r)
	streamJSONL(w, q, findingExport)
}

// sharingBundle is the self-contained sharing format that round-trips
// through ingest.Parse (the "minimal" shape). The shareable unit is one
// repository. GeneratedAt records when the bundle was produced (RFC3339
// UTC); it lives inside the encrypted JSON, not in cleartext metadata, and
// the importer ignores it (it is provenance for the human recipient).
type sharingBundle struct {
	Repository  string           `json:"repository"`
	Commit      string           `json:"commit"`
	Tool        string           `json:"tool"`
	GeneratedAt string           `json:"generated_at,omitempty"`
	Findings    []sharingFinding `json:"findings"`
}

// sharingFinding carries the substance of a finding — what was found and the
// reasoning that justifies it (the six-step audit checklist, reachability,
// sink quality, the sink ids, the cross-party VID), plus enough provenance
// (commit, sub-path, all hit locations) to resolve Location unambiguously on
// the receiving side. This default set is share-safe: it is the finding, not
// the analyst's private workspace, so a plain bundle can go to another team.
//
// An include=all export additionally carries the operator's own enrichment and
// disclosure work product — CVSS vectors, affected/fix_version, CVE/GHSA ids,
// mitigation, breaking-change verdict, dup-check, disclosure draft,
// exploited-in-wild, the source Snippet, the real upstream fix commit, and the
// Notes/Communications/References child records — so a repo's findings can be
// round-tripped losslessly into the operator's own instance. It is opt-in
// because notes and communications are internal, and Snippet embeds verbatim
// (possibly private) source, none of which a cross-party share should leak.
//
// Three things never travel, in either mode. Instance-local lifecycle the
// receiver owns (status, resolution, revalidate verdict, assignee) is dropped
// so imports land fresh and untriaged; auto-applying a foreign lifecycle state
// is the real footgun. The change History is provenance of the instance it
// happened on — the import itself is the new provenance. Release-watch columns
// and Labels are re-derivable / low-value and stay out.
//
// UpstreamFixCommit uses a new upstream_fix_commit key: the legacy fix_commit
// key already carries the SuggestedFix base (db.Finding.SuggestedFixCommit).
//
// Every field after Patch — and every child slice — is emitted with omitempty
// so a finding that lacks them, and a bundle produced before they existed,
// stays byte-compatible with the original seven-field shape.
type sharingFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	CWE         string `json:"cwe"`
	Location    string `json:"location"`
	Patch       string `json:"patch"`

	Commit       string `json:"commit,omitempty"`
	SubPath      string `json:"sub_path,omitempty"`
	Locations    string `json:"locations,omitempty"`
	VID          string `json:"vid,omitempty"`
	Reachability string `json:"reachability,omitempty"`
	QualityTier  string `json:"quality_tier,omitempty"`
	Boundary     string `json:"boundary,omitempty"`
	Validation   string `json:"validation,omitempty"`
	PriorArt     string `json:"prior_art,omitempty"`
	Reach        string `json:"reach,omitempty"`
	Rating       string `json:"rating,omitempty"`
	FixCommit    string `json:"fix_commit,omitempty"`

	// Sinks rides the default bundle. Everything below it is populated only for
	// include=all; omitempty keeps a default bundle byte-identical to the
	// pre-archival shape.
	Sinks string `json:"sinks,omitempty"`

	Snippet                 string `json:"snippet,omitempty"`
	Affected                string `json:"affected,omitempty"`
	FixVersion              string `json:"fix_version,omitempty"`
	CVEID                   string `json:"cve_id,omitempty"`
	GHSAID                  string `json:"ghsa_id,omitempty"`
	CVSSVector              string `json:"cvss_vector,omitempty"`
	CVSSv4Vector            string `json:"cvss_v4_vector,omitempty"`
	Mitigation              string `json:"mitigation,omitempty"`
	MitigationSemgrep       string `json:"mitigation_semgrep,omitempty"`
	BreakingChange          string `json:"breaking_change,omitempty"`
	BreakingChangeRationale string `json:"breaking_change_rationale,omitempty"`
	DupCheck                string `json:"dup_check,omitempty"`
	DisclosureDraft         string `json:"disclosure_draft,omitempty"`
	ExploitedInWild         string `json:"exploited_in_wild,omitempty"`
	ExploitedInWildEvidence string `json:"exploited_in_wild_evidence,omitempty"`
	UpstreamFixCommit       string `json:"upstream_fix_commit,omitempty"`

	Notes          []sharingNote          `json:"notes,omitempty"`
	Communications []sharingCommunication `json:"communications,omitempty"`
	References     []sharingReference     `json:"references,omitempty"`
}

// sharingNote, sharingCommunication and sharingReference are the wire shapes of
// a finding's child records in an include=all bundle. They mirror the minimal*
// structs in internal/ingest/minimal.go field-for-field so the round-trip
// through ingest.Parse stays byte-compatible.
type sharingNote struct {
	Body      string    `json:"body"`
	By        string    `json:"by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type sharingCommunication struct {
	Channel     string    `json:"channel,omitempty"`
	Direction   string    `json:"direction,omitempty"`
	Actor       string    `json:"actor,omitempty"`
	Body        string    `json:"body,omitempty"`
	OfferedHelp string    `json:"offered_help,omitempty"`
	At          time.Time `json:"at"`
	CreatedAt   time.Time `json:"created_at"`
}

type sharingReference struct {
	URL       string    `json:"url,omitempty"`
	Tags      string    `json:"tags,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) apiExportRepoBundle(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	encrypt := r.URL.Query().Get("encrypt") != ""
	if encrypt && len(s.EncRecipients) == 0 {
		writeAPIError(w, http.StatusBadRequest, "encryption requested but no recipients configured")
		return
	}

	includeAll := r.URL.Query().Get("include") == "all"

	var findings []db.Finding
	q := s.DB.Where("scan_id IN (?)",
		s.DB.Model(&db.Scan{}).Select("id").Where("repository_id = ?", repo.ID)).
		Order("id desc")
	if r.URL.Query().Get("scope") == "findings" {
		// Curate to the Findings bucket — drop semgrep/zizmor scanner noise,
		// keep deep-dive, vuln-scan, and operator imports (nonScannerScanFilter,
		// the same predicate the Findings tab uses). Validated in
		// apiExportRepoFindings; the default (no scope) shares every finding.
		q = q.Where(nonScannerScanFilter)
	}
	if includeAll {
		// Load the child records only for the archival superset. Ordered so the
		// bundle is deterministic (byte-stable re-exports) and reads in the same
		// chronological order the finding page shows.
		q = q.Preload("Notes", func(tx *gorm.DB) *gorm.DB { return tx.Order("created_at asc, id asc") }).
			Preload("Communications", func(tx *gorm.DB) *gorm.DB { return tx.Order("at asc, id asc") }).
			Preload("References", func(tx *gorm.DB) *gorm.DB { return tx.Order("id asc") })
	}
	q = applyFindingFilters(q, r)
	if err := q.Find(&findings).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	repositoryURL := bundleRepositoryURL(r.Context(), repo)
	if repo.IsLocal() && repositoryURL == repo.URL && s.Log != nil {
		s.Log.Warn("bundle export: local repository has no portable origin; recipient must pass ?repo= on import",
			"repository_id", repo.ID)
	}
	bundle := sharingBundle{
		Repository:  repositoryURL,
		Tool:        "scrutineer",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, f := range findings {
		if bundle.Commit == "" {
			bundle.Commit = f.Commit
		}
		sf := sharingFinding{
			Title:        f.Title,
			Description:  f.Trace,
			Severity:     f.Severity,
			Confidence:   f.Confidence,
			CWE:          f.CWE,
			Location:     f.Location,
			Patch:        f.SuggestedFix,
			Commit:       f.Commit,
			SubPath:      f.SubPath,
			Locations:    f.Locations,
			VID:          f.VID,
			Reachability: f.Reachability,
			QualityTier:  f.QualityTier,
			Boundary:     f.Boundary,
			Validation:   f.Validation,
			PriorArt:     f.PriorArt,
			Reach:        f.Reach,
			Rating:       f.Rating,
			FixCommit:    f.SuggestedFixCommit,
			Sinks:        f.Sinks,
		}
		if includeAll {
			sf.Snippet = f.Snippet
			sf.Affected = f.Affected
			sf.FixVersion = f.FixVersion
			sf.CVEID = f.CVEID
			sf.GHSAID = f.GHSAID
			sf.CVSSVector = f.CVSSVector
			sf.CVSSv4Vector = f.CVSSv4Vector
			sf.Mitigation = f.Mitigation
			sf.MitigationSemgrep = f.MitigationSemgrep
			sf.BreakingChange = f.BreakingChange
			sf.BreakingChangeRationale = f.BreakingChangeRationale
			sf.DupCheck = f.DupCheck
			sf.DisclosureDraft = f.DisclosureDraft
			sf.ExploitedInWild = f.ExploitedInWild
			sf.ExploitedInWildEvidence = f.ExploitedInWildEvidence
			// The real upstream fix commit rides the new key; the legacy
			// fix_commit above carries the SuggestedFix base.
			sf.UpstreamFixCommit = f.FixCommit
			for _, n := range f.Notes {
				sf.Notes = append(sf.Notes, sharingNote{Body: n.Body, By: n.By, CreatedAt: n.CreatedAt})
			}
			for _, c := range f.Communications {
				sf.Communications = append(sf.Communications, sharingCommunication{
					Channel:     c.Channel,
					Direction:   c.Direction,
					Actor:       c.Actor,
					Body:        c.Body,
					OfferedHelp: c.OfferedHelp,
					At:          c.At,
					CreatedAt:   c.CreatedAt,
				})
			}
			for _, ref := range f.References {
				sf.References = append(sf.References, sharingReference{
					URL:       ref.URL,
					Tags:      ref.Tags,
					Summary:   ref.Summary,
					CreatedAt: ref.CreatedAt,
				})
			}
		}
		bundle.Findings = append(bundle.Findings, sf)
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !encrypt {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(data)
		return
	}

	// Encrypt to all configured recipients. The entire bundle is built in
	// memory so we can return a proper error code on failure instead of a
	// truncated body.
	ct, err := encryptBundle(data, s.EncRecipients)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.bundle.age"`)
	_, _ = w.Write(ct)
}

// bundleRepositoryURL returns repository provenance that another scrutineer
// instance can use. A file:// URL only identifies a path on the exporting
// host, so for local checkouts prefer their validated HTTPS origin. The
// receiver then creates a remote Repository row and the normal scan path
// clones it on first use. Repositories without a usable origin retain their
// file URL so callers can still supply ?repo= explicitly on import.
func bundleRepositoryURL(ctx context.Context, repo *db.Repository) string {
	if repo == nil {
		return ""
	}
	if !repo.IsLocal() {
		return repo.URL
	}

	cmd := exec.CommandContext(ctx, "git", "-C", repo.LocalPath(),
		"config", "--local", "--get", "remote.origin.url")
	out, err := cmd.Output()
	if err != nil {
		return repo.URL
	}
	origin, ok := portableGitOrigin(strings.TrimSpace(string(out)))
	if !ok {
		return repo.URL
	}
	return origin
}

// sshConvertibleForges is deliberately separate from caseInsensitiveForges:
// path case-folding does not imply that a host safely maps SSH owner/repo
// remotes onto the same HTTPS path.
var sshConvertibleForges = map[string]bool{
	"github.com":    true,
	"gitlab.com":    true,
	"bitbucket.org": true,
	"codeberg.org":  true,
}

// portableGitOrigin converts a supported git origin into the HTTPS URL the
// importer and worker accept. HTTPS origins are normalized through the same
// parser as repository creation. Common SSH forms are converted only for the
// public forges whose owner/repo URL semantics we already know. Embedded HTTPS
// credentials are rejected so a local credential never enters a bundle.
func portableGitOrigin(origin string) (string, bool) {
	candidate := origin
	if !strings.Contains(origin, "://") {
		userHost, repoPath, ok := strings.Cut(origin, ":")
		if !ok || strings.Contains(userHost, "/") {
			return "", false
		}
		_, host, ok := strings.Cut(userHost, "@")
		host = strings.ToLower(host)
		if !ok || !sshConvertibleForges[host] {
			return "", false
		}
		candidate = "https://" + host + "/" + strings.TrimPrefix(repoPath, "/")
	} else {
		parsed, err := url.Parse(origin)
		if err != nil {
			return "", false
		}
		switch parsed.Scheme {
		case "https":
			if parsed.User != nil {
				return "", false
			}
		case "ssh":
			host := strings.ToLower(parsed.Hostname())
			if !sshConvertibleForges[host] || (parsed.Port() != "" && parsed.Port() != "22") {
				return "", false
			}
			candidate = "https://" + host + "/" + strings.TrimPrefix(parsed.Path, "/")
		default:
			return "", false
		}
	}

	parsed, err := url.Parse(candidate)
	if err != nil || parsed.User != nil {
		return "", false
	}
	input, err := ParseRepoInput(candidate)
	if err != nil || input.Local {
		return "", false
	}
	return input.CloneURL, true
}

// encryptBundle wraps plaintext in armored age for the given recipients.
//
// Confidentiality + integrity only, not sender authentication: a recipient
// can verify the bundle wasn't tampered with, but cannot cryptographically
// prove who produced it.
func encryptBundle(plain []byte, recipients []age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	armorW := armor.NewWriter(&buf)
	aw, err := age.Encrypt(armorW, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(aw, bytes.NewReader(plain)); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	if err := armorW.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) apiExportFindings(w http.ResponseWriter, r *http.Request) {
	if !validateExportFormat(w, r) {
		return
	}
	q := applyFindingFilters(s.DB.Model(&db.Finding{}).Order("id desc"), r)
	streamJSONL(w, q, findingExport)
}

func (s *Server) apiExportScans(w http.ResponseWriter, r *http.Request) {
	if !validateExportFormat(w, r) {
		return
	}
	q := s.DB.Model(&db.Scan{}).Order("id desc")
	if v := r.URL.Query().Get(statusKey); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := r.URL.Query().Get("skill"); v != "" {
		q = q.Where("skill_name = ?", v)
	}
	streamJSONL(w, q, scanExport)
}

// repositoryExport maps a repositoryExportRow to the public JSON object. Repos
// with no scans emit last_scan: null; scanned repos get a compact scan summary.
func repositoryExport(row repositoryExportRow) map[string]any {
	out := map[string]any{
		"id":             row.ID,
		"url":            row.URL,
		"name":           row.Name,
		"full_name":      row.FullName,
		"owner":          row.Owner,
		"languages":      row.Languages,
		"stars":          row.Stars,
		"findings_count": row.FindingsCount,
		"created_at":     row.CreatedAt,
		"updated_at":     row.UpdatedAt,
	}
	if row.LastScanID == nil {
		out["last_scan"] = nil
		return out
	}
	out["last_scan"] = map[string]any{
		"id":          *row.LastScanID,
		"kind":        row.LastScanKind,
		statusKey:     string(row.LastScanStatus),
		"skill_name":  row.LastScanSkillName,
		"commit":      row.LastScanCommit,
		"created_at":  row.LastScanCreatedAt,
		"finished_at": row.LastScanFinishedAt,
	}
	return out
}

func validateExportFormat(w http.ResponseWriter, r *http.Request) bool {
	if v := r.URL.Query().Get("format"); v != "" && v != "jsonl" {
		writeAPIError(w, http.StatusBadRequest, "unsupported format: only jsonl")
		return false
	}
	// encrypt is only meaningful for per-repository bundle exports. Rejecting
	// it here stops a request that asked for encryption from silently
	// streaming plaintext NDJSON off these endpoints.
	if r.URL.Query().Get("encrypt") != "" {
		writeAPIError(w, http.StatusBadRequest, "encrypt is only supported on per-repository bundle exports")
		return false
	}
	// scope curates the per-repository bundle and has no meaning on these
	// cross-repo NDJSON dumps; reject it rather than silently ignore it.
	if r.URL.Query().Get("scope") != "" {
		writeAPIError(w, http.StatusBadRequest, "scope is only supported on per-repository bundle exports")
		return false
	}
	// include selects the archival bundle superset; likewise bundle-only.
	if r.URL.Query().Get("include") != "" {
		writeAPIError(w, http.StatusBadRequest, "include is only supported on per-repository bundle exports")
		return false
	}
	return true
}

func applyFindingFilters(q *gorm.DB, r *http.Request) *gorm.DB {
	if v := r.URL.Query().Get("severity"); v != "" {
		q = q.Where("severity = ?", v)
	}
	if v := r.URL.Query().Get(statusKey); v != "" {
		q = q.Where("status = ?", v)
	}
	return q
}

// streamJSONL iterates rows incrementally so a million-row export never
// preloads into memory. The body is partial on mid-stream errors: once
// we have committed to 200, a truncated stream is the only honest signal.
func streamJSONL[T any](w http.ResponseWriter, q *gorm.DB, project func(T) map[string]any) {
	rows, err := q.Rows()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	enc := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)
	for rows.Next() {
		var item T
		if err := q.ScanRows(rows, &item); err != nil {
			return
		}
		if err := enc.Encode(project(item)); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// findingExport mirrors every db.Finding column. Relations (labels, notes,
// ...) are exposed via dedicated endpoints, not inlined here.
func findingExport(f db.Finding) map[string]any {
	return map[string]any{
		"id":                  f.ID,
		"scan_id":             f.ScanID,
		"repository_id":       f.RepositoryID,
		"commit":              f.Commit,
		"sub_path":            f.SubPath,
		"fingerprint":         f.Fingerprint,
		"last_seen_scan_id":   f.LastSeenScanID,
		"last_seen_commit":    f.LastSeenCommit,
		"seen_count":          f.SeenCount,
		"missed_count":        f.MissedCount,
		"last_missed_scan_id": f.LastMissedScanID,
		"finding_id":          f.FindingID,
		"sinks":               f.Sinks,
		"title":               f.Title,
		"severity":            f.Severity,
		statusKey:             string(f.Status),
		"cwe":                 f.CWE,
		"location":            f.Location,
		"vid":                 f.VID,
		"affected":            f.Affected,
		"reachability":        f.Reachability,
		"quality_tier":        f.QualityTier,
		"cve_id":              f.CVEID,
		"ghsa_id":             f.GHSAID,
		"cvss_vector":         f.CVSSVector,
		"cvss_score":          f.CVSSScore,
		"fix_version":         f.FixVersion,
		"fix_commit":          f.FixCommit,
		"resolution":          string(f.Resolution),
		"disclosure_draft":    f.DisclosureDraft,
		"assignee":            f.Assignee,
		"trace":               f.Trace,
		"boundary":            f.Boundary,
		"validation":          f.Validation,
		"prior_art":           f.PriorArt,
		"reach":               f.Reach,
		"rating":              f.Rating,
		"created_at":          f.CreatedAt,
		"updated_at":          f.UpdatedAt,
	}
}

// scanExport mirrors db.Scan's columns minus APIToken: the bearer is the
// running scan's auth credential and must never leak through an
// unauthenticated channel.
func scanExport(sc db.Scan) map[string]any {
	out := map[string]any{
		"id":                 sc.ID,
		"repository_id":      sc.RepositoryID,
		"kind":               sc.Kind,
		statusKey:            string(sc.Status),
		"model":              sc.Model,
		"skill_id":           sc.SkillID,
		"skill_version":      sc.SkillVersion,
		"skill_name":         sc.SkillName,
		"finding_id":         sc.FindingID,
		"sub_path":           sc.SubPath,
		"commit":             sc.Commit,
		"started_at":         sc.StartedAt,
		"finished_at":        sc.FinishedAt,
		"cost_usd":           sc.CostUSD,
		"turns":              sc.Turns,
		"input_tokens":       sc.InputTokens,
		"output_tokens":      sc.OutputTokens,
		"cache_read_tokens":  sc.CacheReadTokens,
		"cache_write_tokens": sc.CacheWriteTokens,
		"max_turns_hit":      sc.MaxTurnsHit,
		"prompt":             sc.Prompt,
		"report":             sc.Report,
		"log":                sc.Log,
		errorKey:             sc.Error,
		"findings_count":     sc.FindingsCount,
		"created_at":         sc.CreatedAt,
		"updated_at":         sc.UpdatedAt,
	}
	out["refusal_audit"] = sc.RefusalAudit
	out["refusal_audit_warning"] = sc.RefusalAuditWarning
	return out
}
