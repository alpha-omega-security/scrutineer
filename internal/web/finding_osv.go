package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"scrutineer/internal/db"
)

//go:embed osv_schemas/*.json
var osvSchemaFS embed.FS

const (
	// osvSchemaURL is the schema's own $id; the compiler registers the
	// embedded document under it and compiles that URL, the same shape the
	// CSAF exporter uses. The schema is self-contained (only internal
	// #/$defs refs), so no companion files are needed.
	osvSchemaURL     = "https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json"
	osvSchemaVersion = "1.7.5"

	// osvIDPrefix anchors the record id. Scrutineer is not a registered OSV
	// home database, so the schema's #/$defs/prefix pattern only admits it
	// via the x_ experimental escape; a bare "scrutineer-..." id would fail
	// validation. The upstream CVE/GHSA, when known, goes in aliases.
	osvIDPrefix = "x_scrutineer-finding-"
)

var (
	osvSchemaOnce sync.Once
	osvSchemaVal  *jsonschema.Schema
	osvSchemaErr  error
)

// getOSVSchema returns the compiled validator, building it on first call.
func getOSVSchema() (*jsonschema.Schema, error) {
	osvSchemaOnce.Do(func() {
		b, err := osvSchemaFS.ReadFile("osv_schemas/osv_schema.json")
		if err != nil {
			osvSchemaErr = fmt.Errorf("read osv_schema.json: %w", err)
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			osvSchemaErr = fmt.Errorf("parse osv_schema.json: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(osvSchemaURL, doc); err != nil {
			osvSchemaErr = fmt.Errorf("add osv_schema.json: %w", err)
			return
		}
		osvSchemaVal, osvSchemaErr = c.Compile(osvSchemaURL)
	})
	return osvSchemaVal, osvSchemaErr
}

func (s *Server) findingOSV(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var f db.Finding
	if err := s.DB.First(&f, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if f.Status == db.FindingDuplicate {
		http.Error(w, "finding is a duplicate; export not available", http.StatusGone)
		return
	}
	schema, err := getOSVSchema()
	if err != nil {
		s.Log.Error("osv schema", "err", err)
		http.Error(w, "failed to load OSV schema", http.StatusInternalServerError)
		return
	}
	var repo db.Repository
	s.DB.First(&repo, f.RepositoryID)
	var refs []db.FindingReference
	s.DB.Where("finding_id = ?", f.ID).Order("id desc").Find(&refs)
	var pkgs []db.Package
	s.DB.Select("name, ecosystem, p_url").Where("repository_id = ?", f.RepositoryID).Find(&pkgs)

	raw, err := json.MarshalIndent(buildOSV(f, repo, refs, pkgs), "", "  ")
	if err != nil {
		s.Log.Error("osv marshal", "finding", f.ID, "err", err)
		http.Error(w, "failed to generate OSV document", http.StatusInternalServerError)
		return
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		s.Log.Error("osv reparse", "finding", f.ID, "err", err)
		http.Error(w, "failed to generate OSV document", http.StatusInternalServerError)
		return
	}
	if err := schema.Validate(inst); err != nil {
		s.Log.Error("osv invalid", "finding", f.ID, "err", err)
		http.Error(w, "failed to generate valid OSV document", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("scrutineer-finding-%d-osv-%s.json", f.ID, time.Now().UTC().Format("20060102"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write(raw)
}

type osvRecord struct {
	SchemaVersion    string         `json:"schema_version,omitempty"`
	ID               string         `json:"id"`
	Modified         string         `json:"modified"`
	Published        string         `json:"published,omitempty"`
	Withdrawn        string         `json:"withdrawn,omitempty"`
	Aliases          []string       `json:"aliases,omitempty"`
	Related          []string       `json:"related,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	Severity         []osvSeverity  `json:"severity,omitempty"`
	Affected         []osvAffected  `json:"affected,omitempty"`
	References       []osvReference `json:"references,omitempty"`
	Credits          []osvCredit    `json:"credits,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// osvCredit is the credits entry: who reported the finding (FINDER) and
// who coordinated disclosure (COORDINATOR). The schema's credit_type
// enum is broader (FINDER, REPORTER, ANALYST, COORDINATOR, REMEDIATION_*,
// SPONSOR, OTHER); these two are what scrutineer can fill from the
// finding row plus the operator configuration.
type osvCredit struct {
	Name    string   `json:"name"`
	Type    string   `json:"type,omitempty"`
	Contact []string `json:"contact,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package           *osvPackage    `json:"package,omitempty"`
	Ranges            []osvRange     `json:"ranges,omitempty"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]any `json:"database_specific,omitempty"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Repo   string     `json:"repo,omitempty"`
	Events []osvEvent `json:"events"`
}

// osvEvent carries exactly one of introduced/fixed: the schema's events items
// are a oneOf of single-key objects, so both fields take omitempty.
type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func buildOSV(f db.Finding, repo db.Repository, refs []db.FindingReference, pkgs []db.Package) osvRecord {
	modified := time.Now().UTC().Format(time.RFC3339)
	if !f.UpdatedAt.IsZero() {
		modified = f.UpdatedAt.UTC().Format(time.RFC3339)
	}
	rec := osvRecord{
		SchemaVersion:    osvSchemaVersion,
		ID:               osvIDPrefix + strconv.Itoa(int(f.ID)),
		Modified:         modified,
		Summary:          f.Title,
		Details:          f.Trace,
		Aliases:          osvAliases(f, refs),
		Related:          osvRelated(refs),
		Severity:         osvSeverityList(f),
		Affected:         osvAffectedList(f, repo, pkgs),
		References:       osvReferences(f, repo, refs),
		Credits:          osvCredits(f),
		DatabaseSpecific: osvDatabaseSpecific(f),
	}
	if !f.CreatedAt.IsZero() {
		rec.Published = f.CreatedAt.UTC().Format(time.RFC3339)
	}
	// `withdrawn` is set when a finding is rejected: the OSV record
	// stays available so consumers can see the history, but it carries
	// the withdrawn timestamp so anyone caching the advisory drops it.
	if f.Status == db.FindingRejected && !f.UpdatedAt.IsZero() {
		rec.Withdrawn = f.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return rec
}

// osvRelated returns the OSV ids the finding carries via FindingReference
// rows. Anything tagged `related` is verbatim; CVE and GHSA references
// fall in as well, since OSV consumers prefer those identifiers in the
// related list rather than as plain web URLs. The list is deduped and
// keeps insertion order so re-exports stay stable.
func osvRelated(refs []db.FindingReference) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, r := range refs {
		tags := strings.ToLower(r.Tags)
		if strings.Contains(tags, "related") {
			add(strings.TrimSpace(r.Summary))
			continue
		}
		// GHSA / CVE shaped URLs surface as related when the tag does
		// not explicitly mark them as the primary alias.
		add(ghsaRE.FindString(r.URL))
		add(ghsaRE.FindString(r.Summary))
	}
	return out
}

// osvCredits emits the FINDER (when the finding's prior_art names a
// researcher) and the COORDINATOR (scrutineer's host operator).
// Schema requires `name`; everything else is optional and only set when
// it can be filled honestly.
func osvCredits(f db.Finding) []osvCredit {
	var out []osvCredit
	if name := strings.TrimSpace(f.Assignee); name != "" {
		out = append(out, osvCredit{Name: name, Type: "ANALYST"})
	}
	out = append(out, osvCredit{
		Name: "scrutineer",
		Type: "COORDINATOR",
		Contact: []string{
			"https://github.com/alpha-omega-security/scrutineer",
		},
	})
	return out
}

var ghsaRE = regexp.MustCompile(`(?i)GHSA(-[0-9a-z]{4}){3}`)

// gitSHARE matches the full commit hashes a GIT range event accepts (the
// schema constrains introduced/fixed to ^(0|[a-f0-9]{40}|[a-f0-9]{64})$). A
// short or non-SHA FixCommit is dropped from the range rather than 500ing the
// export; it still surfaces in the references and database_specific.
var gitSHARE = regexp.MustCompile(`^([a-f0-9]{40}|[a-f0-9]{64})$`)

// osvAliases collects upstream identifiers: the finding's CVE and GHSA id plus
// any GHSA id found in a reference URL or summary. De-duplicated, CVE first.
func osvAliases(f db.Finding, refs []db.FindingReference) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	add(f.CVEID)
	add(f.GHSAID)
	for _, r := range refs {
		add(ghsaRE.FindString(r.URL))
		add(ghsaRE.FindString(r.Summary))
	}
	return out
}

// osvSeverityList emits one CVSS vector entry per version the finding
// carries (OSV's severity.score is the vector, not a number). Each
// entry is gated on go-cvss parsing the vector so a malformed value is
// dropped rather than failing schema validation. When both are
// present, v4 comes first (matching the OSS-SIRT advisory template).
func osvSeverityList(f db.Finding) []osvSeverity {
	var out []osvSeverity
	if _, ok := db.ScoreFromV4Vector(f.CVSSv4Vector); ok {
		out = append(out, osvSeverity{Type: "CVSS_V4", Score: f.CVSSv4Vector})
	}
	if _, ok := db.BaseScoreFromVector(f.CVSSVector); ok {
		out = append(out, osvSeverity{Type: "CVSS_V3", Score: f.CVSSVector})
	}
	return out
}

// osvEcosystemByPURLType maps a canonical PURL type to its OSV ecosystem name.
// It mirrors git-pkgs' osvEcosystemNames but (a) carries the ok flag the
// library's EcosystemToOSV lacks -- that helper returns its input unchanged on
// a miss, which would then fail the schema's ecosystem pattern -- and (b) omits
// entries the embedded schema does not list (e.g. cocoapods), so a lookup miss
// always routes the finding to a GIT range instead of an invalid package.
var osvEcosystemByPURLType = map[string]string{
	"gem":           "RubyGems",
	"npm":           "npm",
	"pypi":          "PyPI",
	"cargo":         "crates.io",
	"golang":        "Go",
	"maven":         "Maven",
	"nuget":         "NuGet",
	"composer":      "Packagist",
	"hex":           "Hex",
	"pub":           "Pub",
	"githubactions": "GitHub Actions",
}

func osvEcosystem(pkg db.Package) (string, bool) {
	p, err := purl.Parse(pkg.PURL)
	if err != nil {
		return "", false
	}
	eco, ok := osvEcosystemByPURLType[p.Type]
	return eco, ok
}

// osvAffectedList anchors the finding. Registry packages whose ecosystem the
// schema recognises become package entries; otherwise the finding is anchored
// to the source repo via a GIT range. A local (file://) repo has no cloneable
// URL, so affected is left empty and the code location lives in
// database_specific instead.
func osvAffectedList(f db.Finding, repo db.Repository, pkgs []db.Package) []osvAffected {
	var out []osvAffected
	for _, pkg := range pkgs {
		eco, ok := osvEcosystem(pkg)
		if !ok {
			continue
		}
		entry := osvAffected{
			Package: &osvPackage{Ecosystem: eco, Name: firstNonEmpty(pkg.Name, "unknown"), PURL: pkg.PURL},
		}
		// A package-scoped affected entry pairs with a SEMVER range when
		// the finding has a fix_version that parses as a single anchor.
		// SIRT's intake template expects this shape; without it,
		// downstream tooling cannot tell which version the consumer
		// should upgrade to.
		if r, ok := osvSemverRangeFromFix(f.FixVersion); ok {
			entry.Ranges = []osvRange{r}
		}
		out = append(out, entry)
	}
	if len(out) > 0 {
		return out
	}
	if repo.URL == "" || repo.IsLocal() {
		return nil
	}
	events := []osvEvent{{Introduced: "0"}}
	if gitSHARE.MatchString(f.FixCommit) {
		events = append(events, osvEvent{Fixed: f.FixCommit})
	}
	return []osvAffected{{
		Ranges: []osvRange{{Type: "GIT", Repo: repo.URL, Events: events}},
	}}
}

// osvSemverRangeFromFix turns a `fix_version` like "1.6.3" (with or
// without a leading "v") into a SEMVER range pinned at introduced=0
// and fixed=<that version>. The intent is to give downstream tooling
// a concrete version to compare against; the introduced=0 sentinel
// matches the convention OSV consumers use when the introduced
// version is unknown. Returns ok=false when fix_version is empty or
// not a clean dotted version, so the caller can omit the range
// cleanly rather than emit something that fails schema validation.
func osvSemverRangeFromFix(fix string) (osvRange, bool) {
	v := strings.TrimSpace(fix)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return osvRange{}, false
	}
	if !semverLooseRE.MatchString(v) {
		return osvRange{}, false
	}
	return osvRange{
		Type: "SEMVER",
		Events: []osvEvent{
			{Introduced: "0"},
			{Fixed: v},
		},
	}, true
}

var semverLooseRE = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$`)

func osvReferences(f db.Finding, repo db.Repository, refs []db.FindingReference) []osvReference {
	var out []osvReference
	for _, r := range refs {
		if r.URL == "" {
			continue
		}
		out = append(out, osvReference{Type: osvReferenceType(r.Tags), URL: r.URL})
	}
	if repo.HTMLURL != "" && f.FixCommit != "" {
		out = append(out, osvReference{Type: "FIX", URL: strings.TrimSuffix(repo.HTMLURL, "/") + "/commit/" + f.FixCommit})
	}
	return out
}

// osvReferenceType maps a finding reference's comma-joined tags to one of OSV's
// reference type enum values, defaulting to WEB.
func osvReferenceType(tags string) string {
	for tag := range strings.SplitSeq(tags, ",") {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "advisory", "ghsa", "cve":
			return "ADVISORY"
		case "patch", "fix", "pr":
			return "FIX"
		case "issue":
			return "REPORT"
		case "discussion":
			return "DISCUSSION"
		case "article", "blog":
			return "ARTICLE"
		}
	}
	return "WEB"
}

// osvDatabaseSpecific carries scrutineer's code-anchored context that OSV's
// package-oriented fields cannot express: the file/line location and the audit
// metadata. Always non-empty (id and status are always set), so the block is
// always emitted.
func osvDatabaseSpecific(f db.Finding) map[string]any {
	ds := map[string]any{
		"scrutineer_finding_id": f.ID,
		// Coordinator-facing identifier: the SIRT advisory template
		// expects a tracking_id key for cross-system reference, and
		// scrutineer's finding id is the natural value.
		"tracking_id": fmt.Sprintf("scrutineer-finding-%d", f.ID),
		"status":      string(f.Status),
	}
	put := func(k, v string) {
		if v != "" {
			ds[k] = v
		}
	}
	put("finding_id", f.FindingID)
	put("severity", f.Severity)
	put("confidence", f.Confidence)
	put("reachability", f.Reachability)
	put("quality_tier", f.QualityTier)
	put("location", f.Location)
	put("commit", f.Commit)
	put("sub_path", f.SubPath)
	put("exploited_in_wild", f.ExploitedInWild)
	put("exploited_in_wild_evidence", f.ExploitedInWildEvidence)
	// `cwe_ids` is the OSV-spec / SIRT-template idiom (an array of
	// `CWE-N` strings) while `cwe` was scrutineer's older comma-joined
	// scalar; emit both so consumers reading either still find the
	// data, but prefer cwe_ids in the canonical place.
	if ids := osvCWEIDs(f.CWE); len(ids) > 0 {
		ds["cwe_ids"] = ids
	}
	put("cwe", f.CWE)
	if locs := f.LocationList(); len(locs) > 1 {
		ds["locations"] = locs
	}
	return ds
}

// osvCWEIDs splits the finding's comma-joined CWE string into an array
// of normalised `CWE-N` ids, deduped and order-preserved.
func osvCWEIDs(cwe string) []string {
	if strings.TrimSpace(cwe) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, token := range strings.Split(cwe, ",") {
		id := strings.ToUpper(strings.TrimSpace(token))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
