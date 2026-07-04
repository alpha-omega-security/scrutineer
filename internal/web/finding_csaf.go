package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"scrutineer/internal/db"
)

//go:embed csaf_schemas/*.json
var csafSchemaFS embed.FS

const (
	csafStatusFixed              = "fixed"
	csafStatusKnownAffected      = "known_affected"
	csafStatusKnownNotAffected   = "known_not_affected"
	csafStatusUnderInvestigation = "under_investigation"

	csafSeverityCritical = "CRITICAL"
	csafSeverityHigh     = "HIGH"
	csafSeverityMedium   = "MEDIUM"
	csafSeverityLow      = "LOW"
	csafSeverityNone     = "NONE"

	cvssVersion30 = "3.0"
	cvssVersion31 = "3.1"
)

// CVSS v3 base-score severity bands, per the FIRST CVSS specification.
const (
	cvssCriticalScore = 9.0
	cvssHighScore     = 7.0
	cvssMediumScore   = 4.0
)

var (
	csafSchemaOnce sync.Once
	csafSchemaVal  *jsonschema.Schema
	csafSchemaErr  error
)

// getCSAFSchema returns the compiled validator, building it on first call.
func getCSAFSchema() (*jsonschema.Schema, error) {
	csafSchemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		files := []struct{ url, file string }{
			{"https://www.first.org/cvss/cvss-v2.0.json", "cvss-v2.0.json"},
			{"https://www.first.org/cvss/cvss-v3.0.json", "cvss-v3.0.json"},
			{"https://www.first.org/cvss/cvss-v3.1.json", "cvss-v3.1.json"},
			{"https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", "csaf_json_schema.json"},
		}
		for _, f := range files {
			b, err := csafSchemaFS.ReadFile("csaf_schemas/" + f.file)
			if err != nil {
				csafSchemaErr = fmt.Errorf("read %s: %w", f.file, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				csafSchemaErr = fmt.Errorf("parse %s: %w", f.file, err)
				return
			}
			if err := c.AddResource(f.url, doc); err != nil {
				csafSchemaErr = fmt.Errorf("add %s: %w", f.file, err)
				return
			}
		}
		csafSchemaVal, csafSchemaErr = c.Compile("https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json")
	})
	return csafSchemaVal, csafSchemaErr
}

func (s *Server) findingCSAF(w http.ResponseWriter, r *http.Request) {
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
	var dependentCount int64
	s.DB.Model(&db.Dependent{}).Where("repository_id = ?", f.RepositoryID).Count(&dependentCount)
	if dependentCount == 0 {
		http.Error(w, "CSAF VEX export is unavailable because this repository has no recorded dependents", http.StatusNotFound)
		return
	}
	schema, err := getCSAFSchema()
	if err != nil {
		s.Log.Error("csaf schema", "err", err)
		http.Error(w, "failed to load CSAF schema", http.StatusInternalServerError)
		return
	}
	var repo db.Repository
	s.DB.First(&repo, f.RepositoryID)
	var refs []db.FindingReference
	s.DB.Where("finding_id = ?", f.ID).Order("id desc").Find(&refs)
	var pkgs []db.Package
	s.DB.Where("repository_id = ?", f.RepositoryID).Find(&pkgs)
	var fdRows []db.FindingDependent
	s.DB.Where("finding_id = ?", f.ID).Find(&fdRows)
	deps := loadFindingDependents(s, fdRows)

	raw, err := json.MarshalIndent(buildCSAF(f, repo, refs, pkgs, fdRows, deps), "", "  ")
	if err != nil {
		s.Log.Error("csaf marshal", "finding", f.ID, "err", err)
		http.Error(w, "failed to generate CSAF document", http.StatusInternalServerError)
		return
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		s.Log.Error("csaf reparse", "finding", f.ID, "err", err)
		http.Error(w, "failed to generate CSAF document", http.StatusInternalServerError)
		return
	}
	if err := schema.Validate(inst); err != nil {
		s.Log.Error("csaf invalid", "finding", f.ID, "err", err)
		http.Error(w, "failed to generate valid CSAF document", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("scrutineer-finding-%d-%s.json", f.ID, time.Now().UTC().Format("20060102"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write(raw)
}

type csafDocument struct {
	Document        csafDocMeta         `json:"document"`
	ProductTree     *csafProductTree    `json:"product_tree,omitempty"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities,omitempty"`
}

type csafDocMeta struct {
	Category     string          `json:"category"`
	CSAFVersion  string          `json:"csaf_version"`
	Title        string          `json:"title"`
	Distribution csafDistrib     `json:"distribution"`
	Publisher    csafPublisher   `json:"publisher"`
	Tracking     csafTracking    `json:"tracking"`
	Notes        []csafNote      `json:"notes,omitempty"`
	References   []csafReference `json:"references,omitempty"`
}

type csafDistrib struct {
	TLP csafTLP `json:"tlp"`
}

type csafTLP struct {
	Label string `json:"label"`
}

type csafPublisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type csafTracking struct {
	ID                 string         `json:"id"`
	InitialReleaseDate string         `json:"initial_release_date"`
	CurrentReleaseDate string         `json:"current_release_date"`
	Status             string         `json:"status"`
	Version            string         `json:"version"`
	RevisionHistory    []csafRevision `json:"revision_history"`
	Generator          *csafGenerator `json:"generator,omitempty"`
}

type csafRevision struct {
	Number  string `json:"number"`
	Date    string `json:"date"`
	Summary string `json:"summary"`
}

type csafGenerator struct {
	Engine csafEngine `json:"engine"`
}

type csafEngine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type csafProductTree struct {
	Branches []csafBranch `json:"branches,omitempty"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []csafBranch `json:"branches,omitempty"`
	Product  *csafProduct `json:"product,omitempty"`
}

type csafProduct struct {
	Name        string                 `json:"name"`
	ProductID   string                 `json:"product_id"`
	IdentHelper *csafProductIdentifier `json:"product_identification_helper,omitempty"`
}

type csafProductIdentifier struct {
	PURL string `json:"purl,omitempty"`
}

type csafVulnerability struct {
	CVE           string             `json:"cve,omitempty"`
	CWE           *csafCWE           `json:"cwe,omitempty"`
	Title         string             `json:"title,omitempty"`
	Notes         []csafNote         `json:"notes,omitempty"`
	ProductStatus *csafProductStatus `json:"product_status,omitempty"`
	Flags         []csafFlag         `json:"flags,omitempty"`
	Scores        []csafScore        `json:"scores,omitempty"`
	Remediations  []csafRemediation  `json:"remediations,omitempty"`
	References    []csafReference    `json:"references,omitempty"`
}

type csafFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type csafCWE struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type csafNote struct {
	Category string `json:"category"`
	Title    string `json:"title,omitempty"`
	Text     string `json:"text"`
}

type csafProductStatus struct {
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

type csafScore struct {
	Products []string    `json:"products"`
	CVSSv3   *csafCVSSv3 `json:"cvss_v3,omitempty"`
}

type csafCVSSv3 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	AttackVector          string  `json:"attackVector,omitempty"`
	AttackComplexity      string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
	UserInteraction       string  `json:"userInteraction,omitempty"`
	Scope                 string  `json:"scope,omitempty"`
	ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
}

type csafRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
	URL        string   `json:"url,omitempty"`
}

type csafReference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

// loadFindingDependents fetches the Dependent rows referenced by the
// given exposure rows, keyed by ID for cheap lookup in buildCSAF.
func loadFindingDependents(s *Server, rows []db.FindingDependent) map[uint]db.Dependent {
	if len(rows) == 0 {
		return nil
	}
	ids := make([]uint, len(rows))
	for i, r := range rows {
		ids[i] = r.DependentID
	}
	var deps []db.Dependent
	s.DB.Where("id IN ?", ids).Find(&deps)
	out := make(map[uint]db.Dependent, len(deps))
	for _, d := range deps {
		out[d.ID] = d
	}
	return out
}

func dependentProductID(d db.Dependent) string {
	return fmt.Sprintf("DEP-%d", d.ID)
}

func buildCSAF(f db.Finding, repo db.Repository, refs []db.FindingReference, pkgs []db.Package, fdRows []db.FindingDependent, deps map[uint]db.Dependent) csafDocument {
	productID := fmt.Sprintf("PKG-%d-%s", f.RepositoryID, csafProductSuffix(f))

	now := time.Now().UTC().Format(time.RFC3339)
	initial := now
	if !f.CreatedAt.IsZero() {
		initial = f.CreatedAt.UTC().Format(time.RFC3339)
	}
	current := initial
	if !f.UpdatedAt.IsZero() {
		current = f.UpdatedAt.UTC().Format(time.RFC3339)
	}

	docStatus := "draft"
	if f.Status == db.FindingPublished {
		docStatus = "final"
	}

	doc := csafDocument{
		Document: csafDocMeta{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Title:       fmt.Sprintf("Scrutineer VEX: %s", firstNonEmpty(f.Title, "finding "+strconv.Itoa(int(f.ID)))),
			Distribution: csafDistrib{
				TLP: csafTLP{Label: "WHITE"},
			},
			Publisher: csafPublisher{
				Category:  "discoverer",
				Name:      "Scrutineer",
				Namespace: "https://github.com/alpha-omega-security/scrutineer",
			},
			Tracking: csafTracking{
				ID:                 fmt.Sprintf("scrutineer-finding-%d", f.ID),
				InitialReleaseDate: initial,
				CurrentReleaseDate: current,
				Status:             docStatus,
				Version:            "1",
				RevisionHistory: []csafRevision{
					{Number: "1", Date: initial, Summary: "initial export"},
				},
				Generator: &csafGenerator{
					Engine: csafEngine{Name: "scrutineer", Version: "0"},
				},
			},
		},
	}

	productName := firstNonEmpty(repo.FullName, repo.Name, "package")
	productVersion := firstNonEmpty(f.Affected, "unknown")
	doc.ProductTree = buildProductTree(productName, productVersion, productID, pkgs, fdRows, deps)

	productIDs := []string{productID}
	for _, pkg := range pkgs {
		if pkg.PURL != "" {
			productIDs = append(productIDs, pkgProductID(pkg))
		}
	}

	v := csafVulnerability{
		CVE:           f.CVEID,
		Title:         f.Title,
		ProductStatus: buildProductStatusMulti(f, productIDs, fdRows, deps),
		References:    buildReferences(refs),
		Notes:         buildAuditNotes(f),
		Flags:         buildFlags(f, productIDs, fdRows, deps),
	}
	if cwe := buildCWE(f.CWE); cwe != nil {
		v.CWE = cwe
	}
	if score := buildScoreMulti(f, productIDs); score != nil {
		v.Scores = []csafScore{*score}
	}
	if rem := buildRemediationsMulti(f, repo, productIDs); len(rem) > 0 {
		v.Remediations = rem
	}
	doc.Vulnerabilities = []csafVulnerability{v}

	return doc
}

func pkgProductID(pkg db.Package) string {
	return fmt.Sprintf("PKG-%d-%s-%s", pkg.RepositoryID, pkg.Ecosystem, pkg.Name)
}

func buildProductTree(productName, productVersion, baseProductID string, pkgs []db.Package, fdRows []db.FindingDependent, deps map[uint]db.Dependent) *csafProductTree {
	baseProduct := csafBranch{
		Category: "product_version",
		Name:     productVersion,
		Product: &csafProduct{
			Name:      fmt.Sprintf("%s %s", productName, productVersion),
			ProductID: baseProductID,
		},
	}
	versionBranches := []csafBranch{baseProduct}
	for _, pkg := range pkgs {
		if pkg.PURL == "" {
			continue
		}
		versionBranches = append(versionBranches, csafBranch{
			Category: "product_version",
			Name:     productVersion,
			Product: &csafProduct{
				Name:      fmt.Sprintf("%s %s", pkg.Name, productVersion),
				ProductID: pkgProductID(pkg),
				IdentHelper: &csafProductIdentifier{
					PURL: pkg.PURL,
				},
			},
		})
	}
	branches := []csafBranch{{
		Category: "product_name",
		Name:     productName,
		Branches: versionBranches,
	}}
	for _, r := range fdRows {
		dep, ok := deps[r.DependentID]
		if !ok {
			continue
		}
		name := firstNonEmpty(dep.Name, fmt.Sprintf("dependent-%d", dep.ID))
		ver := firstNonEmpty(dep.LatestVersion, "unknown")
		var ident *csafProductIdentifier
		if dep.PURL != "" {
			ident = &csafProductIdentifier{PURL: dep.PURL}
		}
		branches = append(branches, csafBranch{
			Category: "product_name",
			Name:     name,
			Branches: []csafBranch{{
				Category: "product_version",
				Name:     ver,
				Product: &csafProduct{
					Name:        fmt.Sprintf("%s %s", name, ver),
					ProductID:   dependentProductID(dep),
					IdentHelper: ident,
				},
			}},
		})
	}
	return &csafProductTree{Branches: branches}
}

func buildFlags(f db.Finding, productIDs []string, fdRows []db.FindingDependent, deps map[uint]db.Dependent) []csafFlag {
	var flags []csafFlag
	if mapProductStatus(f) == csafStatusKnownNotAffected {
		flags = append(flags, csafFlag{
			Label:      "vulnerable_code_not_present",
			ProductIDs: productIDs,
		})
	}
	byLabel := make(map[string][]string)
	for _, r := range fdRows {
		if r.Status != db.ExposureKnownNotAffected || r.Justification == "" {
			continue
		}
		dep, ok := deps[r.DependentID]
		if !ok {
			continue
		}
		byLabel[r.Justification] = append(byLabel[r.Justification], dependentProductID(dep))
	}
	labels := make([]string, 0, len(byLabel))
	for label := range byLabel {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		flags = append(flags, csafFlag{Label: label, ProductIDs: byLabel[label]})
	}
	return flags
}

func buildProductStatusMulti(f db.Finding, productIDs []string, fdRows []db.FindingDependent, deps map[uint]db.Dependent) *csafProductStatus {
	ps := &csafProductStatus{}
	switch mapProductStatus(f) {
	case csafStatusFixed:
		ps.Fixed = productIDs
	case csafStatusKnownNotAffected:
		ps.KnownNotAffected = productIDs
	case csafStatusKnownAffected:
		ps.KnownAffected = productIDs
	default:
		ps.UnderInvestigation = productIDs
	}
	for _, r := range fdRows {
		dep, ok := deps[r.DependentID]
		if !ok {
			continue
		}
		pid := dependentProductID(dep)
		switch r.Status {
		case db.ExposureKnownAffected:
			ps.KnownAffected = append(ps.KnownAffected, pid)
		case db.ExposureKnownNotAffected:
			ps.KnownNotAffected = append(ps.KnownNotAffected, pid)
		case db.ExposureFixed:
			ps.Fixed = append(ps.Fixed, pid)
		default:
			ps.UnderInvestigation = append(ps.UnderInvestigation, pid)
		}
	}
	return ps
}

// buildScoreMulti derives the CVSS block from the vector itself. The
// stored f.CVSSScore is intentionally ignored: rows written before the
// auto-sync landed (or by a tool that wrote vector without score) would
// otherwise emit baseScore: 0 / baseSeverity: NONE next to a populated
// vector, which is worse than no score at all.
func buildScoreMulti(f db.Finding, productIDs []string) *csafScore {
	cvss := parseCVSSv3Vector(f.CVSSVector)
	if cvss == nil {
		return nil
	}
	score, ok := db.BaseScoreFromVector(f.CVSSVector)
	if !ok {
		return nil
	}
	cvss.BaseScore = score
	cvss.BaseSeverity = severityLabel(score)
	cvss.VectorString = f.CVSSVector
	return &csafScore{Products: productIDs, CVSSv3: cvss}
}

func buildRemediationsMulti(f db.Finding, repo db.Repository, productIDs []string) []csafRemediation {
	var out []csafRemediation
	if f.FixVersion != "" || f.FixCommit != "" {
		details := "Fix available"
		if f.FixVersion != "" {
			details = "Fixed in " + f.FixVersion
		} else if f.FixCommit != "" {
			details = "Fixed in commit " + f.FixCommit
		}
		url := ""
		if repo.HTMLURL != "" && f.FixCommit != "" {
			url = strings.TrimSuffix(repo.HTMLURL, "/") + "/commit/" + f.FixCommit
		}
		out = append(out, csafRemediation{
			Category:   "vendor_fix",
			Details:    details,
			ProductIDs: productIDs,
			URL:        url,
		})
	}
	if f.Resolution == db.ResolutionWorkaround {
		out = append(out, csafRemediation{
			Category:   "workaround",
			Details:    "Workaround available; see finding details.",
			ProductIDs: productIDs,
		})
	}
	return out
}

func csafProductSuffix(f db.Finding) string {
	if f.FindingID != "" {
		return f.FindingID
	}
	return strconv.Itoa(int(f.ID))
}

// mapProductStatus picks the CSAF product_status bucket. FindingPublished
// means the advisory went out, not that the bug is fixed; only emit "fixed"
// when a fix is actually pinned via FixVersion/FixCommit.
func mapProductStatus(f db.Finding) string {
	if f.FixVersion != "" || f.FixCommit != "" {
		return csafStatusFixed
	}
	switch f.Status {
	case db.FindingFixed:
		return csafStatusFixed
	case db.FindingRejected:
		return csafStatusKnownNotAffected
	case db.FindingNew, db.FindingEnriched:
		return csafStatusUnderInvestigation
	case db.FindingTriaged, db.FindingReady, db.FindingReported, db.FindingAcknowledged, db.FindingPublished:
		if f.Resolution == db.ResolutionWontfix {
			return csafStatusKnownNotAffected
		}
		return csafStatusKnownAffected
	}
	if f.Resolution == db.ResolutionWontfix {
		return csafStatusKnownNotAffected
	}
	return csafStatusUnderInvestigation
}

func buildCWE(id string) *csafCWE {
	if id == "" {
		return nil
	}
	if _, c, ok := LookupCWE(id); ok {
		return &csafCWE{ID: id, Name: c.Name}
	}
	return &csafCWE{ID: id, Name: id}
}

func buildAuditNotes(f db.Finding) []csafNote {
	steps := []struct{ title, text string }{
		{"trace", f.Trace},
		{"boundary", f.Boundary},
		{"validation", f.Validation},
		{"prior_art", f.PriorArt},
		{"reach", f.Reach},
		{"rating", f.Rating},
	}
	var out []csafNote
	for _, s := range steps {
		if s.text == "" {
			continue
		}
		out = append(out, csafNote{Category: "details", Title: s.title, Text: s.text})
	}
	// Exploitation status surfaces as a CSAF note rather than under a
	// `threats` block: the latter is reserved for impact descriptors
	// the spec accepts at write time, while a free-text exploitation
	// note travels reliably to coordinators that scan note titles.
	if f.ExploitedInWild != "" {
		text := "Exploited in wild: " + f.ExploitedInWild
		if e := strings.TrimSpace(f.ExploitedInWildEvidence); e != "" {
			text += "\n\n" + e
		}
		out = append(out, csafNote{Category: "details", Title: "exploited_in_wild", Text: text})
	}
	return out
}

func buildReferences(refs []db.FindingReference) []csafReference {
	if len(refs) == 0 {
		return nil
	}
	out := make([]csafReference, 0, len(refs))
	for _, r := range refs {
		summary := firstNonEmpty(r.Summary, r.Tags, r.URL)
		out = append(out, csafReference{Category: "external", Summary: summary, URL: r.URL})
	}
	return out
}

func parseCVSSv3Vector(vec string) *csafCVSSv3 {
	if !strings.HasPrefix(vec, "CVSS:") {
		return nil
	}
	parts := strings.Split(vec, "/")
	const minParts = 2
	if len(parts) < minParts {
		return nil
	}
	version := strings.TrimPrefix(parts[0], "CVSS:")
	if version != cvssVersion30 && version != cvssVersion31 {
		return nil
	}
	out := &csafCVSSv3{Version: version}
	got := 0
	for _, kv := range parts[1:] {
		k, v, ok := strings.Cut(kv, ":")
		if !ok {
			continue
		}
		val, ok := cvssValue(k, v)
		if !ok {
			continue
		}
		switch k {
		case "AV":
			out.AttackVector = val
		case "AC":
			out.AttackComplexity = val
		case "PR":
			out.PrivilegesRequired = val
		case "UI":
			out.UserInteraction = val
		case "S":
			out.Scope = val
		case "C":
			out.ConfidentialityImpact = val
		case "I":
			out.IntegrityImpact = val
		case "A":
			out.AvailabilityImpact = val
		}
		got++
	}
	if got == 0 {
		return nil
	}
	return out
}

func cvssValue(k, v string) (string, bool) {
	var m map[string]string
	switch k {
	case "AV":
		m = map[string]string{"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
	case "AC":
		m = map[string]string{"L": "LOW", "H": "HIGH"}
	case "PR":
		m = map[string]string{"N": "NONE", "L": "LOW", "H": "HIGH"}
	case "UI":
		m = map[string]string{"N": "NONE", "R": "REQUIRED"}
	case "S":
		m = map[string]string{"U": "UNCHANGED", "C": "CHANGED"}
	case "C", "I", "A":
		m = map[string]string{"H": "HIGH", "L": "LOW", "N": "NONE"}
	default:
		return "", false
	}
	val, ok := m[v]
	return val, ok
}

// severityLabel derives the CVSS base severity from the numeric score per
// the FIRST spec. The textual Finding.Severity is intentionally ignored:
// analyst free-form values can drift from the score (e.g. score 9.8 marked
// "High" instead of "Critical"), and CSAF tooling expects strict bands.
func severityLabel(score float64) string {
	switch {
	case score >= cvssCriticalScore:
		return csafSeverityCritical
	case score >= cvssHighScore:
		return csafSeverityHigh
	case score >= cvssMediumScore:
		return csafSeverityMedium
	case score > 0:
		return csafSeverityLow
	}
	return csafSeverityNone
}
