package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/vince"
)

func seedVINCEFinding(t *testing.T, s *Server) vinceFindingContext {
	t.Helper()
	repo := db.Repository{
		URL:      "https://github.com/acme/widget.git",
		Name:     "widget",
		FullName: "acme/widget",
		Owner:    "acme",
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         "skill",
		Status:       db.ScanDone,
		SkillName:    "security-deep-dive",
		Backend:      "codex",
		Commit:       "0123456789abcdef",
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		ScanID:                  scan.ID,
		RepositoryID:            repo.ID,
		Commit:                  scan.Commit,
		FindingID:               "F1",
		Title:                   "Command injection",
		Severity:                "High",
		Status:                  db.FindingReady,
		CWE:                     "CWE-78",
		Location:                "cmd/run.go:42",
		Affected:                "< 2.0.0",
		CVSSVector:              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		DisclosureDraft:         "## Command injection\n\nCrafted input reaches a shell.",
		Reach:                   "A network request reaches the command builder.",
		Validation:              "The reproduction writes a marker file.",
		Rating:                  "Remote code execution as the service account.",
		ExploitedInWild:         "yes",
		ExploitedInWildEvidence: "https://example.com/exploitation",
	}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	pkg := db.Package{
		RepositoryID: repo.ID,
		Name:         "github.com/acme/widget/v2",
		Ecosystem:    "Go",
	}
	if err := s.DB.Create(&pkg).Error; err != nil {
		t.Fatal(err)
	}
	ref := db.FindingReference{
		FindingID: finding.ID,
		URL:       "https://example.com/public-advisory",
		Tags:      "advisory",
	}
	if err := s.DB.Create(&ref).Error; err != nil {
		t.Fatal(err)
	}
	contactAt := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	comm := db.FindingCommunication{
		FindingID: finding.ID,
		Channel:   "email",
		Direction: "outbound",
		Actor:     "security@acme.example",
		Body:      "Sent technical details.",
		At:        contactAt,
		CreatedAt: contactAt,
	}
	if err := s.DB.Create(&comm).Error; err != nil {
		t.Fatal(err)
	}
	return vinceFindingContext{
		Finding: finding, Repository: repo, Scan: scan,
		Packages: []db.Package{pkg}, References: []db.FindingReference{ref},
		Communications: []db.FindingCommunication{comm},
	}
}

func validVINCEWebForm() url.Values {
	return url.Values{
		"package_id":              {"0"},
		"contact_name":            {"Alice"},
		"contact_org":             {"Example Security"},
		"contact_email":           {"alice@example.com"},
		"contact_phone":           {"+44 20 7946 0958"},
		"share_release":           {"False"},
		"credit_release":          {"True"},
		"coord_status":            {"4"},
		"comm_attempt":            {"True"},
		"vendor_name":             {"acme"},
		"multiplevendors":         {"False"},
		"product_name":            {"widget"},
		"product_version":         {"< 2.0.0"},
		"ics_impact":              {"False"},
		"ai_ml_system":            {"False"},
		"vul_description":         {"Reviewed disclosure"},
		"vul_exploit":             {"Send crafted input"},
		"vul_impact":              {"Remote code execution"},
		"vul_discovery":           {"AI-assisted analysis followed by manual review"},
		"vul_public":              {"False"},
		"vul_exploited":           {"False"},
		"vul_disclose":            {"True"},
		"cisa_please":             {"False"},
		"attachment":              {"none"},
		"attachment_generated_at": {time.Now().UTC().Format(time.RFC3339Nano)},
		"confirm_recipient":       {"yes"},
		"confirm_reporter":        {"yes"},
		"confirm_choices":         {"yes"},
		"confirm_attachment":      {"yes"},
		"confirm_manual_review":   {"yes"},
	}
}

func TestMapVINCEReport(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	s.VINCE = vince.Config{Reporter: vince.Reporter{
		Name: "Configured Name", Organization: "Configured Org",
		Email: "configured@example.com", Phone: "+1 555 0100", PGPKey: "https://example.com/key",
	}}

	report := s.mapVINCEReport(ctx, ctx.Packages[0].ID, map[uint]bool{ctx.References[0].ID: true})
	if report.ProductName != ctx.Packages[0].Name || report.ProductVersion != ctx.Finding.Affected {
		t.Errorf("product = %q %q", report.ProductName, report.ProductVersion)
	}
	if report.VendorName != "acme" {
		t.Errorf("vendor = %q", report.VendorName)
	}
	if report.ContactName != "Configured Name" || report.ContactEmail != "configured@example.com" {
		t.Errorf("reporter = %+v", report)
	}
	for _, want := range []string{"acme/widget", "cmd/run.go:42", "CWE-78", "CVSS:3.1"} {
		if !strings.Contains(report.VulnerabilityDescription, want) {
			t.Errorf("description missing %q: %s", want, report.VulnerabilityDescription)
		}
	}
	if !strings.Contains(report.VulnerabilityExploit, ctx.Finding.Reach) ||
		!strings.Contains(report.VulnerabilityExploit, ctx.Finding.Validation) {
		t.Errorf("exploit mapping = %q", report.VulnerabilityExploit)
	}
	if !strings.Contains(report.VulnerabilityImpact, ctx.Finding.Rating) ||
		!strings.Contains(report.VulnerabilityImpact, "High") {
		t.Errorf("impact mapping = %q", report.VulnerabilityImpact)
	}
	for _, want := range []string{"security-deep-dive", "0123456789abcdef", "codex", "AI-assisted", "manually reviewed"} {
		if !strings.Contains(report.VulnerabilityDiscovery, want) {
			t.Errorf("discovery missing %q: %s", want, report.VulnerabilityDiscovery)
		}
	}
	if report.PublicReferences != ctx.References[0].URL {
		t.Errorf("public references = %q", report.PublicReferences)
	}
	if report.VulnerabilityExploited != vince.AnswerYes ||
		report.ExploitReferences != ctx.Finding.ExploitedInWildEvidence {
		t.Errorf("exploitation = %q %q", report.VulnerabilityExploited, report.ExploitReferences)
	}
	if report.CommunicationAttempt != "" ||
		len(report.CoordinationStatus) != 0 ||
		report.FirstContact != "" ||
		!strings.Contains(report.VendorCommunication, "Sent technical details") {
		t.Errorf("communications = %+v", report)
	}
	if report.ShareRelease != "" || report.CreditRelease != "" || report.MultipleVendors != "" ||
		report.VulnerabilityPublic != "" || report.VulnerabilityDisclose != "" {
		t.Errorf("unknown policy choices must remain unresolved: %+v", report)
	}
}

func TestVINCEEligibility(t *testing.T) {
	base := db.Finding{Status: db.FindingReady, DisclosureDraft: "reviewed"}
	if err := vinceEligibility(base, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, status := range []db.FindingLifecycle{
		db.FindingReported, db.FindingAcknowledged, db.FindingFixed,
		db.FindingPublished, db.FindingRejected, db.FindingDuplicate,
	} {
		finding := base
		finding.Status = status
		if err := vinceEligibility(finding, nil, nil); err == nil {
			t.Errorf("status %q accepted", status)
		}
	}
	finding := base
	finding.DisclosureDraft = " "
	if err := vinceEligibility(finding, nil, nil); err == nil {
		t.Error("empty disclosure draft accepted")
	}
	if err := vinceEligibility(base, []db.FindingNote{{
		Body: "finding-dedup: subsumed by finding #12\nreason",
	}}, nil); err == nil {
		t.Error("subsumed finding accepted")
	}
	if err := vinceEligibility(base, nil, []db.FindingReference{{
		Tags: "coordinator, VINCE",
	}}); err == nil {
		t.Error("existing VINCE reference accepted")
	}
}

func TestFindingVINCEPreviewAndDisabledAction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", ctx.Finding.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("finding status = %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `disabled title="VINCE API key is not configured"`) {
		t.Errorf("finding page did not disable VINCE action: %s", w.Body)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d/vince", ctx.Finding.ID)))
	if w.Code != http.StatusNotFound {
		t.Errorf("preview without key = %d, want 404", w.Code)
	}

	s.VINCE = vince.Config{
		BaseURL: "https://vince.example", APIKey: "secret",
		Reporter: vince.Reporter{Name: "Alice", Email: "alice@example.com"},
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet,
		fmt.Sprintf("/findings/%d/vince?package_id=%d&reference_id=%d",
			ctx.Finding.ID, ctx.Packages[0].ID, ctx.References[0].ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("preview status = %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Submit to CERT/CC VINCE",
		`value="github.com/acme/widget/v2"`,
		ctx.References[0].URL,
		"Do not include sensitive details",
		"runnable proof of concept",
		`name="contact_phone" maxlength="20"`,
		`name="exploit_references" rows="5" maxlength="1000"`,
		`name="confirm_manual_review"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("preview missing %q", want)
		}
	}
	if strings.Contains(body, "secret") {
		t.Error("VINCE API key leaked into preview")
	}
}

func TestFindingVINCESubmitSuccessAndDuplicatePrevention(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/vince/comm/api/vulreport/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Token secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("ParseMultipartForm: %v", err)
		}
		if r.FormValue("product_name") != "widget" {
			t.Errorf("product_name = %q", r.FormValue("product_name"))
		}
		if _, _, err := r.FormFile("user_file"); err == nil {
			t.Error("unexpected attachment")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"vrf_id":"VRF#26-07-ABCDE"}`)
	}))
	defer server.Close()
	s.VINCE = vince.Config{BaseURL: server.URL, APIKey: "secret"}

	path := fmt.Sprintf("/findings/%d/vince", ctx.Finding.ID)
	w := postForm(t, s, path, validVINCEWebForm())
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303: %s", w.Code, w.Body)
	}
	var finding db.Finding
	if err := s.DB.First(&finding, ctx.Finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if finding.Status != db.FindingReported {
		t.Errorf("status = %q, want reported", finding.Status)
	}
	var refs []db.FindingReference
	s.DB.Where("finding_id = ?", finding.ID).Find(&refs)
	if !slices.ContainsFunc(refs, func(ref db.FindingReference) bool {
		return vinceReference(ref) && strings.Contains(ref.Summary, "VRF#26-07-ABCDE")
	}) {
		t.Errorf("VINCE reference missing: %+v", refs)
	}
	var comms []db.FindingCommunication
	s.DB.Where("finding_id = ? AND channel = ?", finding.ID, "vince").Find(&comms)
	if len(comms) != 1 || !strings.Contains(comms[0].Body, "VRF#26-07-ABCDE") ||
		!strings.Contains(comms[0].Body, "Attachment: none") {
		t.Errorf("VINCE communications = %+v", comms)
	}
	var history db.FindingHistory
	if err := s.DB.Where("finding_id = ? AND field = ?", finding.ID, "status").First(&history).Error; err != nil {
		t.Fatal(err)
	}
	if history.Source != db.SourceSystem || history.By != "vince" {
		t.Errorf("status history = %+v", history)
	}

	w = postForm(t, s, path, validVINCEWebForm())
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate status = %d, want 409", w.Code)
	}
	if requests.Load() != 1 {
		t.Errorf("VINCE requests = %d, want exactly 1", requests.Load())
	}
}

func TestFindingVINCESurfacesRemoteFieldErrors(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"errors":{"product_name":["VINCE says this name is invalid."]}}`)
	}))
	defer server.Close()
	s.VINCE = vince.Config{BaseURL: server.URL, APIKey: "secret"}

	w := postForm(t, s, fmt.Sprintf("/findings/%d/vince", ctx.Finding.ID), validVINCEWebForm())
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "VINCE says this name is invalid.") {
		t.Errorf("field error missing: %s", w.Body)
	}
	var finding db.Finding
	s.DB.First(&finding, ctx.Finding.ID)
	if finding.Status != db.FindingReady {
		t.Errorf("status changed to %q", finding.Status)
	}
}

func TestFindingVINCEPersistenceFailureShowsVRFID(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"vrf_id":"VRF#manual-reconcile"}`)
	}))
	defer server.Close()
	s.VINCE = vince.Config{BaseURL: server.URL, APIKey: "secret"}

	callback := "test:fail-vince-reference"
	if err := s.DB.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "FindingReference" &&
			strings.Contains(fmt.Sprint(tx.Statement.Dest), "vince,coordinator") {
			if err := tx.AddError(errors.New("database unavailable")); err == nil {
				t.Error("expected transaction error")
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.DB.Callback().Create().Remove(callback); err != nil {
			t.Errorf("remove callback: %v", err)
		}
	}()

	w := postForm(t, s, fmt.Sprintf("/findings/%d/vince", ctx.Finding.ID), validVINCEWebForm())
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body)
	}
	for _, want := range []string{"VRF#manual-reconcile", "reconcile it manually", "Do not submit"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("response missing %q: %s", want, w.Body)
		}
	}
	var finding db.Finding
	s.DB.First(&finding, ctx.Finding.ID)
	if finding.Status != db.FindingReady {
		t.Errorf("status changed despite rollback: %q", finding.Status)
	}
}

func TestVINCEAttachmentPreviewUsesTimestampAndListsSensitiveContents(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	ctx.Finding.SuggestedFix = "diff --git a/x b/x\n"
	ctx.Finding.Validation = "```sh\necho reproduced\n```"
	if err := s.DB.Save(&ctx.Finding).Error; err != nil {
		t.Fatal(err)
	}
	generatedAt := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	first, contents, err := s.vinceAttachment(ctx, vinceAttachmentBundle, generatedAt)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := s.vinceAttachment(ctx, vinceAttachmentBundle, generatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if attachmentHash(first) != attachmentHash(second) {
		t.Error("same finding and preview timestamp produced different attachment hashes")
	}
	const wantGeneratedAt = "at 2026-07-29 12:00 UTC."
	archive := readArchive(t, first.Data)
	if !strings.Contains(string(archive["report.md"]), wantGeneratedAt) {
		t.Errorf("bundle report does not use preview timestamp: %s", archive["report.md"])
	}
	for _, want := range []string{"manifest.json", "report.md", "patch.diff", "poc/run.sh"} {
		if !slices.Contains(contents, want) {
			t.Errorf("bundle contents missing %q: %#v", want, contents)
		}
	}

	report, _, err := s.vinceAttachment(ctx, vinceAttachmentReport, generatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report.Data), wantGeneratedAt) {
		t.Errorf("report attachment does not use preview timestamp: %s", report.Data)
	}
}
