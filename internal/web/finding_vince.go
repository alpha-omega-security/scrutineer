package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/vince"
)

const (
	vinceAttachmentBundle = "bundle"
	vinceAttachmentReport = "report"
	vinceAttachmentNone   = "none"
)

type vinceFindingContext struct {
	Finding        db.Finding
	Repository     db.Repository
	Scan           db.Scan
	Packages       []db.Package
	References     []db.FindingReference
	Communications []db.FindingCommunication
	Notes          []db.FindingNote
}

type vinceAttachmentOption struct {
	Value    string
	Label    string
	Name     string
	Size     int64
	Contents []string
	TooLarge bool
}

type vincePageData struct {
	Finding               db.Finding
	Repository            db.Repository
	Packages              []db.Package
	References            []db.FindingReference
	SelectedPackageID     uint
	SelectedReferences    map[uint]bool
	Report                vince.Report
	Errors                vince.ValidationErrors
	Error                 string
	Ambiguous             bool
	ReconciliationVRFID   string
	Recipient             string
	ReportsURL            string
	Attachment            string
	AttachmentGeneratedAt string
	AttachmentSHA256      string
	AttachmentOptions     []vinceAttachmentOption
	Confirmations         map[string]bool
}

func (s *Server) findingVINCEPreview(w http.ResponseWriter, r *http.Request) {
	if !s.VINCE.Enabled() {
		http.NotFound(w, r)
		return
	}
	ctx, ok := s.loadVINCEFinding(w, r)
	if !ok {
		return
	}
	if err := vinceEligibility(ctx.Finding, ctx.Notes, ctx.References); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	packageID, selectedRefs, err := vinceSelections(r.URL.Query(), ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	report := s.mapVINCEReport(ctx, packageID, selectedRefs)
	page := s.vincePage(ctx, report, packageID, selectedRefs, vinceAttachmentBundle,
		time.Now().UTC(), nil, nil)
	s.render(w, r, "finding_vince.html", map[string]any{"VINCE": page})
}

func (s *Server) findingVINCESubmit(w http.ResponseWriter, r *http.Request) {
	if !s.VINCE.Enabled() {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Serialising the eligibility re-check and POST prevents two browser
	// submissions from sending the same finding before the first can persist
	// its VINCE reference.
	s.vinceSubmitMu.Lock()
	defer s.vinceSubmitMu.Unlock()

	ctx, ok := s.loadVINCEFinding(w, r)
	if !ok {
		return
	}
	if err := vinceEligibility(ctx.Finding, ctx.Notes, ctx.References); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	report := vinceReportFromForm(r.Form)
	attachmentChoice := r.FormValue("attachment")
	confirmations := vinceConfirmations(r.Form)
	fieldErrors := vince.ValidationErrors{}
	packageID, selectedRefs, selectionErr := vinceSelections(r.Form, ctx)
	if selectionErr != nil {
		addVINCEError(fieldErrors, "selection", selectionErr.Error())
	}
	if err := report.Validate(); err != nil {
		var validation vince.ValidationErrors
		if errors.As(err, &validation) {
			mergeVINCEErrors(fieldErrors, validation)
		}
	}
	for field, confirmed := range confirmations {
		if !confirmed {
			addVINCEError(fieldErrors, field, "confirmation is required")
		}
	}

	generatedAt, err := time.Parse(time.RFC3339Nano, r.FormValue("attachment_generated_at"))
	if err != nil {
		addVINCEError(fieldErrors, "user_file", "attachment preview expired; review it again")
		generatedAt = time.Now().UTC()
	}
	attachment, _, err := s.vinceAttachment(ctx, attachmentChoice, generatedAt)
	if err != nil {
		addVINCEError(fieldErrors, "user_file", err.Error())
	}
	if attachment != nil {
		if len(attachment.Data) > vince.MaxAttachmentSize {
			addVINCEError(fieldErrors, "user_file", fmt.Sprintf(
				"attachment is %d bytes; VINCE permits at most %d",
				len(attachment.Data), vince.MaxAttachmentSize))
		}
		gotHash := attachmentHash(attachment)
		if expected := r.FormValue("attachment_sha256"); expected == "" || expected != gotHash {
			addVINCEError(fieldErrors, "user_file", "attachment contents changed after the preview; review them again")
		}
	}
	if attachmentChoice == vinceAttachmentNone && r.FormValue("attachment_sha256") != "" {
		addVINCEError(fieldErrors, "user_file", "attachment selection changed after the preview; review it again")
	}

	if len(fieldErrors) > 0 {
		page := s.vincePage(ctx, report, packageID, selectedRefs, attachmentChoice,
			time.Now().UTC(), fieldErrors, confirmations)
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "finding_vince.html", map[string]any{"VINCE": page})
		return
	}

	client := vince.Client{Config: s.VINCE, HTTPClient: s.vinceHTTPClient}
	vrfID, err := client.Submit(r.Context(), report, attachment)
	if err != nil {
		submitErr, _ := vince.AsSubmitError(err)
		status := http.StatusBadGateway
		message := err.Error()
		ambiguous := false
		if submitErr != nil {
			mergeVINCEErrors(fieldErrors, submitErr.FieldErrors)
			switch submitErr.Kind {
			case vince.ErrorValidation:
				status = http.StatusUnprocessableEntity
			case vince.ErrorAuth:
				status = http.StatusUnauthorized
			case vince.ErrorRateLimit:
				status = http.StatusTooManyRequests
			case vince.ErrorAmbiguous:
				ambiguous = true
			}
		}
		page := s.vincePage(ctx, report, packageID, selectedRefs, attachmentChoice,
			time.Now().UTC(), fieldErrors, confirmations)
		page.Error = message
		page.Ambiguous = ambiguous
		w.WriteHeader(status)
		s.render(w, r, "finding_vince.html", map[string]any{"VINCE": page})
		return
	}

	reportsURL, _ := s.VINCE.ReportsURL()
	attachmentName := "none"
	if attachment != nil {
		attachmentName = attachment.Name
	}
	if err := s.persistVINCESubmission(ctx.Finding.ID, vrfID, reportsURL, attachmentName); err != nil {
		page := s.vincePage(ctx, report, packageID, selectedRefs, attachmentChoice,
			time.Now().UTC(), nil, confirmations)
		page.Error = "VINCE returned " + vrfID + " but Scrutineer could not save the result. Record the ID and reconcile it manually. Do not submit the report again."
		page.ReconciliationVRFID = vrfID
		w.WriteHeader(http.StatusInternalServerError)
		s.render(w, r, "finding_vince.html", map[string]any{"VINCE": page})
		return
	}

	setFlash(w, Flash{
		Category: successKey,
		Title:    "Submitted to VINCE as " + vrfID,
		Href:     reportsURL,
		Label:    "Open VINCE reports",
	})
	s.redirect(w, r, fmt.Sprintf("/findings/%d", ctx.Finding.ID))
}

func (s *Server) loadVINCEFinding(w http.ResponseWriter, r *http.Request) (vinceFindingContext, bool) {
	var out vinceFindingContext
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return out, false
	}
	if err := s.DB.First(&out.Finding, id).Error; err != nil {
		http.NotFound(w, r)
		return out, false
	}
	if err := s.DB.First(&out.Repository, out.Finding.RepositoryID).Error; err != nil {
		http.Error(w, "repository missing for finding", http.StatusInternalServerError)
		return out, false
	}
	if err := s.DB.First(&out.Scan, out.Finding.ScanID).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "could not load finding scan", http.StatusInternalServerError)
		return out, false
	}
	queries := []struct {
		label string
		err   error
	}{
		{"packages", s.DB.Where("repository_id = ?", out.Finding.RepositoryID).Order("name").Find(&out.Packages).Error},
		{"references", s.DB.Where("finding_id = ?", out.Finding.ID).Order("id").Find(&out.References).Error},
		{"communications", s.DB.Where("finding_id = ?", out.Finding.ID).Order("at").Find(&out.Communications).Error},
		{"notes", s.DB.Where("finding_id = ?", out.Finding.ID).Order("created_at").Find(&out.Notes).Error},
	}
	for _, query := range queries {
		if query.err != nil {
			http.Error(w, "could not load finding "+query.label, http.StatusInternalServerError)
			return out, false
		}
	}
	return out, true
}

func vinceEligibility(f db.Finding, notes []db.FindingNote, refs []db.FindingReference) error {
	if strings.TrimSpace(f.DisclosureDraft) == "" {
		return fmt.Errorf("a reviewed disclosure draft is required before VINCE submission")
	}
	switch f.Status {
	case db.FindingReported, db.FindingAcknowledged, db.FindingFixed, db.FindingPublished:
		return fmt.Errorf("finding status %q has already reached or passed reported", f.Status)
	case db.FindingRejected, db.FindingDuplicate:
		return fmt.Errorf("finding status %q cannot be submitted", f.Status)
	}
	for _, note := range notes {
		firstLine, _, _ := strings.Cut(note.Body, "\n")
		if strings.HasPrefix(strings.TrimSpace(firstLine), "finding-dedup: subsumed by finding #") {
			return fmt.Errorf("this finding is subsumed by another finding")
		}
	}
	for _, ref := range refs {
		if vinceReference(ref) {
			return fmt.Errorf("finding already has a VINCE reference")
		}
	}
	return nil
}

func vinceReference(ref db.FindingReference) bool {
	for _, tag := range strings.Split(ref.Tags, ",") {
		if strings.EqualFold(strings.TrimSpace(tag), "vince") {
			return true
		}
	}
	return false
}

func vinceSelections(values url.Values, ctx vinceFindingContext) (uint, map[uint]bool, error) {
	var packageID uint
	if raw := strings.TrimSpace(values.Get("package_id")); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid package selection")
		}
		packageID = uint(id)
		if packageID != 0 && !slices.ContainsFunc(ctx.Packages, func(p db.Package) bool { return p.ID == packageID }) {
			return 0, nil, fmt.Errorf("selected package does not belong to this repository")
		}
	}

	availableRefs := make(map[uint]bool, len(ctx.References))
	for _, ref := range ctx.References {
		availableRefs[ref.ID] = true
	}
	selected := map[uint]bool{}
	for _, raw := range values["reference_id"] {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || !availableRefs[uint(id)] {
			return 0, nil, fmt.Errorf("invalid reference selection")
		}
		selected[uint(id)] = true
	}
	return packageID, selected, nil
}

func (s *Server) mapVINCEReport(ctx vinceFindingContext, packageID uint, selectedRefs map[uint]bool) vince.Report {
	productName := firstNonEmpty(ctx.Repository.Name, ctx.Repository.FullName, ctx.Repository.URL)
	if packageID != 0 {
		for _, pkg := range ctx.Packages {
			if pkg.ID == packageID {
				productName = pkg.Name
				break
			}
		}
	}
	commit := firstNonEmpty(ctx.Finding.Commit, ctx.Scan.Commit, ctx.Finding.LastSeenCommit)
	version := strings.TrimSpace(ctx.Finding.Affected)
	if version == "" {
		version = commit
	}

	descriptionParts := []string{strings.TrimSpace(ctx.Finding.DisclosureDraft)}
	coordinates := []string{}
	appendCoordinate := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			coordinates = append(coordinates, label+": "+strings.TrimSpace(value))
		}
	}
	appendCoordinate("Repository", firstNonEmpty(ctx.Repository.FullName, ctx.Repository.Name, ctx.Repository.URL))
	appendCoordinate("Location", ctx.Finding.Location)
	appendCoordinate("CWE", ctx.Finding.CWE)
	appendCoordinate("CVE", ctx.Finding.CVEID)
	appendCoordinate("GHSA", ctx.Finding.GHSAID)
	appendCoordinate("CVSS v3", ctx.Finding.CVSSVector)
	appendCoordinate("CVSS v4", ctx.Finding.CVSSv4Vector)
	if len(coordinates) > 0 {
		descriptionParts = append(descriptionParts, strings.Join(coordinates, "\n"))
	}

	exploitParts := labelledVINCEText(
		"Reach", ctx.Finding.Reach,
		"Validation", ctx.Finding.Validation,
	)
	impactParts := labelledVINCEText(
		"Rating", ctx.Finding.Rating,
		"Severity", ctx.Finding.Severity,
		"CVSS v3", ctx.Finding.CVSSVector,
		"CVSS v4", ctx.Finding.CVSSv4Vector,
	)
	producer := firstNonEmpty(ctx.Scan.SkillName, ctx.Finding.ImportedFrom, ctx.Scan.Kind, "Scrutineer")
	backend := firstNonEmpty(ctx.Scan.Backend, "unknown backend")
	discovery := fmt.Sprintf(
		"Scrutineer used AI-assisted analysis via %s on tested commit %s with the %s backend. An analyst manually reviewed the finding and its reproduction before submission.",
		producer, firstNonEmpty(commit, "unknown"), backend,
	)

	publicRefs := []string{}
	for _, ref := range ctx.References {
		if selectedRefs[ref.ID] && !vinceReference(ref) {
			publicRefs = append(publicRefs, strings.TrimSpace(ref.URL))
		}
	}

	report := vince.Report{
		ContactName:              s.VINCE.Reporter.Name,
		ContactOrganization:      s.VINCE.Reporter.Organization,
		ContactEmail:             s.VINCE.Reporter.Email,
		ReporterPGP:              s.VINCE.Reporter.PGPKey,
		ContactPhone:             s.VINCE.Reporter.Phone,
		VendorName:               repositoryOwner(ctx.Repository),
		ProductName:              productName,
		ProductVersion:           version,
		VulnerabilityDescription: strings.Join(descriptionParts, "\n\n"),
		VulnerabilityExploit:     exploitParts,
		VulnerabilityImpact:      impactParts,
		VulnerabilityDiscovery:   discovery,
		PublicReferences:         strings.Join(publicRefs, "\n"),
		ExploitReferences:        strings.TrimSpace(ctx.Finding.ExploitedInWildEvidence),
	}
	switch ctx.Finding.ExploitedInWild {
	case "yes":
		report.VulnerabilityExploited = vince.AnswerYes
	case "no":
		report.VulnerabilityExploited = vince.AnswerNo
	}
	if len(ctx.Communications) > 0 {
		report.VendorCommunication = formatVINCECommunications(ctx.Communications)
	}
	return report
}

func labelledVINCEText(items ...string) string {
	parts := []string{}
	for i := 0; i+1 < len(items); i += 2 {
		if value := strings.TrimSpace(items[i+1]); value != "" {
			parts = append(parts, items[i]+":\n"+value)
		}
	}
	return strings.Join(parts, "\n\n")
}

func repositoryOwner(repo db.Repository) string {
	if strings.TrimSpace(repo.Owner) != "" {
		return strings.TrimSpace(repo.Owner)
	}
	if owner, _, ok := strings.Cut(strings.TrimSpace(repo.FullName), "/"); ok {
		return owner
	}
	u, err := url.Parse(repo.URL)
	if err == nil {
		path := strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
		if owner, _, ok := strings.Cut(path, "/"); ok {
			return owner
		}
	}
	return ""
}

func formatVINCECommunications(comms []db.FindingCommunication) string {
	lines := make([]string, 0, len(comms))
	for _, comm := range comms {
		line := fmt.Sprintf("%s %s via %s with %s",
			comm.At.Format("2006-01-02"),
			firstNonEmpty(comm.Direction, "communication"),
			firstNonEmpty(comm.Channel, "unknown channel"),
			firstNonEmpty(comm.Actor, "unknown party"),
		)
		if body := strings.TrimSpace(comm.Body); body != "" {
			line += ": " + body
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func vinceReportFromForm(values url.Values) vince.Report {
	return vince.Report{
		ContactName:              strings.TrimSpace(values.Get("contact_name")),
		ContactOrganization:      strings.TrimSpace(values.Get("contact_org")),
		ContactEmail:             strings.TrimSpace(values.Get("contact_email")),
		ReporterPGP:              strings.TrimSpace(values.Get("reporter_pgp")),
		ContactPhone:             strings.TrimSpace(values.Get("contact_phone")),
		ShareRelease:             values.Get("share_release"),
		CreditRelease:            values.Get("credit_release"),
		CoordinationStatus:       values["coord_status"],
		CommunicationAttempt:     values.Get("comm_attempt"),
		WhyNoAttempt:             values.Get("why_no_attempt"),
		PleaseExplain:            strings.TrimSpace(values.Get("please_explain")),
		VendorName:               strings.TrimSpace(values.Get("vendor_name")),
		MultipleVendors:          values.Get("multiplevendors"),
		OtherVendors:             strings.TrimSpace(values.Get("other_vendors")),
		FirstContact:             strings.TrimSpace(values.Get("first_contact")),
		VendorCommunication:      strings.TrimSpace(values.Get("vendor_communication")),
		ProductName:              strings.TrimSpace(values.Get("product_name")),
		ProductVersion:           strings.TrimSpace(values.Get("product_version")),
		ICSImpact:                values.Get("ics_impact"),
		AIMLSystem:               values.Get("ai_ml_system"),
		VulnerabilityDescription: strings.TrimSpace(values.Get("vul_description")),
		VulnerabilityExploit:     strings.TrimSpace(values.Get("vul_exploit")),
		VulnerabilityImpact:      strings.TrimSpace(values.Get("vul_impact")),
		VulnerabilityDiscovery:   strings.TrimSpace(values.Get("vul_discovery")),
		VulnerabilityPublic:      values.Get("vul_public"),
		PublicReferences:         strings.TrimSpace(values.Get("public_references")),
		VulnerabilityExploited:   values.Get("vul_exploited"),
		ExploitReferences:        strings.TrimSpace(values.Get("exploit_references")),
		VulnerabilityDisclose:    values.Get("vul_disclose"),
		DisclosurePlans:          strings.TrimSpace(values.Get("disclosure_plans")),
		Tracking:                 strings.TrimSpace(values.Get("tracking")),
		Comments:                 strings.TrimSpace(values.Get("comments")),
		CISACoordination:         values.Get("cisa_please"),
	}
}

func vinceConfirmations(values url.Values) map[string]bool {
	out := map[string]bool{}
	for _, field := range []string{
		"confirm_recipient", "confirm_reporter", "confirm_choices",
		"confirm_attachment", "confirm_manual_review",
	} {
		out[field] = values.Get(field) == "yes"
	}
	return out
}

func mergeVINCEErrors(dst, src vince.ValidationErrors) {
	for field, messages := range src {
		dst[field] = append(dst[field], messages...)
	}
}

func addVINCEError(errs vince.ValidationErrors, field, message string) {
	errs[field] = append(errs[field], message)
}

func (s *Server) vincePage(
	ctx vinceFindingContext,
	report vince.Report,
	packageID uint,
	selectedRefs map[uint]bool,
	attachmentChoice string,
	generatedAt time.Time,
	fieldErrors vince.ValidationErrors,
	confirmations map[string]bool,
) vincePageData {
	if fieldErrors == nil {
		fieldErrors = vince.ValidationErrors{}
	}
	if confirmations == nil {
		confirmations = map[string]bool{}
	}
	if !slices.Contains([]string{vinceAttachmentBundle, vinceAttachmentReport, vinceAttachmentNone}, attachmentChoice) {
		attachmentChoice = vinceAttachmentBundle
	}
	recipient, _ := s.VINCE.Endpoint()
	reportsURL, _ := s.VINCE.ReportsURL()
	attachmentChoices := []string{vinceAttachmentBundle, vinceAttachmentReport, vinceAttachmentNone}
	options := make([]vinceAttachmentOption, 0, len(attachmentChoices))
	var selectedAttachment *vince.Attachment
	for _, choice := range attachmentChoices {
		attachment, contents, err := s.vinceAttachment(ctx, choice, generatedAt)
		option := vinceAttachmentOption{
			Value: choice, Contents: contents,
		}
		switch choice {
		case vinceAttachmentBundle:
			option.Label = "Disclosure bundle (recommended)"
		case vinceAttachmentReport:
			option.Label = "Markdown report"
		case vinceAttachmentNone:
			option.Label = "No attachment"
		}
		if err != nil {
			addVINCEError(fieldErrors, "user_file", err.Error())
		} else if attachment != nil {
			option.Name = attachment.Name
			option.Size = int64(len(attachment.Data))
			option.TooLarge = option.Size > int64(vince.MaxAttachmentSize)
		}
		if choice == attachmentChoice {
			selectedAttachment = attachment
		}
		options = append(options, option)
	}
	hash := ""
	if selectedAttachment != nil {
		hash = attachmentHash(selectedAttachment)
	}
	return vincePageData{
		Finding:               ctx.Finding,
		Repository:            ctx.Repository,
		Packages:              ctx.Packages,
		References:            ctx.References,
		SelectedPackageID:     packageID,
		SelectedReferences:    selectedRefs,
		Report:                report,
		Errors:                fieldErrors,
		Recipient:             recipient,
		ReportsURL:            reportsURL,
		Attachment:            attachmentChoice,
		AttachmentGeneratedAt: generatedAt.Format(time.RFC3339Nano),
		AttachmentSHA256:      hash,
		AttachmentOptions:     options,
		Confirmations:         confirmations,
	}
}

func (s *Server) vinceAttachment(
	ctx vinceFindingContext,
	choice string,
	generatedAt time.Time,
) (*vince.Attachment, []string, error) {
	switch choice {
	case vinceAttachmentBundle:
		entries, err := s.bundleEntriesAt(&ctx.Finding, &ctx.Repository, generatedAt)
		if err != nil {
			return nil, nil, fmt.Errorf("build disclosure bundle: %w", err)
		}
		body, err := buildTarGzAt(entries, generatedAt)
		if err != nil {
			return nil, nil, fmt.Errorf("build disclosure bundle: %w", err)
		}
		contents := make([]string, 0, len(entries))
		for _, entry := range entries {
			contents = append(contents, entry.Name)
		}
		return &vince.Attachment{
			Name:        fmt.Sprintf("scrutineer-finding-%d-disclosure.tar.gz", ctx.Finding.ID),
			ContentType: "application/gzip",
			Data:        body,
		}, contents, nil
	case vinceAttachmentReport:
		report := renderFindingReportAt(s.DB, &ctx.Finding, &ctx.Scan, &ctx.Repository, generatedAt)
		return &vince.Attachment{
			Name:        fmt.Sprintf("scrutineer-finding-%d-report.md", ctx.Finding.ID),
			ContentType: "text/markdown; charset=utf-8",
			Data:        []byte(report),
		}, []string{"report.md"}, nil
	case vinceAttachmentNone:
		return nil, nil, nil
	default:
		return nil, nil, fmt.Errorf("choose a valid attachment")
	}
}

func attachmentHash(attachment *vince.Attachment) string {
	h := sha256.New()
	_, _ = h.Write([]byte(attachment.Name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(attachment.Data)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) persistVINCESubmission(findingID uint, vrfID, reportsURL, attachmentName string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		var refs []db.FindingReference
		if err := tx.Where("finding_id = ?", findingID).Find(&refs).Error; err != nil {
			return err
		}
		for _, ref := range refs {
			if vinceReference(ref) {
				return fmt.Errorf("finding already has a VINCE reference")
			}
		}
		if _, err := db.AddFindingReference(tx, findingID, reportsURL, "vince,coordinator",
			"CERT/CC VINCE report "+vrfID); err != nil {
			return err
		}
		body := "Submitted vulnerability report " + vrfID + " to CERT/CC VINCE.\nAttachment: " + attachmentName
		if _, err := db.AddFindingCommunication(tx, findingID, "vince", "outbound",
			"CERT/CC", body, "", time.Now()); err != nil {
			return err
		}
		return db.WriteFindingField(tx, findingID, "status", string(db.FindingReported), db.SourceSystem, "vince")
	})
}
