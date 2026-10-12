package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
	"gorm.io/gorm"

	"scrutineer/internal/akrites"
	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
)

type akritesPage struct {
	Finding    db.Finding
	Report     akrites.Report
	Disclosure string
	Exploit    string
	Submission db.AkritesSubmission
	Endpoint   string
	Error      string
}

func (s *Server) findingAkritesPreview(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.loadDisclosureFinding(w, r)
	if !ok {
		return
	}
	page := akritesPage{Finding: ctx.Finding}
	page.Endpoint, _ = s.Akrites.Endpoint()
	err := s.DB.Where("finding_id = ?", ctx.Finding.ID).First(&page.Submission).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "could not load Akrites submission", http.StatusInternalServerError)
		return
	}
	// A saved submission stays readable after the token is removed; only new
	// submissions need it.
	if page.Submission.ID == 0 && !s.Akrites.Enabled() {
		http.NotFound(w, r)
		return
	}
	if page.Submission.ID == 0 {
		if err := akritesEligibility(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		page.Disclosure = ctx.Finding.DisclosureDraft
		page.Exploit = strings.TrimSpace(ctx.Finding.Reach + "\n\n" + ctx.Finding.Validation)
		page.Report = akrites.Report{
			Software:       ctx.Repository.Name,
			AffectedSymbol: akritesSymbol(ctx.Finding),
			PackageRepoURL: ctx.Repository.URL, DiscoveryMethod: "ai-assisted",
			Email: s.Akrites.Email, Notify: "off",
		}
		packages, err := findingAdvisoryPackages(s.DB, ctx.Finding, nil)
		if err != nil {
			http.Error(w, "could not load affected packages", http.StatusInternalServerError)
			return
		}
		if len(packages) == 1 {
			pkg := packages[0]
			page.Report.Software, page.Report.PURL = pkg.Name, pkg.PURL
			// Intake derives the ecosystem from a package URL, and otherwise
			// expects an OSV ecosystem name rather than the stored PURL type.
			if pkg.PURL == "" {
				page.Report.Ecosystem, _ = purl.PURLTypeToOSV(db.EcosystemType("", pkg.Ecosystem))
			}
		}
	}
	s.render(w, r, "finding_akrites.html", map[string]any{"Akrites": page})
}

// akritesSymbol prefills affected_symbol from the finding's location. The
// function is left for the analyst because locations name only a file and line.
func akritesSymbol(f db.Finding) *akrites.Symbol {
	file := findingnorm.FindingPath(f.SubPath, f.Location)
	if file == "" {
		return nil
	}
	return &akrites.Symbol{File: file, Line: locationLine(f.Location)}
}

// locationLine returns the line from a "path:line[:col]" or "path:start-end"
// location, or 0 when it names none.
func locationLine(location string) int {
	loc := strings.TrimSpace(strings.Split(strings.TrimSpace(location), "\n")[0])
	line := 0
	for {
		i := strings.LastIndexByte(loc, ':')
		if i < 0 || !findingnorm.IsPositionalSuffix(loc[i+1:]) {
			return line
		}
		start, _, _ := strings.Cut(loc[i+1:], "-")
		line, _ = strconv.Atoi(start)
		loc = loc[:i]
	}
}

func akritesEligibility(ctx disclosureFindingContext) error {
	if db.FindingDisclosureBlocked(ctx.Finding) {
		return db.ErrFindingNonViable
	}
	if strings.TrimSpace(ctx.Finding.DisclosureDraft) == "" {
		return fmt.Errorf("a reviewed disclosure draft is required before Akrites submission")
	}
	switch ctx.Finding.Status {
	case db.FindingReported, db.FindingAcknowledged, db.FindingFixed, db.FindingPublished, db.FindingRejected, db.FindingDuplicate:
		return fmt.Errorf("finding status %q cannot be submitted to Akrites", ctx.Finding.Status)
	}
	for _, note := range ctx.Notes {
		first, _, _ := strings.Cut(note.Body, "\n")
		if strings.HasPrefix(strings.TrimSpace(first), "finding-dedup: subsumed by finding #") {
			return fmt.Errorf("this finding is subsumed by another finding")
		}
	}
	return nil
}

// akritesAttachments sends the disclosure draft and the exploitation details
// as attachments. Their filenames, descriptions and types are stored in the
// clear at Akrites, so they carry no finding detail.
func akritesAttachments(disclosure, exploit string) []akrites.Attachment {
	var out []akrites.Attachment
	if strings.TrimSpace(disclosure) != "" {
		out = append(out, akrites.Attachment{Filename: "disclosure.md", Data: disclosure, ContentType: "text/markdown", Description: "Disclosure report", Type: "other"})
	}
	if strings.TrimSpace(exploit) != "" {
		out = append(out, akrites.Attachment{Filename: "exploit.txt", Data: exploit, ContentType: "text/plain", Description: "Exploitation details", Type: "exploit-proof-of-concept"})
	}
	return out
}

func akritesPageFromForm(r *http.Request, finding db.Finding) akritesPage {
	page := akritesPage{Finding: finding, Disclosure: r.FormValue("raw"), Exploit: r.FormValue("exploit")}
	page.Report = akrites.Report{
		Software: strings.TrimSpace(r.FormValue("software")), PURL: strings.TrimSpace(r.FormValue("purl")),
		Ecosystem:       strings.TrimSpace(r.FormValue("ecosystem")),
		Attachments:     akritesAttachments(page.Disclosure, page.Exploit),
		PackageRepoURL:  strings.TrimSpace(r.FormValue("package_repo_url")),
		DiscoveryMethod: strings.TrimSpace(r.FormValue("discovery_method")), Email: strings.TrimSpace(r.FormValue("email")), Notify: r.FormValue("notify"),
	}
	symbol := akrites.Symbol{File: strings.TrimSpace(r.FormValue("symbol_file")), Function: strings.TrimSpace(r.FormValue("symbol_function"))}
	if line := strings.TrimSpace(r.FormValue("symbol_line")); line != "" {
		n, err := strconv.Atoi(line)
		if err != nil {
			n = -1
		}
		symbol.Line = n
	}
	if symbol != (akrites.Symbol{}) {
		page.Report.AffectedSymbol = &symbol
	}
	for v := range strings.SplitSeq(r.FormValue("versions"), "\n") {
		if v = strings.TrimSpace(v); v != "" {
			page.Report.Versions = append(page.Report.Versions, v)
		}
	}
	return page
}

func (s *Server) findingAkritesSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.Akrites.Enabled() {
		http.NotFound(w, r)
		return
	}
	// URL-encoded forms can expand each byte to three bytes.
	const formEncodingExpansion = 3
	r.Body = http.MaxBytesReader(w, r.Body, formEncodingExpansion*akrites.MaxBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid or oversized form", http.StatusBadRequest)
		return
	}
	s.vinceSubmitMu.Lock()
	defer s.vinceSubmitMu.Unlock()
	ctx, ok := s.loadDisclosureFinding(w, r)
	if !ok {
		return
	}
	if err := akritesEligibility(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	page := akritesPageFromForm(r, ctx.Finding)
	endpoint, err := s.Akrites.Endpoint()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	page.Endpoint = endpoint
	renderError := func(status int, message string) {
		page.Error = message
		w.WriteHeader(status)
		s.render(w, r, "finding_akrites.html", map[string]any{"Akrites": page})
	}
	if strings.TrimSpace(page.Disclosure) == "" {
		renderError(http.StatusUnprocessableEntity, "a disclosure report is required")
		return
	}
	if _, err := page.Report.JSON(); err != nil {
		renderError(http.StatusUnprocessableEntity, err.Error())
		return
	}
	if r.FormValue("confirm") != "yes" || r.FormValue("endpoint") != endpoint {
		renderError(http.StatusUnprocessableEntity, "confirm the recipient and reviewed report before submitting")
		return
	}
	claims, err := s.claimPeerHold(r.Context(), ctx.Finding)
	if err != nil {
		renderError(http.StatusInternalServerError, "failed to check federation peers")
		return
	}
	if claims != "" {
		renderError(http.StatusConflict, "A federation peer holds this finding: "+claims+". Coordinate through that contact before submitting again.")
		return
	}
	// Reserve before POST so a crash or another server cannot submit it twice.
	submission := db.AkritesSubmission{FindingID: ctx.Finding.ID, Endpoint: endpoint, Status: "uncertain"}
	if err := s.DB.Create(&submission).Error; err != nil {
		http.Error(w, "could not reserve submission; check the existing Akrites submission before retrying", http.StatusConflict)
		return
	}
	client := akrites.Client{Config: s.Akrites, HTTPClient: s.akritesHTTPClient}
	receipt, err := client.Submit(r.Context(), page.Report)
	if err != nil {
		s.akritesSubmitError(w, r, &page, submission, err)
		return
	}
	next := time.Now().Add(akritesPollInitial)
	saved := s.DB.Model(&submission).Updates(map[string]any{"receipt": receipt, "status": "queued", "next_poll_at": next})
	if saved.Error != nil || saved.RowsAffected != 1 {
		page.Submission = submission
		page.Submission.Receipt = receipt
		page.Submission.Status = "uncertain"
		page.Submission.NextPollAt = nil
		renderError(http.StatusInternalServerError, "Akrites accepted the report, but the receipt could not be saved. Record the receipt below and reconcile with Akrites. Do not resubmit.")
		return
	}
	if err := s.persistAkritesOutreach(ctx.Finding.ID); err != nil {
		page.Submission = submission
		renderError(http.StatusInternalServerError, "The receipt is saved, but the finding status could not be updated. Review the finding manually. Do not resubmit.")
		return
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d/akrites", ctx.Finding.ID))
}

// akritesSubmitError releases the reservation when intake definitely stored
// nothing, so the analyst's edits stay on the form for correction or a later
// retry. An ambiguous failure keeps the reservation and blocks another POST.
func (s *Server) akritesSubmitError(w http.ResponseWriter, r *http.Request, page *akritesPage, submission db.AkritesSubmission, err error) {
	status := http.StatusBadGateway
	page.Error = err.Error()
	var response *akrites.ResponseError
	if errors.As(err, &response) && !response.Ambiguous {
		if response.Validation() {
			status = http.StatusUnprocessableEntity
		}
		if response.RetryAfter > 0 {
			page.Error += fmt.Sprintf(". Akrites asked for a delay; submit again after %s.", time.Now().Add(response.RetryAfter).UTC().Format(time.RFC3339))
		}
		if deleteErr := s.DB.Delete(&submission).Error; deleteErr == nil {
			w.WriteHeader(status)
			s.render(w, r, "finding_akrites.html", map[string]any{"Akrites": page})
			return
		}
	}
	page.Submission = submission
	page.Submission.LastError = err.Error()
	if saveErr := s.DB.Save(&page.Submission).Error; saveErr != nil {
		page.Submission.Status = "uncertain"
	}
	w.WriteHeader(status)
	s.render(w, r, "finding_akrites.html", map[string]any{"Akrites": page})
}

func (s *Server) persistAkritesOutreach(findingID uint) error {
	return db.FindingWriteTransaction(s.DB, findingID, func(tx *gorm.DB) error {
		if _, err := db.AddFindingCommunication(tx, findingID, "akrites", "outbound", "Akrites", "Submitted a vulnerability report to Akrites. Receipt and intake status are available on the Akrites submission page.", "", time.Now()); err != nil {
			return err
		}
		return db.WriteFindingField(tx, findingID, "status", string(db.FindingReported), db.SourceSystem, "akrites")
	})
}
