package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/vince"
	"scrutineer/internal/worker"
)

// peerServer stands in for a federation peer's POST /claim-check.
func peerServer(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/claim-check" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func seedReadyFinding(t *testing.T, s *Server) db.Finding {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/acme/lib", Name: "lib"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Title: "sqli", Severity: "High",
		Status: db.FindingReady, CWE: "CWE-89", Location: "src/db.go:42",
	}
	s.DB.Create(&f)
	return f
}

func postFindingStatus(t *testing.T, s *Server, id uint, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return postForm(t, s, "/findings/"+strconv.FormatUint(uint64(id), 10)+"/status", form)
}

func reloadFinding(t *testing.T, s *Server, id uint) db.Finding {
	t.Helper()
	var f db.Finding
	if err := s.DB.First(&f, id).Error; err != nil {
		t.Fatal(err)
	}
	return f
}

func TestValidatePeerURL(t *testing.T) {
	for _, ok := range []string{"https://peer.example.com", "http://127.0.0.1:8080", "https://peer.example.com/scrutineer"} {
		if err := ValidatePeerURL(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "peer.example.com", "file:///etc/passwd", "ftp://peer.example.com", "https://",
		// Credentials would be sent on every click and logged when the peer
		// is down; a query or fragment would swallow the /claim-check path.
		"https://user:token@peer.example.com",
		"https://peer.example.com?tenant=1",
		"https://peer.example.com#frag",
	} {
		if err := ValidatePeerURL(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestAskPeerClaim_appendsToThePeerPath(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"match":false}`))
	}))
	defer srv.Close()

	if _, _, err := askPeerClaim(t.Context(), srv.URL+"/scrutineer", strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	if got != "/scrutineer/claim-check" {
		t.Errorf("posted to %q, want the endpoint appended to the peer's path", got)
	}
}

func TestPeerClaims(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"match", http.StatusOK, `{"match":true,"contact":"peer@example.com"}`, true},
		{"miss", http.StatusOK, `{"match":false}`, false},
		{"peer not federated", http.StatusNotFound, "not found", false},
		{"peer erroring", http.StatusInternalServerError, "boom", false},
		{"peer answering garbage", http.StatusOK, "{not json", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			s.FederationSalt = testFederationSalt
			s.FederationPeers = []string{peerServer(t, tc.status, tc.body)}
			f := seedReadyFinding(t, s)

			claims, err := s.peerClaims(t.Context(), f)
			if err != nil {
				t.Fatalf("a peer answering badly must not be a local error: %v", err)
			}
			if got := claims != ""; got != tc.want {
				t.Fatalf("peerClaims = %q, want a claim: %v", claims, tc.want)
			}
			if tc.want && claims != s.FederationPeers[0]+" (peer@example.com)" {
				t.Errorf("claim must name the peer and its contact, got %q", claims)
			}
		})
	}
}

func TestPeerClaims_dormantWithoutPeersOrSalt(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedReadyFinding(t, s)
	peer := peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)

	claims, err := s.peerClaims(t.Context(), f)
	if err != nil || claims != "" {
		t.Errorf("no peers configured must mean no claim, got %q / %v", claims, err)
	}
	s.FederationPeers = []string{peer}
	claims, err = s.peerClaims(t.Context(), f)
	if err != nil || claims != "" {
		t.Errorf("without the shared salt the hash cannot match, so no claim must be reported, got %q / %v", claims, err)
	}
}

// A local failure must not read as "nobody claims it": that would open the
// gate on exactly the runs where it could not be evaluated.
func TestPeerClaims_localFailureIsAnError(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	f := seedReadyFinding(t, s)
	f.RepositoryID = 999999

	if _, err := s.peerClaims(t.Context(), f); err == nil {
		t.Fatal("a repository that cannot be loaded must be reported as an error")
	}
}

func TestFindingStatus_claimGateFailureDoesNotReport(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":false}`)}
	f := seedReadyFinding(t, s)
	// A finding pointing at a repository row that cannot be read cannot be
	// hashed, so the gate must refuse rather than let the transition through
	// unchecked. Repointing rather than deleting: the repository cascade
	// would take the finding with it.
	if err := s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).
		Update("repository_id", 999999).Error; err != nil {
		t.Fatal(err)
	}

	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"reported"}}); w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500. body=%s", w.Code, w.Body)
	}
	if got := reloadFinding(t, s, f.ID); got.Status != db.FindingReady {
		t.Fatalf("status = %q, want ready", got.Status)
	}
}

func TestFindingStatus_peerClaimBlocksReported(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	peer := peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)
	s.FederationPeers = []string{peer}
	f := seedReadyFinding(t, s)

	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"reported"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	blocked := reloadFinding(t, s, f.ID)
	if blocked.Status != db.FindingReady {
		t.Fatalf("a claimed finding must stay ready, got %q", blocked.Status)
	}
	if blocked.FederationClaimContacts == "" || blocked.FederationClaimAt == nil {
		t.Fatalf("the claim must be recorded for the banner: %q / %v", blocked.FederationClaimContacts, blocked.FederationClaimAt)
	}

	// The finding page names the contact to coordinate through.
	page := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/findings/"+strconv.FormatUint(uint64(f.ID), 10), nil)
	req.Host = testHost
	s.Handler().ServeHTTP(page, req)
	if !strings.Contains(page.Body.String(), "peer@example.com") {
		t.Error("the finding page must surface the peer contact")
	}

	// The recorded claim is the acknowledgement: a second submit goes
	// through, no extra form field needed.
	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"reported"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	acked := reloadFinding(t, s, f.ID)
	if acked.Status != db.FindingReported {
		t.Fatalf("acknowledging the claim must let the transition through, got %q", acked.Status)
	}
	if acked.FederationClaimContacts != "" || acked.FederationClaimAt != nil {
		t.Errorf("a completed transition must clear the claim: %q / %v", acked.FederationClaimContacts, acked.FederationClaimAt)
	}
}

// A peer must not be able to aim this instance's own POST at its loopback
// admin API by answering the claim-check with a redirect.
func TestAskPeerClaim_doesNotFollowRedirects(t *testing.T) {
	var reached string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = r.URL.Path
	}))
	defer target.Close()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/repositories/1/delete", http.StatusTemporaryRedirect)
	}))
	defer peer.Close()

	_, matched, err := askPeerClaim(t.Context(), peer.URL, strings.Repeat("ab", 32))
	if err == nil {
		t.Fatal("a redirected claim-check must be reported as an error, not followed")
	}
	if matched {
		t.Error("a redirect must never read as a match")
	}
	if reached != "" {
		t.Fatalf("the redirect was followed to %q", reached)
	}
}

// report-upstream files with the maintainer and only then PATCHes the
// status, so the gate has to sit at enqueue: refusing the later write would
// leave the outreach done and the finding stuck.
func TestEnqueueOutreachSkill_refusedWhileAPeerHoldsTheFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	f := seedReadyFinding(t, s)
	skill := db.Skill{Name: "report-upstream", Active: true}
	s.DB.Create(&skill)

	_, err := s.enqueueSkillScoped(t.Context(), f.RepositoryID, skill.ID, &f.ID, "")
	if !errors.Is(err, ErrFederationClaimPending) {
		t.Fatalf("expected ErrFederationClaimPending, got %v", err)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Where("skill_id = ?", skill.ID).Count(&scans)
	if scans != 0 {
		t.Fatalf("a refused enqueue must create no scan row, got %d", scans)
	}
	held := reloadFinding(t, s, f.ID)
	if held.FederationClaimContacts == "" {
		t.Fatal("the claim must be recorded so the page names the contact")
	}

	// Recorded claim = acknowledged, so running it again goes through.
	if _, err := s.enqueueSkillScoped(t.Context(), f.RepositoryID, skill.ID, &f.ID, ""); err != nil {
		t.Fatalf("second attempt must proceed: %v", err)
	}
}

func TestEnqueueNonOutreachSkill_neverConsultsPeers(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}
	f := seedReadyFinding(t, s)
	skill := db.Skill{Name: "verify", Active: true}
	s.DB.Create(&skill)

	if _, err := s.enqueueSkillScoped(t.Context(), f.RepositoryID, skill.ID, &f.ID, ""); err != nil {
		t.Fatalf("a skill that contacts nobody must not be gated: %v", err)
	}
	if got := reloadFinding(t, s, f.ID); got.FederationClaimContacts != "" {
		t.Errorf("no claim should have been recorded, got %q", got.FederationClaimContacts)
	}
}

func TestFindingStatus_unclaimedFindingReportsNormally(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":false}`)}
	f := seedReadyFinding(t, s)

	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"reported"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := reloadFinding(t, s, f.ID); got.Status != db.FindingReported {
		t.Fatalf("status = %q, want reported", got.Status)
	}
}

func TestFindingStatus_gateOnlyAppliesToReported(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	peer, asked := countingPeerServer(t)
	s.FederationPeers = []string{peer}
	f := seedReadyFinding(t, s)

	if w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"rejected"}, "verdict": {"false_positive"}, "reason": {"guarded"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := reloadFinding(t, s, f.ID); got.Status != db.FindingRejected {
		t.Fatalf("status = %q, want rejected", got.Status)
	}
	if asked.Load() != 0 {
		t.Errorf("a transition that reports nothing asked the peers %d times", asked.Load())
	}
}

// The enqueue gate is the mirror of the status handler's: a finding no first
// report can follow has nothing left to deduplicate, and both outreach skills
// stand down on those statuses themselves, so a claim recorded here would
// never be cleared.
func TestEnqueueOutreachSkill_notGatedWhenNoFirstReportCanFollow(t *testing.T) {
	for _, status := range []db.FindingLifecycle{
		db.FindingReported, db.FindingAcknowledged, db.FindingFixed,
		db.FindingPublished, db.FindingRejected, db.FindingDuplicate,
	} {
		t.Run(string(status), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			s.FederationSalt = testFederationSalt
			peer, asked := countingPeerServer(t)
			s.FederationPeers = []string{peer}
			f := seedReadyFinding(t, s)
			if err := s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).
				Update("status", status).Error; err != nil {
				t.Fatal(err)
			}
			skill := db.Skill{Name: "report-upstream", Active: true}
			s.DB.Create(&skill)

			if _, err := s.enqueueSkillScoped(t.Context(), f.RepositoryID, skill.ID, &f.ID, ""); err != nil {
				t.Fatalf("enqueue on a %q finding must not be gated: %v", status, err)
			}
			if asked.Load() != 0 {
				t.Errorf("peers asked %d times about a %q finding", asked.Load(), status)
			}
			if got := reloadFinding(t, s, f.ID); got.FederationClaimContacts != "" {
				t.Errorf("a claim was recorded that nothing would ever clear: %q", got.FederationClaimContacts)
			}
		})
	}
}

// TestFindingVINCE_peerClaimBlocksSubmission covers the third route to
// reported: a peer holding the finding refuses the submission before the
// VINCE request is built, and the recorded claim lets the second attempt
// through, exactly like the analyst's own transition.
func TestFindingVINCE_peerClaimBlocksSubmission(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`)}

	var requests atomic.Int32
	vinceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"vrf_id":"VRF#26-07-ABCDE"}`)
	}))
	defer vinceSrv.Close()
	s.VINCE = vince.Config{BaseURL: vinceSrv.URL, APIKey: "secret"}

	path := fmt.Sprintf("/findings/%d/vince", ctx.Finding.ID)
	w := postForm(t, s, path, validVINCEWebForm())
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body)
	}
	if requests.Load() != 0 {
		t.Fatalf("VINCE requests = %d, want none before the claim is acknowledged", requests.Load())
	}
	if !strings.Contains(w.Body.String(), "peer@example.com") {
		t.Errorf("page must name the peer contact to coordinate with: %s", w.Body)
	}
	blocked := reloadFinding(t, s, ctx.Finding.ID)
	if blocked.FederationClaimContacts == "" || blocked.FederationClaimAt == nil {
		t.Fatalf("claim not recorded: %+v", blocked)
	}
	if blocked.Status != db.FindingReady {
		t.Errorf("status = %q, want ready", blocked.Status)
	}

	w = postForm(t, s, path, validVINCEWebForm())
	if w.Code != http.StatusSeeOther {
		t.Fatalf("second attempt status = %d, want 303: %s", w.Code, w.Body)
	}
	if requests.Load() != 1 {
		t.Errorf("VINCE requests = %d, want exactly 1", requests.Load())
	}
	sent := reloadFinding(t, s, ctx.Finding.ID)
	if sent.Status != db.FindingReported {
		t.Errorf("status = %q, want reported", sent.Status)
	}
	if sent.FederationClaimContacts != "" || sent.FederationClaimAt != nil {
		t.Errorf("claim must be cleared once the submission carried the finding to reported: %+v", sent)
	}
}

// TestFindingVINCE_unclaimedFindingSubmitsNormally is the happy path of the
// same gate: peers configured, nobody claiming, so the submission is not
// held up and no claim is recorded.
func TestFindingVINCE_unclaimedFindingSubmitsNormally(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	s.FederationSalt = testFederationSalt
	s.FederationPeers = []string{peerServer(t, http.StatusOK, `{"match":false}`)}

	vinceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"vrf_id":"VRF#26-07-ABCDE"}`)
	}))
	defer vinceSrv.Close()
	s.VINCE = vince.Config{BaseURL: vinceSrv.URL, APIKey: "secret"}

	w := postForm(t, s, fmt.Sprintf("/findings/%d/vince", ctx.Finding.ID), validVINCEWebForm())
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303: %s", w.Code, w.Body)
	}
	got := reloadFinding(t, s, ctx.Finding.ID)
	if got.Status != db.FindingReported {
		t.Errorf("status = %q, want reported", got.Status)
	}
	if got.FederationClaimContacts != "" {
		t.Errorf("no peer claimed it, yet a claim was recorded: %q", got.FederationClaimContacts)
	}
}

// countingPeerServer answers every claim-check with a miss and counts what it
// was asked, so a test can assert a peer was never contacted at all.
func countingPeerServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var asked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = io.WriteString(w, `{"match":false}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &asked
}

func TestPeerClaims_silentForRepositoriesTheFeedsNeverPublish(t *testing.T) {
	for name, prepare := range map[string]func(*Server, db.Finding){
		"opted out": func(s *Server, f db.Finding) {
			optedOut := time.Now().UTC()
			if err := s.DB.Model(&db.Repository{}).Where("id = ?", f.RepositoryID).
				Update("federation_opt_out_at", &optedOut).Error; err != nil {
				t.Fatal(err)
			}
		},
		"local": func(s *Server, f db.Finding) {
			if err := s.DB.Model(&db.Repository{}).Where("id = ?", f.RepositoryID).
				Update("url", "file:///srv/checkouts/lib").Error; err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			s.FederationSalt = testFederationSalt
			peer, asked := countingPeerServer(t)
			s.FederationPeers = []string{peer}
			f := seedReadyFinding(t, s)
			prepare(s, f)

			claims, err := s.peerClaims(t.Context(), f)
			if err != nil {
				t.Fatalf("peerClaims: %v", err)
			}
			if claims != "" {
				t.Errorf("claims = %q, want none", claims)
			}
			if asked.Load() != 0 {
				t.Errorf("peer asked %d times about a repository the feeds never publish", asked.Load())
			}
		})
	}
}

// A peer that never answers must not eat the whole round's deadline: the claim
// the reachable peer holds still has to come back.
func TestPeerClaims_oneHangingPeerDoesNotHideAnother(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	block := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer func() { close(block); hanging.Close() }()
	s.FederationPeers = []string{
		hanging.URL,
		peerServer(t, http.StatusOK, `{"match":true,"contact":"peer@example.com"}`),
	}
	f := seedReadyFinding(t, s)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	claims, err := s.peerClaims(ctx, f)
	if err != nil {
		t.Fatalf("peerClaims: %v", err)
	}
	if !strings.Contains(claims, "peer@example.com") {
		t.Errorf("claims = %q, want the reachable peer's contact", claims)
	}
}

func recordClaim(t *testing.T, s *Server, id uint) {
	t.Helper()
	claimedAt := time.Now().UTC()
	if err := s.DB.Model(&db.Finding{}).Where("id = ?", id).Updates(map[string]any{
		"federation_claim_contacts": "https://peer.example.com (peer@example.com)",
		"federation_claim_at":       &claimedAt,
	}).Error; err != nil {
		t.Fatal(err)
	}
}

// Clearing lives in WriteFindingField, so the paths that report without going
// through the status handler (an outreach skill's PATCH, the worker) clear the
// banner too. Every status change clears, not just the one to reported: the
// coordination the contacts describe belongs to the transition they were
// recorded for.
func TestWriteFindingStatus_anyChangeClearsTheClaim(t *testing.T) {
	for _, status := range []db.FindingLifecycle{db.FindingReported, db.FindingRejected, db.FindingDuplicate, db.FindingTriaged} {
		t.Run(string(status), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f := seedReadyFinding(t, s)
			recordClaim(t, s, f.ID)

			if err := db.WriteFindingField(s.DB, f.ID, statusKey, string(status), db.SourceSystem, "report-upstream"); err != nil {
				t.Fatal(err)
			}
			got := reloadFinding(t, s, f.ID)
			if got.FederationClaimContacts != "" || got.FederationClaimAt != nil {
				t.Errorf("claim survived the move to %s: %q / %v", status, got.FederationClaimContacts, got.FederationClaimAt)
			}
		})
	}
}

// A write that is not the status leaves the claim alone: the banner has to
// stay up while the analyst edits the finding and coordinates with the peer.
func TestWriteFindingField_nonStatusWriteKeepsTheClaim(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedReadyFinding(t, s)
	recordClaim(t, s, f.ID)

	if err := db.WriteFindingField(s.DB, f.ID, "assignee", "alice", db.SourceSystem, "test"); err != nil {
		t.Fatal(err)
	}
	got := reloadFinding(t, s, f.ID)
	if got.FederationClaimContacts == "" || got.FederationClaimAt == nil {
		t.Errorf("claim cleared by an unrelated field: %q / %v", got.FederationClaimContacts, got.FederationClaimAt)
	}
}

// The claim is an acknowledgement of one coordination round, so a finding
// rejected rather than reported and later reopened is asked about again
// instead of the old contacts reading as a standing acknowledgement.
func TestClaimPeerHold_reopenedAfterRejectAsksPeersAgain(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = testFederationSalt
	var asked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = io.WriteString(w, `{"match":true,"contact":"peer@example.com"}`)
	}))
	defer srv.Close()
	s.FederationPeers = []string{srv.URL}
	f := seedReadyFinding(t, s)

	claims, err := s.claimPeerHold(t.Context(), f)
	if err != nil {
		t.Fatalf("claimPeerHold: %v", err)
	}
	if claims == "" {
		t.Fatal("first round recorded no claim")
	}
	for _, status := range []db.FindingLifecycle{db.FindingRejected, db.FindingReady} {
		if err := db.WriteFindingField(s.DB, f.ID, statusKey, string(status), db.SourceSystem, "analyst"); err != nil {
			t.Fatal(err)
		}
	}

	if claims, err = s.claimPeerHold(t.Context(), reloadFinding(t, s, f.ID)); err != nil {
		t.Fatalf("claimPeerHold after reopen: %v", err)
	}
	if claims == "" {
		t.Error("the reopened finding went through on the rejected round's claim")
	}
	if asked.Load() != 2 {
		t.Errorf("peer asked %d times, want one round per report attempt", asked.Load())
	}
}
