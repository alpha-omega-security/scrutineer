package web

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
	"scrutineer/internal/testutil"
	"scrutineer/internal/worker"
)

// testGit runs git under testutil.GitEnv so the host's global git config
// cannot leak into the temp repositories these tests create. A trace2
// listener that writes refs/notes/* into observed repos, or a global
// commit.gpgsign, otherwise changes commit counts and breaks peer commits.
func testGit(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Env = testutil.GitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func feedTime(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
}

// seedFeedRepo creates a repository with a disclosure route already
// stamped, which is what routeRecords requires to publish it.
func seedFeedRepo(t *testing.T, s *Server, url, channel string) db.Repository {
	t.Helper()
	at := feedTime(t)
	repo := db.Repository{URL: url, Name: filepath.Base(url), DisclosureChannel: channel}
	if channel != "" {
		repo.DisclosureChannelAt = &at
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func seedAudit(t *testing.T, s *Server, repoID uint, uuid, status string) {
	t.Helper()
	if err := s.DB.Create(&db.AdvisoryAudit{
		RepositoryID: repoID, AdvisoryUUID: uuid, Status: status, CreatedAt: feedTime(t),
	}).Error; err != nil {
		t.Fatal(err)
	}
}

func mustRepoIDs(t *testing.T, s *Server) map[string]uint {
	t.Helper()
	ids, err := s.repoIDsByCanonicalURL()
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func recordKindCounts(recs []interchange.Statement) map[string]int {
	out := map[string]int{}
	for _, rec := range recs {
		out[rec.PredicateType]++
	}
	return out
}

// initBareRemote creates an empty bare repository usable as a feed remote.
func initBareRemote(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	testGit(t, "init", "--quiet", "--bare", dir)
	return dir
}

func remoteCommitCount(t *testing.T, remote string) int {
	t.Helper()
	// --branches, not --all: --all counts refs/notes/* and refs/tags/* too, so
	// anything that adds a stray ref to the bare remote would inflate the
	// count these tests assert on.
	out := testGit(t, "-C", remote, "rev-list", "--count", "--branches")
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("unexpected rev-list output %q: %v", out, err)
	}
	return n
}

func TestValidateFeedRemote(t *testing.T) {
	for _, ok := range []string{
		"https://github.com/org/feed.git",
		"git@github.com:org/feed.git",
		"ssh://git@github.com/org/feed.git",
		"/srv/feeds/public.git",
	} {
		if err := ValidateFeedRemote(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []struct{ remote, secret string }{
		// A token as the username is the common PAT spelling and the remote
		// reaches the log on every pass, so it is refused like a password.
		{"https://ghp_secret@github.com/org/feed.git", "ghp_secret"},
		{"https://x-access-token:ghp_secret@github.com/org/feed.git", "ghp_secret"},
		{"user:pw@github.com:org/feed.git", "user:pw"},
	} {
		err := ValidateFeedRemote(bad.remote)
		if err == nil {
			t.Errorf("%q embeds credentials and must be refused", bad.remote)
			continue
		}
		// The refusal is what the fatal logger prints at startup, so it must
		// not carry the very token the check exists to keep out of the log.
		if strings.Contains(err.Error(), bad.secret) {
			t.Errorf("the refusal for %q leaks the credential: %v", bad.remote, err)
		}
		if !strings.Contains(err.Error(), "github.com") {
			t.Errorf("the refusal for %q must still name the remote: %v", bad.remote, err)
		}
	}
}

func TestFeedRecords_publicTier(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	routed := seedFeedRepo(t, s, "https://github.com/acme/routed", "security@acme.example")
	seedAudit(t, s, routed.ID, "uuid-clean", "fixed")
	seedAudit(t, s, routed.ID, "uuid-broken", "bypass")

	optedOut := seedFeedRepo(t, s, "https://github.com/acme/quiet", "security@quiet.example")
	at := feedTime(t)
	s.DB.Model(&db.Repository{}).Where("id = ?", optedOut.ID).Update("federation_opt_out_at", &at)
	seedAudit(t, s, optedOut.ID, "uuid-quiet", "fixed")

	recs, err := s.feedRecords(interchange.TierPublic)
	if err != nil {
		t.Fatal(err)
	}
	counts := recordKindCounts(recs)
	if counts[interchange.PredicateTypeOptOut] != 1 {
		t.Errorf("expected 1 optout record, got %d", counts[interchange.PredicateTypeOptOut])
	}
	if counts[interchange.PredicateTypeRoute] != 1 {
		t.Errorf("expected only the non-opted-out route, got %d", counts[interchange.PredicateTypeRoute])
	}
	if counts[interchange.PredicateTypeCertificate] != 1 {
		t.Errorf("expected only the clean certificate of the non-opted-out repo, got %d", counts[interchange.PredicateTypeCertificate])
	}
	if counts[interchange.PredicateTypeCertificateV2] != 0 {
		t.Errorf("a non-clean certificate must never appear on the public tier, got %d", counts[interchange.PredicateTypeCertificateV2])
	}
}

func TestFeedRecords_membersTierCarriesOnlyNonCleanCertificates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "security@acme.example")
	seedAudit(t, s, repo.ID, "uuid-clean", "fixed")
	seedAudit(t, s, repo.ID, "uuid-bypass", "bypass")
	seedAudit(t, s, repo.ID, "uuid-variant", "variant")

	// A repository whose maintainer opted out must stay off this tier too:
	// a certificate/v2 names a live unfixed weakness in it.
	optedOut := seedFeedRepo(t, s, "https://github.com/acme/quiet", "")
	at := feedTime(t)
	s.DB.Model(&db.Repository{}).Where("id = ?", optedOut.ID).Update("federation_opt_out_at", &at)
	seedAudit(t, s, optedOut.ID, "uuid-quiet", "regressed")

	recs, err := s.feedRecords(interchange.TierMembers)
	if err != nil {
		t.Fatal(err)
	}
	counts := recordKindCounts(recs)
	if counts[interchange.PredicateTypeCertificateV2] != 2 {
		t.Errorf("expected the 2 non-clean certificates of the non-opted-out repo, got %d", counts[interchange.PredicateTypeCertificateV2])
	}
	if len(recs) != 2 {
		t.Errorf("the members tier must carry certificates only, got %d records", len(recs))
	}
}

// The members query filters on the verdicts certificate/v2 accepts rather
// than on "not fixed", so this list has to stay in step with the db enum:
// a new verdict must be added to both or the export silently stops
// publishing it.
func TestCertificateStatusesV2_matchesTheAuditEnum(t *testing.T) {
	want := make([]string, 0, len(db.AdvisoryAuditStatuses))
	for status := range db.AdvisoryAuditStatuses {
		if status != interchange.CertificateStatusFixed {
			want = append(want, status)
		}
	}
	slices.Sort(want)
	if got := interchange.CertificateStatusesV2(); !slices.Equal(got, want) {
		t.Fatalf("CertificateStatusesV2() = %v, want %v (from db.AdvisoryAuditStatuses)", got, want)
	}
}

func TestFeedRecords_skipsLocalReposAndUnstampedRoutes(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	local := db.Repository{URL: LocalScheme + "/home/analyst/work/lib", Name: "lib", DisclosureChannel: "me@example.com"}
	at := feedTime(t)
	local.DisclosureChannelAt = &at
	s.DB.Create(&local)
	seedAudit(t, s, local.ID, "uuid-local", "fixed")

	// A channel written before disclosure_channel_at existed has no
	// verified_at to publish, so it stays off the feed instead of being
	// stamped with a timestamp that would move on every export.
	legacy := db.Repository{URL: "https://github.com/acme/legacy", Name: "legacy", DisclosureChannel: "security@legacy.example"}
	s.DB.Create(&legacy)

	recs, err := s.feedRecords(interchange.TierPublic)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no publishable records, got %+v", recs)
	}
}

func TestCertificateRecords_newestVerdictWins(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	seedAudit(t, s, repo.ID, "uuid-1", "fixed")
	seedAudit(t, s, repo.ID, "uuid-1", "regressed")

	public, err := s.certificateRecords(interchange.TierPublic)
	if err != nil {
		t.Fatal(err)
	}
	if len(public) != 0 {
		t.Errorf("a superseded clean verdict must not stay on the public feed, got %+v", public)
	}
	members, err := s.certificateRecords(interchange.TierMembers)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("expected the newest verdict only, got %d records", len(members))
	}
}

// Nothing enforces uniqueness on (repository_id, uuid) and the url is
// optional, so the grouped subselect must not answer "no URL" for an advisory
// one of whose duplicate rows carries a real one.
func TestCertificateRecords_prefersANonEmptyAdvisoryURL(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	seedAudit(t, s, repo.ID, "uuid-1", "fixed")
	for _, url := range []string{"", "https://osv.dev/GHSA-xxxx"} {
		if err := s.DB.Create(&db.Advisory{RepositoryID: repo.ID, UUID: "uuid-1", URL: url}).Error; err != nil {
			t.Fatal(err)
		}
	}

	recs, err := s.certificateRecords(interchange.TierPublic)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected one certificate, got %d", len(recs))
	}
	var p interchange.CertificatePredicate
	if err := interchange.DecodePredicate(recs[0], &p); err != nil {
		t.Fatal(err)
	}
	if p.AdvisoryURL != "https://osv.dev/GHSA-xxxx" {
		t.Errorf("advisory_url = %q, want the non-empty duplicate", p.AdvisoryURL)
	}
}

func TestExportFeed_publishesThenNoOps(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "security@acme.example")
	seedAudit(t, s, repo.ID, "uuid-clean", "fixed")

	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}
	if got := remoteCommitCount(t, remote); got != 1 {
		t.Fatalf("expected 1 commit after the first export, got %d", got)
	}
	clone := filepath.Join(s.Worker.DataDir, "feeds", "public")
	records, err := interchange.ReadFeed(clone, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected the route and the certificate on the feed, got %d", len(records))
	}

	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}
	if got := remoteCommitCount(t, remote); got != 1 {
		t.Fatalf("an unchanged feed must not produce a second commit, got %d", got)
	}
}

// The sync has to actually reset onto the remote, not just skip: a peer or a
// second instance pushing between ticks must not leave this one exporting
// from a diverged clone forever.
func TestExportFeed_picksUpAThirdPartyCommit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "security@acme.example")
	seedAudit(t, s, repo.ID, "uuid-clean", "fixed")
	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}

	// A third party adds a README to the feed repository.
	work := t.TempDir()
	run := func(args ...string) { testGit(t, append([]string{"-C", work}, args...)...) }
	run("clone", "--quiet", remote, ".")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("peer feed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "--quiet", "-m", "readme")
	run("push", "--quiet", "origin", "HEAD")

	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(s.Worker.DataDir, "feeds", "public")
	if _, err := os.Stat(filepath.Join(clone, "README.md")); err != nil {
		t.Fatalf("the export clone must have been reset onto the remote: %v", err)
	}
	if got := remoteCommitCount(t, remote); got != 2 {
		t.Fatalf("an unchanged record set must add no commit on top of the peer's, got %d", got)
	}
}

// A clean working tree says the records match this clone's HEAD, never that
// the remote has that commit. An operator who recreates the feed repository
// (wrong remote first time, a wipe and retry) must not leave the tier silently
// publishing nothing for the life of the process.
func TestExportFeed_republishesOntoARecreatedRemote(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "security@acme.example")
	seedAudit(t, s, repo.ID, "uuid-clean", "fixed")
	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}

	// The remote is wiped back to an empty repository under the running
	// instance, whose clone still holds the published commit.
	if err := os.RemoveAll(remote); err != nil {
		t.Fatal(err)
	}
	testGit(t, "init", "--quiet", "--bare", remote)

	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}
	if got := remoteCommitCount(t, remote); got == 0 {
		t.Fatal("a recreated remote must be republished, not left empty forever")
	}
}

// An operator repointing federation_public_feed at a new remote must have the
// feed follow: nothing but this rewrites the working clone's origin, so the
// job would keep publishing to the remote the clone was first made against
// while the newly configured one stays empty with nothing saying why.
func TestExportFeed_followsAChangedRemote(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	seedFeedRepo(t, s, "https://github.com/acme/routed", "security@acme.example")

	old := initBareRemote(t)
	if err := s.exportFeed(context.Background(), interchange.TierPublic, old); err != nil {
		t.Fatal(err)
	}
	moved := initBareRemote(t)
	if err := s.exportFeed(context.Background(), interchange.TierPublic, moved); err != nil {
		t.Fatal(err)
	}
	if remoteCommitCount(t, moved) == 0 {
		t.Error("the newly configured remote must receive the feed")
	}
	if n := remoteCommitCount(t, old); n != 1 {
		t.Errorf("the abandoned remote must stop receiving pushes, got %d commits", n)
	}
}

func TestExportFeed_membersTierIsEncrypted(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s.EncRecipients = []age.Recipient{id.Recipient()}
	s.EncIdentities = []age.Identity{id}
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	seedAudit(t, s, repo.ID, "uuid-bypass", "bypass")

	if err := s.exportFeed(context.Background(), interchange.TierMembers, remote); err != nil {
		t.Fatal(err)
	}
	// age re-encrypts under a fresh key each call, so without the
	// plaintext comparison every tick would push a full rewrite forever.
	if err := s.exportFeed(context.Background(), interchange.TierMembers, remote); err != nil {
		t.Fatal(err)
	}
	if got := remoteCommitCount(t, remote); got != 1 {
		t.Fatalf("an unchanged members feed must not produce a second commit, got %d", got)
	}
	clone := filepath.Join(s.Worker.DataDir, "feeds", "members")
	if records, err := interchange.ReadFeed(clone, nil); err != nil {
		t.Fatal(err)
	} else if len(records) != 1 || records[0].Err == nil {
		t.Fatalf("the members feed must be unreadable without an identity: %+v", records)
	}
	records, err := interchange.ReadFeed(clone, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one decryptable record, got %+v", records)
	}
}

func TestExportFeed_membersTierWithoutRecipientsFails(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	seedAudit(t, s, repo.ID, "uuid-bypass", "bypass")

	if err := s.exportFeed(context.Background(), interchange.TierMembers, remote); err == nil {
		t.Fatal("publishing non-clean certificates without recipients must fail")
	}
	if got := remoteCommitCount(t, remote); got != 0 {
		t.Fatalf("nothing must have been pushed, got %d commits", got)
	}
}

// publishPeerFeed writes recs to a bare remote by way of a throwaway
// export, giving the import tests a real peer feed to pull from.
func publishPeerFeed(t *testing.T, recs []interchange.Statement) string {
	t.Helper()
	return publishPeerFeedWithRaw(t, recs, nil)
}

// publishPeerFeedWithRaw is publishPeerFeed plus feed-relative files written
// verbatim, for the record files only a broken or hostile peer publishes.
func publishPeerFeedWithRaw(t *testing.T, recs []interchange.Statement, raw map[string]string) string {
	t.Helper()
	remote := initBareRemote(t)
	pushPeerFeed(t, remote, recs, raw)
	return remote
}

// pushPeerFeed rewrites an existing peer remote to exactly recs, which is how
// a test publishes a peer's correction of a record it has already published.
func pushPeerFeed(t *testing.T, remote string, recs []interchange.Statement, raw map[string]string) {
	t.Helper()
	work := t.TempDir()
	testGit(t, "clone", "--quiet", remote, work)
	run := func(args ...string) { testGit(t, append([]string{"-C", work}, args...)...) }
	if err := interchange.WriteFeed(work, interchange.TierPublic, recs, interchange.FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	for name, body := range raw {
		path := filepath.Join(work, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "--all", ".")
	run("commit", "--quiet", "-m", "feed")
	run("push", "--quiet", "origin", "HEAD")
}

func TestImportFeed_storesRecordsAndAppliesOptOut(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository:  "https://github.com/ACME/lib.git",
			RequestedAt: feedTime(t),
			Reason:      "please stop",
		}),
	})

	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var rows []db.InterchangeRecord
	if err := s.DB.Where("feed = ?", remote).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].PredicateType != interchange.PredicateTypeOptOut {
		t.Fatalf("expected the opt-out stored verbatim, got %+v", rows)
	}
	// The column is documented as the record as published, so it must be
	// the peer's own bytes: same as what sits on the feed clone.
	onFeed, err := interchange.ReadFeed(filepath.Join(s.Worker.DataDir, "feeds", "import", feedDirName(remote)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(onFeed) != 1 || strings.TrimSpace(string(onFeed[0].Raw)) != strings.TrimSpace(rows[0].Record) {
		t.Fatalf("stored record is not the published bytes:\n%s\n---\n%s", onFeed[0].Raw, rows[0].Record)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.FederationOptOutAt == nil {
		t.Fatal("a peer opt-out must apply even when the URL differs in case and .git suffix")
	}
	if got.FederationOptOutReason != "please stop" {
		t.Errorf("reason = %q", got.FederationOptOutReason)
	}
}

func TestImportFeed_routeOnlyFillsAnEmptyChannel(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	empty := seedFeedRepo(t, s, "https://github.com/acme/empty", "")
	owned := seedFeedRepo(t, s, "https://github.com/acme/owned", "analyst@example.com")
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewRoute(interchange.RoutePredicate{
			Repository: "https://github.com/acme/empty", Channel: "peer@example.com", VerifiedAt: feedTime(t),
		}),
		interchange.NewRoute(interchange.RoutePredicate{
			Repository: "https://github.com/acme/owned", Channel: "peer@example.com", VerifiedAt: feedTime(t),
		}),
	})

	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var filled db.Repository
	s.DB.First(&filled, empty.ID)
	if !strings.HasPrefix(filled.DisclosureChannel, "peer@example.com") {
		t.Errorf("an imported route must fill an empty channel, got %q", filled.DisclosureChannel)
	}
	// The channel is where a GHSA draft gets mailed, so an analyst has to be
	// able to see it came from a peer rather than a verified SECURITY.md.
	if !strings.Contains(filled.DisclosureChannel, "(via "+remote+")") {
		t.Errorf("an imported channel must name the feed it came from, got %q", filled.DisclosureChannel)
	}
	// An imported hint is not a route this instance validated, and the peer
	// feed remote it is annotated with may name an internal host or a path on
	// this operator's disk. Leaving disclosure_channel_at unset is what keeps
	// the whole string off the public feed until an analyst adopts it.
	if filled.DisclosureChannelAt != nil {
		t.Errorf("an imported channel must not be stamped, got %v", filled.DisclosureChannelAt)
	}
	routes, err := s.routeRecords()
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range routes {
		var p interchange.RoutePredicate
		if err := interchange.DecodePredicate(rec, &p); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(p.Channel, "(via ") {
			t.Errorf("an imported route must not be republished as this instance's own, got %q", p.Channel)
		}
	}
	var kept db.Repository
	s.DB.First(&kept, owned.ID)
	if kept.DisclosureChannel != "analyst@example.com" {
		t.Errorf("an imported route must never overwrite a local channel, got %q", kept.DisclosureChannel)
	}
}

// A peer publishes an opt-out for every repository they hold, most of which
// this operator does not track yet. The record is archived on the first pass
// with nothing to apply it to, so closing it there would mean the opt-out is
// never honoured for a repository imported afterwards, while its own record
// sits in this instance's database.
func TestImportFeed_optOutAppliesToARepositoryImportedLater(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository: "https://github.com/acme/later", RequestedAt: feedTime(t), Reason: "please stop",
		}),
	})
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var row db.InterchangeRecord
	if err := s.DB.Where("feed = ?", remote).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.AppliedAt != nil {
		t.Fatalf("a record with no local repository must stay open, got applied_at %v", row.AppliedAt)
	}

	repo := seedFeedRepo(t, s, "https://github.com/acme/later", "")
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.FederationOptOutAt == nil {
		t.Error("the opt-out must apply once the repository it names exists here")
	}
	if got.FederationOptOutReason != "please stop" {
		t.Errorf("reason = %q", got.FederationOptOutReason)
	}
	s.DB.First(&row, row.ID)
	if row.AppliedAt == nil {
		t.Error("an applied record must be stamped so the next pass leaves it alone")
	}
}

// One unreadable file from a peer must not cost the rest of the feed: the
// peer controls these bytes, and a whole skipped import would take the
// opt-outs down with the bad record.
func TestImportFeed_skipsAnUnreadableRecordAndKeepsTheRest(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	remote := publishPeerFeedWithRaw(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository: "https://github.com/acme/lib", RequestedAt: feedTime(t),
		}),
	}, map[string]string{
		// Sorts before the good record's own digest-named file, so a parser
		// that gave up on the first failure would skip the opt-out too.
		"optout/" + strings.Repeat("0", 64) + ".json": "{not json",
	})

	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatalf("one bad file must not fail the whole import: %v", err)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.FederationOptOutAt == nil {
		t.Error("the valid opt-out published alongside the bad file must still apply")
	}
	var stored int64
	s.DB.Model(&db.InterchangeRecord{}).Where("feed = ?", remote).Count(&stored)
	if stored != 1 {
		t.Errorf("only the readable record must be archived, got %d rows", stored)
	}
}

func TestImportFeed_keepsOneRowPerPeer(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	rec := interchange.NewOptOut(interchange.OptOutPredicate{
		Repository: "https://github.com/acme/lib", RequestedAt: feedTime(t),
	})
	for _, remote := range []string{publishPeerFeed(t, []interchange.Statement{rec}), publishPeerFeed(t, []interchange.Statement{rec})} {
		if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
			t.Fatal(err)
		}
		// Re-importing the same feed must refresh its row, not add one.
		if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	s.DB.Model(&db.InterchangeRecord{}).Count(&count)
	if count != 2 {
		t.Fatalf("expected one row per peer for the same subject, got %d", count)
	}
}

func TestImportFeed_unchangedRecordIsNotReapplied(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository: "https://github.com/acme/lib", RequestedAt: feedTime(t),
		}),
	})
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	// An operator who clears an imported opt-out must not have it silently
	// reinstated on the next tick from a record the peer has not touched.
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("federation_opt_out_at", nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.FederationOptOutAt != nil {
		t.Fatal("an unchanged record must not be re-applied")
	}
}

// An imported opt-out carries the same request as one recorded on the repo
// page, so it has to stop the work already under way and not merely refuse
// the next enqueue: the scans queued on this repository would otherwise run
// against a maintainer who has asked every federated instance to stop. Only
// the queued and paused rows are asserted here, since newTestServer's worker
// has nothing running; the in-flight branch is the worker package's.
func TestImportFeed_optOutStopsTheScansAlreadyQueued(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	queued := seedScan(t, s, repo.ID, db.ScanQueued)
	paused := seedScan(t, s, repo.ID, db.ScanPaused)
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository: "https://github.com/acme/lib", RequestedAt: feedTime(t),
		}),
	})

	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]uint{"queued": queued.ID, "paused": paused.ID} {
		got := reloadScan(t, s, id)
		if got.Status != db.ScanCancelled {
			t.Errorf("%s scan status = %q, want %q", name, got.Status, db.ScanCancelled)
		}
		if got.Error != worker.OptOutCancelReason {
			t.Errorf("%s scan error = %q, want %q", name, got.Error, worker.OptOutCancelReason)
		}
	}
}

// A peer that corrects a route it already published must have the correction
// take effect. The changed bytes re-open the record, and the address sitting
// on the repository is this same feed's own unstamped hint, so it is the one
// thing an import is allowed to overwrite; without that the correction is
// archived and stamped while the superseded address keeps receiving drafts.
func TestImportFeed_peerCorrectsItsOwnRoute(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	adopted := seedFeedRepo(t, s, "https://github.com/acme/adopted", "")
	route := func(url, channel string, at time.Time) interchange.Statement {
		return interchange.NewRoute(interchange.RoutePredicate{Repository: url, Channel: channel, VerifiedAt: at})
	}
	remote := publishPeerFeed(t, []interchange.Statement{
		route("https://github.com/acme/lib", "old@example.com", feedTime(t)),
		route("https://github.com/acme/adopted", "old@example.com", feedTime(t)),
	})
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	// An analyst who has checked the hint adopts it, which stamps it. From
	// there it is this instance's own confirmed route and the peer no longer
	// gets to move it.
	at := feedTime(t)
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", adopted.ID).
		Update("disclosure_channel_at", &at).Error; err != nil {
		t.Fatal(err)
	}

	pushPeerFeed(t, remote, []interchange.Statement{
		route("https://github.com/acme/lib", "new@example.com", feedTime(t).Add(time.Hour)),
		route("https://github.com/acme/adopted", "new@example.com", feedTime(t).Add(time.Hour)),
	}, nil)
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}

	var corrected db.Repository
	s.DB.First(&corrected, repo.ID)
	if corrected.DisclosureChannel != "new@example.com"+viaFeed(remote) {
		t.Errorf("channel = %q, want the peer's correction", corrected.DisclosureChannel)
	}
	if corrected.DisclosureChannelAt != nil {
		t.Errorf("a corrected hint is still a hint and must stay unstamped, got %v", corrected.DisclosureChannelAt)
	}
	var kept db.Repository
	s.DB.First(&kept, adopted.ID)
	if kept.DisclosureChannel != "old@example.com"+viaFeed(remote) {
		t.Errorf("a stamped channel is the analyst's and must survive the peer's correction, got %q", kept.DisclosureChannel)
	}
}

// The federation lock covers the opt-out flag, not disclosure_channel: the
// repo page and the maintainers skill both write that column without taking
// it. So the import's write has to be conditional on the channel its decision
// was taken against, or an address an analyst saves between the read and the
// write is silently replaced by a peer's hint and left unstamped, on the one
// column that decides where an unpublished draft gets mailed.
//
// The interleaving is forced rather than raced: a one-shot GORM update
// callback commits the analyst's edit in the window under test, so this fails
// on an unconditional write every run.
func TestImportFeed_routeDoesNotClobberAConcurrentLocalEdit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewRoute(interchange.RoutePredicate{
			Repository: "https://github.com/acme/lib", Channel: "peer@example.com", VerifiedAt: feedTime(t),
		}),
	})

	var once sync.Once
	const callback = "test:analyst_edits_channel_mid_import"
	if err := s.DB.Callback().Update().Before("gorm:update").Register(callback, func(d *gorm.DB) {
		if d.Statement.Table != "repositories" {
			return
		}
		once.Do(func() {
			at := feedTime(t)
			if err := s.DB.Exec("UPDATE repositories SET disclosure_channel = ?, disclosure_channel_at = ? WHERE id = ?",
				"analyst@acme.example", at, repo.ID).Error; err != nil {
				t.Error(err)
			}
		})
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.DB.Callback().Update().Remove(callback) }()

	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.DisclosureChannel != "analyst@acme.example" {
		t.Errorf("channel = %q, want the analyst's edit to survive the import", got.DisclosureChannel)
	}
	if got.DisclosureChannelAt == nil {
		t.Error("the analyst's stamp must survive too, or the peer keeps ownership of the channel")
	}
	// Losing the write leaves the record open on purpose: the next pass reads
	// what is actually stored and closes it against that instead of guessing.
	var row db.InterchangeRecord
	if err := s.DB.Where("feed = ?", remote).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.AppliedAt != nil {
		t.Error("a route that lost the write must stay open for the next pass to decide again")
	}

	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	s.DB.First(&got, repo.ID)
	if got.DisclosureChannel != "analyst@acme.example" {
		t.Errorf("channel = %q, want the stamped local channel to outrank the peer hint on the retry", got.DisclosureChannel)
	}
	var closed db.InterchangeRecord
	if err := s.DB.First(&closed, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if closed.AppliedAt == nil {
		t.Error("the retry must close the record rather than retry it forever")
	}
}

// A clean tree over a remote that already carries this clone's HEAD is the
// no-op case, and a re-clone (fresh data directory, cleared workspace) must
// reach it too. Reporting no tracking ref there reads as "nothing local has
// reached the remote" and pushes, logging a publication that never happened.
func TestFeedClone_freshCloneKnowsTheRemoteAlreadyHasIt(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()
	remote := initBareRemote(t)

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "security@acme.example")
	seedAudit(t, s, repo.ID, "uuid-clean", "fixed")
	if err := s.exportFeed(context.Background(), interchange.TierPublic, remote); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(s.Worker.DataDir, "feeds", "public")); err != nil {
		t.Fatal(err)
	}

	dir, tracking, err := s.feedClone(context.Background(), "public", remote)
	if err != nil {
		t.Fatal(err)
	}
	if tracking == "" {
		t.Fatal("a fresh clone of a populated remote must report the branch's remote-tracking ref")
	}
	pushed, err := commitAndPushFeed(context.Background(), dir, tracking, "scrutineer: public feed")
	if err != nil {
		t.Fatal(err)
	}
	if pushed {
		t.Error("a re-cloned feed that already matches the remote must not report a publication")
	}
}

// An opt-out stamped against a repository row means that row carries it, so
// deleting the row has to re-open the record. Otherwise a repository removed
// and re-added comes back scannable while the peer's request still stands on
// the feed and in this instance's own archive.
func TestRepoDelete_reopensTheRecordsAppliedToIt(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	remote := publishPeerFeed(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository: "https://github.com/acme/lib", RequestedAt: feedTime(t), Reason: "please stop",
		}),
	})
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var row db.InterchangeRecord
	if err := s.DB.Where("feed = ?", remote).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.AppliedRepositoryID != repo.ID {
		t.Fatalf("applied_repository_id = %d, want the repository the stamp was written against (%d)", row.AppliedRepositoryID, repo.ID)
	}

	if _, err := s.deleteRepository(repo); err != nil {
		t.Fatal(err)
	}
	// Reloaded into a fresh struct: First leaves an already-populated pointer
	// field alone when the column comes back NULL, which is exactly the value
	// under test here.
	var reopened db.InterchangeRecord
	if err := s.DB.First(&reopened, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reopened.AppliedAt != nil || reopened.AppliedRepositoryID != 0 {
		t.Fatalf("deleting the repository must re-open the record, got applied_at %v against repository %d",
			reopened.AppliedAt, reopened.AppliedRepositoryID)
	}

	readded := seedFeedRepo(t, s, "https://github.com/acme/lib", "")
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var got db.Repository
	s.DB.First(&got, readded.ID)
	if got.FederationOptOutAt == nil {
		t.Error("a re-added repository must pick the peer's still-standing opt-out back up")
	}
}

func TestSetDisclosureChannel_stampsOnlyOnChange(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedFeedRepo(t, s, "https://github.com/acme/lib", "")

	if err := db.SetDisclosureChannel(s.DB, repo.ID, "security@acme.example"); err != nil {
		t.Fatal(err)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.DisclosureChannelAt == nil {
		t.Fatal("a new channel must be stamped")
	}
	stamped := *got.DisclosureChannelAt

	if err := db.SetDisclosureChannel(s.DB, repo.ID, "security@acme.example"); err != nil {
		t.Fatal(err)
	}
	s.DB.First(&got, repo.ID)
	if !got.DisclosureChannelAt.Equal(stamped) {
		t.Errorf("an unchanged re-write must not move the timestamp the route record publishes")
	}

	// The channel the caller compares against is the stored one, not a row it
	// loaded earlier: a scan that started an hour ago holds a stale snapshot,
	// and a stamp skipped there would publish the new channel under the old
	// verified_at.
	if err := db.SetDisclosureChannel(s.DB, repo.ID, "moved@acme.example"); err != nil {
		t.Fatal(err)
	}
	s.DB.First(&got, repo.ID)
	if got.DisclosureChannelAt.Equal(stamped) {
		t.Error("a changed channel must move the timestamp")
	}
}

// One pass has to honour an opt-out it just imported. Exporting first would
// publish the disclosure route of a repository the peer has said not to
// contact, and leave it on the public feed until the next tick an hour later.
func TestRunFederation_importsBeforeExporting(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker.DataDir = t.TempDir()

	seedFeedRepo(t, s, "https://github.com/acme/quiet", "security@acme.example")
	s.FederationImportFeeds = []string{publishPeerFeed(t, []interchange.Statement{
		interchange.NewOptOut(interchange.OptOutPredicate{
			Repository: "https://github.com/acme/quiet", RequestedAt: feedTime(t), Reason: "please stop",
		}),
	})}
	s.FederationPublicFeed = initBareRemote(t)

	s.runFederation(context.Background())

	published, err := interchange.ReadFeed(filepath.Join(s.Worker.DataDir, "feeds", "public"), nil)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, rec := range published {
		if rec.Err != nil {
			t.Fatalf("record %s: %v", rec.Path, rec.Err)
		}
		kinds[rec.Statement.PredicateType]++
	}
	if kinds[interchange.PredicateTypeRoute] != 0 {
		t.Errorf("the route of a repository that opted out this pass must not be published, got %d", kinds[interchange.PredicateTypeRoute])
	}
	if kinds[interchange.PredicateTypeOptOut] != 1 {
		t.Errorf("expected the imported opt-out relayed on the public feed, got %d", kinds[interchange.PredicateTypeOptOut])
	}
}

func TestStartFederation_returnsWithoutConfiguration(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	// No feed configured: the job must not tick, and above all must not
	// block the goroutine main starts it on.
	stopped := make(chan struct{})
	go func() {
		s.StartFederation(context.Background())
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("StartFederation must return immediately when no feed is configured")
	}
}
