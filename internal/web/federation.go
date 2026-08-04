package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/git-pkgs/clone"
	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
)

// federationTick is how often the export and import feed jobs run. Feeds
// carry slow-moving records (a disclosure route, an opt-out, a fix-audit
// verdict), so an hour keeps peers usefully fresh without a git push per
// scan; the export skips the push entirely when nothing changed.
const federationTick = time.Hour

// feedCommitter identifies the export job's commits. Feed clones are
// scrutineer-owned working copies and the host may have no git identity
// configured at all, so the identity is passed per invocation rather than
// read from global config. Signing is turned off for the same reason: a host
// with commit.gpgsign set globally would fail every export commit, since
// there is no key for the scrutineer identity and no prompt to answer under
// GIT_TERMINAL_PROMPT=0.
var feedCommitter = []string{
	"-c", "user.name=scrutineer",
	"-c", "user.email=scrutineer@localhost",
	"-c", "commit.gpgsign=false",
}

// feedDirPerm is the mode of the feed working-clone directories under the
// data directory.
const feedDirPerm = 0o755

// StartFederation runs the interchange feed jobs until ctx is cancelled,
// starting with one immediate pass so an operator who has just configured
// a feed sees it populated without waiting out a tick. It returns straight
// away when no feed is configured.
func (s *Server) StartFederation(ctx context.Context) {
	if s.FederationPublicFeed == "" && s.FederationMembersFeed == "" && len(s.FederationImportFeeds) == 0 {
		return
	}
	s.runFederation(ctx)
	t := time.NewTicker(federationTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runFederation(ctx)
		}
	}
}

// runFederation imports before it exports. An opt-out that lands this pass
// withdraws its repository from the route and certificate records, so
// exporting first would keep publishing the disclosure route of a repository
// a peer has just said not to contact for another whole tick.
func (s *Server) runFederation(ctx context.Context) {
	s.importFeeds(ctx)
	for _, feed := range []struct {
		tier   interchange.Tier
		remote string
	}{
		{interchange.TierPublic, s.FederationPublicFeed},
		{interchange.TierMembers, s.FederationMembersFeed},
	} {
		if feed.remote == "" {
			continue
		}
		if err := s.exportFeed(ctx, feed.tier, feed.remote); err != nil {
			s.Log.Error("federation: export feed", "tier", feed.tier, "err", err)
		}
	}
}

func (s *Server) importFeeds(ctx context.Context) {
	if len(s.FederationImportFeeds) == 0 {
		return
	}
	// The URL index is immutable, so it is built once for the whole pass
	// rather than re-reading the repositories table per feed.
	repoIDs, err := s.repoIDsByCanonicalURL()
	if err != nil {
		s.Log.Error("federation: index repositories", "err", err)
		return
	}
	for _, remote := range s.FederationImportFeeds {
		if err := s.importFeed(ctx, remote, repoIDs); err != nil {
			s.Log.Error("federation: import feed", "remote", remote, "err", err)
		}
	}
}

// exportFeed republishes one tier: sync the working clone, rewrite it to
// exactly the records this instance currently stands behind, then commit
// and push if that changed anything. Rewriting rather than appending is
// what makes a withdrawn opt-out or a re-audited certificate disappear
// from the feed instead of sitting next to its replacement.
func (s *Server) exportFeed(ctx context.Context, tier interchange.Tier, remote string) error {
	dir, tracking, err := s.feedClone(ctx, string(tier), remote)
	if err != nil {
		return err
	}
	recs, err := s.feedRecords(tier)
	if err != nil {
		return err
	}
	var keys interchange.FeedKeys
	if tier == interchange.TierMembers {
		keys = interchange.FeedKeys{Recipients: s.EncRecipients, Identities: s.EncIdentities}
	}
	if err := interchange.WriteFeed(dir, tier, recs, keys); err != nil {
		return err
	}
	pushed, err := commitAndPushFeed(ctx, dir, tracking, fmt.Sprintf("scrutineer: %s feed, %d records", tier, len(recs)))
	if err != nil {
		return err
	}
	if pushed {
		s.Log.Info("federation: published feed", "tier", tier, "records", len(recs))
	}
	return nil
}

// publishableRepo narrows a query to the repositories whose URL may appear
// in a record. A local (file://) URL is a path on the operator's own
// filesystem, and an empty one canonicalises to a value the schema refuses,
// which would abort the whole export over a single unusable row.
// Qualified so it reads the same in the certificate query, which joins, and
// built from LocalScheme so it cannot drift from what marks a row local.
const publishableRepo = "repositories.url != '' AND repositories.url NOT LIKE '" + LocalScheme + "%'"

// feedRecords builds every record this instance publishes on a tier.
// Opted-out repositories are excluded from route and certificate records as
// well as scanning: an opt-out asks federated instances not to contact the
// maintainer, and republishing their disclosure route works against that.
func (s *Server) feedRecords(tier interchange.Tier) ([]interchange.Statement, error) {
	var out []interchange.Statement
	if tier == interchange.TierPublic {
		optOuts, err := s.optOutRecords()
		if err != nil {
			return nil, err
		}
		routes, err := s.routeRecords()
		if err != nil {
			return nil, err
		}
		out = append(out, optOuts...)
		out = append(out, routes...)
	}
	certs, err := s.certificateRecords(tier)
	if err != nil {
		return nil, err
	}
	return append(out, certs...), nil
}

func (s *Server) optOutRecords() ([]interchange.Statement, error) {
	var rows []db.Repository
	if err := s.DB.Select("url, federation_opt_out_at, federation_opt_out_reason").
		Where(db.FederationHasOptedOut).Where(publishableRepo).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]interchange.Statement, 0, len(rows))
	for _, r := range rows {
		out = append(out, interchange.NewOptOut(interchange.OptOutPredicate{
			Repository:  r.URL,
			RequestedAt: r.FederationOptOutAt.UTC(),
			Reason:      r.FederationOptOutReason,
		}))
	}
	return out, nil
}

// routeRecords publishes the validated disclosure route of every
// repository that has one. A repository whose channel predates
// disclosure_channel_at is skipped rather than stamped with a made-up
// verified_at: the record's timestamp has to be the one that only moves
// when the channel does, or every export would rewrite the whole feed.
func (s *Server) routeRecords() ([]interchange.Statement, error) {
	var rows []db.Repository
	if err := s.DB.Select("url, disclosure_channel, disclosure_channel_at").
		Where("disclosure_channel != '' AND disclosure_channel_at IS NOT NULL").
		Where(db.FederationNotOptedOut).Where(publishableRepo).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]interchange.Statement, 0, len(rows))
	for _, r := range rows {
		out = append(out, interchange.NewRoute(interchange.RoutePredicate{
			Repository: r.URL,
			Channel:    r.DisclosureChannel,
			VerifiedAt: r.DisclosureChannelAt.UTC(),
		}))
	}
	return out, nil
}

// certificateRecords publishes the newest fix-audit verdict per
// (repository, advisory), split by tier: the clean "fixed" verdicts are
// certificate/v1 records for the public feed, the bypass/variant/regressed
// ones certificate/v2 records for the encrypted members feed, since each
// of those names a repository whose advertised fix does not hold.
func (s *Server) certificateRecords(tier interchange.Tier) ([]interchange.Statement, error) {
	type row struct {
		URL         string
		AdvisoryURL string
		Advisory    string
		Status      string
		Commit      string
		CreatedAt   time.Time
	}
	// The advisories join goes through a grouped subselect: nothing enforces
	// uniqueness on (repository_id, uuid) and parseAdvisoriesOutput inserts
	// whatever the report listed, so a plain join would fan out and publish
	// the same subject twice with an advisory_url picked by row order.
	// NULLIF before the MIN: a URL is optional on an advisory row, and the
	// empty string sorts first, so the plain aggregate would answer "no URL"
	// for a uuid one of whose duplicates carries a real one.
	q := s.DB.Model(&db.AdvisoryAudit{}).
		Select("repositories.url, advisories.url AS advisory_url, advisory_audits.advisory_uuid AS advisory, advisory_audits.status, advisory_audits.`commit`, advisory_audits.created_at").
		Joins("JOIN repositories ON repositories.id = advisory_audits.repository_id").
		Joins("LEFT JOIN (SELECT repository_id, uuid, MIN(NULLIF(url, '')) AS url FROM advisories GROUP BY repository_id, uuid) advisories"+
			" ON advisories.repository_id = advisory_audits.repository_id AND advisories.uuid = advisory_audits.advisory_uuid").
		Where("advisory_audits.id IN (?)", s.DB.Model(&db.AdvisoryAudit{}).
			Select("MAX(id)").Group("repository_id, advisory_uuid")).
		Where(db.FederationNotOptedOut).
		Where(publishableRepo).
		Where("advisory_audits.advisory_uuid != ''")
	// Filtered to the verdicts each revision's schema accepts, rather than
	// "everything that is not fixed": an unexpected status would otherwise
	// reach certificate/v2, fail validation, and abort the whole export.
	if tier == interchange.TierPublic {
		q = q.Where("advisory_audits.status = ?", interchange.CertificateStatusFixed)
	} else {
		q = q.Where("advisory_audits.status IN ?", interchange.CertificateStatusesV2())
	}
	var rows []row
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]interchange.Statement, 0, len(rows))
	for _, r := range rows {
		out = append(out, interchange.NewCertificate(interchange.CertificatePredicate{
			Repository:  r.URL,
			Advisory:    r.Advisory,
			AdvisoryURL: r.AdvisoryURL,
			Status:      r.Status,
			Commit:      r.Commit,
			AuditedAt:   r.CreatedAt.UTC(),
		}))
	}
	return out, nil
}

// importFeed pulls one peer feed and ingests it. Every record is stored
// verbatim; opt-outs and routes additionally apply to the matching local
// repository, which is the whole point of importing them, and stay open
// until they have been. A record that fails to decrypt, validate or decode
// is logged and skipped so one bad file from a peer does not cost the rest
// of the feed.
func (s *Server) importFeed(ctx context.Context, remote string, repoIDs map[string]uint) error {
	dir, _, err := s.feedClone(ctx, filepath.Join("import", feedDirName(remote)), remote)
	if err != nil {
		return err
	}
	records, err := interchange.ReadFeed(dir, s.EncIdentities)
	if err != nil {
		return err
	}
	var stored, applied, failed int
	for _, rec := range records {
		if rec.Err != nil {
			s.Log.Warn("federation: skipping record", "remote", remote, "path", rec.Path, "err", rec.Err)
			failed++
			continue
		}
		row, err := s.storeImportedRecord(remote, rec)
		if err != nil {
			s.Log.Error("federation: store record", "remote", remote, "path", rec.Path, "err", err)
			failed++
			continue
		}
		stored++
		if row.AppliedAt != nil {
			continue
		}
		// The stamp is what closes a record, so it is written only once the
		// record has actually been acted on: an apply that fails, or one whose
		// repository this instance does not track yet, leaves the row open and
		// the next pass tries again. Advancing on the archive write alone would
		// drop a maintainer's opt-out on a single transient failure, and would
		// never honour one published before its repository was imported here.
		repoID, done, err := s.applyImportedRecord(rec.Statement, repoIDs, remote)
		if err != nil {
			s.Log.Error("federation: apply record", "remote", remote, "path", rec.Path, "err", err)
			failed++
			continue
		}
		if !done {
			continue
		}
		// The repository the stamp was written against is recorded with it, so
		// deleting that repository re-opens the record instead of leaving a
		// stamp that names a row nothing carries any more.
		if err := s.DB.Model(&db.InterchangeRecord{}).Where("id = ?", row.ID).
			UpdateColumns(map[string]any{"applied_at": time.Now().UTC(), "applied_repository_id": repoID}).Error; err != nil {
			s.Log.Error("federation: stamp record", "remote", remote, "path", rec.Path, "err", err)
			failed++
			continue
		}
		applied++
	}
	// failed counts every record this pass could not carry through, apply
	// errors included: a feed whose every apply fails must not read as a clean
	// import that merely had nothing to do.
	s.Log.Info("federation: imported feed", "remote", remote, "stored", stored, "applied", applied, "failed", failed)
	return nil
}

// storeImportedRecord archives the peer's own bytes and returns the stored
// row. Bytes that differ from the archived ones clear applied_at so the
// caller re-applies the correction; identical bytes keep the stamp, since an
// unchanged record has already had its effect and re-applying it every hour
// would silently undo an operator who cleared what a peer once asked for.
func (s *Server) storeImportedRecord(remote string, rec interchange.FeedRecord) (db.InterchangeRecord, error) {
	row := db.InterchangeRecord{
		Feed:          remote,
		PredicateType: rec.Statement.PredicateType,
		SubjectDigest: rec.Statement.Subject[0].Digest["sha256"],
	}
	var existing db.InterchangeRecord
	res := s.DB.Where(&row).Limit(1).Find(&existing)
	if res.Error != nil {
		return db.InterchangeRecord{}, res.Error
	}
	now, raw := time.Now().UTC(), string(rec.Raw)
	if res.RowsAffected == 0 {
		row.Record, row.ReceivedAt = raw, now
		// Created before the return rather than inside it: Create fills row.ID,
		// which the caller stamps against, and the order in which a return
		// statement reads a plain operand next to a call is unspecified.
		if err := s.DB.Create(&row).Error; err != nil {
			return db.InterchangeRecord{}, err
		}
		return row, nil
	}
	if existing.Record == raw {
		return existing, s.DB.Model(&existing).UpdateColumn("received_at", now).Error
	}
	existing.Record, existing.ReceivedAt, existing.AppliedAt = raw, now, nil
	return existing, s.DB.Model(&existing).
		Updates(map[string]any{"record": raw, "received_at": now, "applied_at": nil}).Error
}

// applyImportedRecord mirrors a peer's opt-out or disclosure route onto the
// matching local repository. An opt-out is honoured whichever peer sent it,
// since refusing to scan is the conservative direction; a route is only
// taken when this instance has none of its own and the repository has not
// opted out, so an imported hint neither overwrites what the maintainers
// skill or the analyst established here nor routes outreach to a maintainer
// who asked not to be contacted.
//
// The repository row is re-read per record rather than taken from the URL
// index: an opt-out applied earlier in the same pass (opt-outs sort before
// routes) has already changed the columns this decision turns on.
//
// It reports the repository the record was applied to, zero for the kinds
// that act on nothing local, and whether the record is closed. Not closed
// means the subject names no repository this instance tracks, so the caller
// leaves the row open for a later pass: a peer publishing an opt-out before
// this operator imports the repository must not have it silently forgotten.
// The kinds that apply to nothing local (certificates, claims) are closed on
// sight.
func (s *Server) applyImportedRecord(rec interchange.Statement, repoIDs map[string]uint, feed string) (uint, bool, error) {
	switch rec.PredicateType {
	case interchange.PredicateTypeOptOut:
		var p interchange.OptOutPredicate
		if err := interchange.DecodePredicate(rec, &p); err != nil {
			return 0, false, err
		}
		repo, unlock, ok, err := s.repoForRecord(repoIDs, p.Repository)
		defer unlock()
		if err != nil || !ok {
			return 0, false, err
		}
		// An opt-out already recorded here keeps its own request date, which is
		// what a peer is told the request was made on; only the sweep below is
		// worth redoing, since reaching this line means no earlier pass closed
		// the record and its sweep may be the step that failed.
		if !repo.FederationOptedOut() {
			at := p.RequestedAt.UTC()
			if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Updates(map[string]any{
				"federation_opt_out_at":     &at,
				"federation_opt_out_reason": p.Reason,
			}).Error; err != nil {
				return 0, false, err
			}
		}
		// Same order as the repo page's own handler: the flag commits first, so
		// no scan is enqueued behind the sweep, then the work already under way
		// is stopped. An imported opt-out is the same maintainer's request, so
		// it has to stop this instance's scans too and not merely refuse the
		// next one.
		return repo.ID, true, s.stopScansForOptOut(repo.ID)
	case interchange.PredicateTypeRoute:
		var p interchange.RoutePredicate
		if err := interchange.DecodePredicate(rec, &p); err != nil {
			return 0, false, err
		}
		repo, unlock, ok, err := s.repoForRecord(repoIDs, p.Repository)
		defer unlock()
		if err != nil || !ok {
			return 0, false, err
		}
		if repo.FederationOptedOut() || !replaceableRoute(repo, feed) {
			return repo.ID, true, nil
		}
		// The channel is where an unpublished GHSA draft and patch get
		// mailed, so an imported one says where it came from: an analyst must
		// be able to tell a peer's hint from an address the maintainers skill
		// read out of a verified SECURITY.md. Same convention as cna-match,
		// which appends the CNA's organization name.
		//
		// disclosure_channel_at is cleared rather than set to the peer's
		// verified_at: that timestamp is what routeRecords publishes, so
		// keeping it would re-export a hint this instance never validated as
		// its own confirmed route, peer feed remote and all, and make one
		// peer's claim look like two independent ones. The channel goes back
		// on the feed once an analyst changes it, which stamps it here.
		//
		// Conditional on the channel the decision above was taken against:
		// the federation lock covers the opt-out flag, but disclosure_channel
		// is written outside it by the repo page and the maintainers skill, so
		// an unconditional write would drop an address an analyst saved
		// between the read and here, on the one column that decides where an
		// unpublished draft gets mailed. Zero rows means someone else owns the
		// channel now, so the record stays open and the next pass decides
		// again on what is actually stored.
		res := s.DB.Model(&db.Repository{}).Where("id = ? AND disclosure_channel = ?", repo.ID, repo.DisclosureChannel).
			Updates(map[string]any{
				"disclosure_channel":    strings.TrimSpace(p.Channel) + viaFeed(feed),
				"disclosure_channel_at": nil,
			})
		if res.Error != nil {
			return 0, false, res.Error
		}
		return repo.ID, res.RowsAffected > 0, nil
	}
	return 0, true, nil
}

// viaFeed is the provenance suffix an imported channel carries, and the only
// handle on where a channel came from once it is a plain string.
func viaFeed(feed string) string { return " (via " + feed + ")" }

// replaceableRoute reports whether an imported route may write over the
// repository's current channel. An empty channel is free, and so is the
// unstamped hint this same feed left on an earlier pass, which is exactly
// what a peer's correction has to replace: without that, the corrected
// record is archived and stamped while the superseded address stays in place.
// Anything else is left alone. A stamped channel came from the maintainers
// skill or an analyst and outranks any peer hint, and another feed's hint is
// another peer's claim, not this one's to overwrite.
func replaceableRoute(repo db.Repository, feed string) bool {
	if repo.DisclosureChannel == "" {
		return true
	}
	return repo.DisclosureChannelAt == nil && strings.HasSuffix(repo.DisclosureChannel, viaFeed(feed))
}

// repoForRecord resolves a record's repository URL to the current local row
// and holds that repository's federation section until the caller releases
// it: the opt-out flag both decisions turn on is written under the same lock
// by the repo page and read under it by the scheduler, so reading it outside
// would leave the import applying a route to a repository that opted out in
// between. The release is never nil, so a caller defers it unconditionally.
//
// A URL this instance does not track is not an error; a row that vanished
// between the index and the read is not either, but any other failure is,
// since silently treating a locked database as "no such repository" would
// drop a maintainer's opt-out.
func (s *Server) repoForRecord(repoIDs map[string]uint, url string) (db.Repository, func(), bool, error) {
	id, ok := repoIDs[interchange.CanonicalRepo(url)]
	if !ok {
		return db.Repository{}, func() {}, false, nil
	}
	unlock := s.lockRepoFederation(id)
	var repo db.Repository
	err := s.DB.Select("id, disclosure_channel, disclosure_channel_at, federation_opt_out_at").First(&repo, id).Error
	if err != nil {
		unlock()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return db.Repository{}, func() {}, false, nil
		}
		return db.Repository{}, func() {}, false, err
	}
	return repo, unlock, true, nil
}

// ValidateFeedRemote rejects a git remote that embeds a token. Feed remotes
// are pushed to and fetched from on every tick and are written verbatim into
// the job's error messages and log fields, so a credentialed remote would
// leak its token into the logs. Both spellings are covered: the URL form
// parses its userinfo, and the scp-style form does not parse as a URL at all,
// so its userinfo is read off the text before the path. A bare username is
// refused only where it can be carrying a PAT, which is http(s); ssh:// and
// the scp-style form, which is ssh too, keep the ordinary git@host spelling.
func ValidateFeedRemote(raw string) error {
	remote := strings.TrimSpace(raw)
	if u, err := url.Parse(remote); err == nil && u.Scheme != "" && u.Host != "" {
		// Over http(s) any userinfo is refused: as parse_repo_url.go puts it,
		// tokens are commonly supplied as the username, so a bare-username
		// allowance would let the common PAT spelling straight through. A bare
		// username over ssh:// is the ordinary ssh://git@host/... form and
		// carries no secret; a password there still does.
		if u.User != nil {
			_, hasPassword := u.User.Password()
			if hasPassword || u.Scheme == "http" || u.Scheme == "https" {
				u.User = url.User(redactedUserinfo)
				return credentialedRemote(u.String())
			}
		}
		return nil
	}
	// scp-style: [user[:password]@]host:path. Only the part before the first
	// "/" can hold userinfo, so the path never confuses the check. The form is
	// ssh-only, so a password is refused and a bare username is not: git@host
	// is how every ssh remote is written.
	head, _, _ := strings.Cut(remote, "/")
	if userinfo, _, ok := strings.Cut(head, "@"); ok && strings.Contains(userinfo, ":") {
		_, rest, _ := strings.Cut(remote, "@")
		return credentialedRemote(redactedUserinfo + "@" + rest)
	}
	return nil
}

const redactedUserinfo = "***"

// credentialedRemote names the offending remote with its userinfo replaced
// rather than verbatim. The refusal is returned from startup validation and
// printed by the fatal logger, which is precisely the destination this check
// exists to keep the token out of.
func credentialedRemote(redacted string) error {
	return fmt.Errorf("federation feed remote %q must not contain credentials; configure a git credential helper on the host instead", redacted)
}

// repoIDsByCanonicalURL keys the local repository ids by the same canonical
// URL the records carry, since the canonicalisation (lowercase, trailing
// slash and .git stripped) cannot be expressed as a SQL join. Only the id is
// indexed: it is the one thing that cannot change under an import pass.
func (s *Server) repoIDsByCanonicalURL() (map[string]uint, error) {
	var rows []db.Repository
	if err := s.DB.Select("id, url").Where(publishableRepo).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]uint, len(rows))
	for _, r := range rows {
		out[interchange.CanonicalRepo(r.URL)] = r.ID
	}
	return out, nil
}

// feedClone returns a synced working clone of remote under the data
// directory, cloning it on first use and hard-resetting it to the remote
// afterwards. The reset is what keeps the export idempotent: local commits
// from a previous run that never reached the remote are discarded rather
// than accumulating into a push that conflicts forever.
//
// It also returns the branch's remote-tracking ref, empty when the remote does
// not carry the branch, which is what tells the export whether the remote
// already holds this clone's HEAD.
func (s *Server) feedClone(ctx context.Context, name, remote string) (string, string, error) {
	if s.Worker == nil || s.Worker.DataDir == "" {
		return "", "", errors.New("no data directory configured")
	}
	dir := filepath.Join(s.Worker.DataDir, "feeds", name)
	fresh, err := ensureFeedClone(ctx, dir, remote)
	if err != nil {
		return "", "", err
	}
	// A clone made moments ago already points at remote and already carries
	// every ref it advertises, so the retarget and the fetch are skipped: they
	// would cost a second network round trip to learn nothing.
	if !fresh {
		// An existing clone is re-pointed when the configured remote changed:
		// nothing else rewrites origin, so an operator editing federation_*_feed
		// would keep fetching from and pushing to the remote this clone was first
		// made against, leaving the new one empty with nothing saying why. The
		// --prune fetch below then drops the old remote's tracking refs.
		if err := retargetOrigin(ctx, dir, remote); err != nil {
			return "", "", err
		}
		// --prune so a branch deleted on the remote takes its remote-tracking ref
		// with it. Without it a feed repository that was recreated leaves a stale
		// ref behind, and the reset below would sync this clone onto a commit the
		// remote no longer has, with nothing downstream able to tell.
		if out, err := runFeedGit(ctx, dir, "fetch", "--quiet", "--prune", "origin"); err != nil {
			return "", "", fmt.Errorf("fetch %s: %s: %w", remote, out, err)
		}
	}
	branch, err := runFeedGit(ctx, dir, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return "", "", fmt.Errorf("resolve branch of %s: %s: %w", remote, branch, err)
	}
	// Reset onto this branch's remote-tracking ref, not FETCH_HEAD: the fetch
	// uses the clone's all-branches refspec, so FETCH_HEAD holds every branch
	// the remote advertises and which one it resolves to depends on git's
	// ordering. The tracking ref is also independent of branch.<name>.merge,
	// which a clone of an empty remote never sets. A remote that does not
	// carry this branch yet is the first-export case: nothing to reset onto,
	// and the local state is already the whole feed.
	tracking := "refs/remotes/origin/" + strings.TrimSpace(branch)
	if _, err := runFeedGit(ctx, dir, "rev-parse", "--verify", "--quiet", tracking); err != nil {
		return dir, "", nil
	}
	if out, err := runFeedGit(ctx, dir, "reset", "--quiet", "--hard", tracking); err != nil {
		return "", "", fmt.Errorf("reset %s: %s: %w", remote, out, err)
	}
	return dir, tracking, nil
}

// ensureFeedClone clones remote into dir when dir is not a working clone
// already, and reports whether it did. The caller resolves the tracking ref
// on both paths: a fresh clone of a remote that already holds these records
// has a clean tree, and answering "no tracking ref" there would read as
// "nothing local ever reached the remote" and push, logging a publication
// that never happened, on the first tick after every re-clone.
func ensureFeedClone(ctx context.Context, dir, remote string) (bool, error) {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		// Only an absent .git means "not cloned yet". Any other answer is the
		// filesystem failing to say, and wiping a healthy working clone over a
		// transient one would throw away the tier's history and re-clone.
		return false, err
	}
	// A clone that died partway leaves the destination populated but
	// without .git, and git refuses a non-empty target with a permanent
	// error, so the leftovers would wedge every later tick. The path is
	// entirely scrutineer-owned and derived from the tier or a digest of
	// the remote, never from user input, so clearing it is safe.
	if err := os.RemoveAll(dir); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(dir), feedDirPerm); err != nil {
		return false, err
	}
	// The Reset hook is what makes the retry budget mean anything here: a
	// clone killed mid-transfer leaves the destination populated, and git
	// answers a non-empty target with a permanent error, so without it the
	// second attempt fails on the leftovers of the first rather than on the
	// remote. DestReset only offers to clear a destination that is absent or
	// empty right now, which the RemoveAll above has just made it.
	if out, err := (clone.Retry{}).Do(ctx, clone.Command{
		Label: "feed clone",
		Env:   feedGitEnv,
		Args:  []string{"clone", "--quiet", "--", remote, dir},
		Reset: clone.DestReset(dir),
	}); err != nil {
		return false, fmt.Errorf("clone %s: %s: %w", remote, out, err)
	}
	return true, nil
}

// retargetOrigin points the clone's origin at remote when it does not
// already match.
func retargetOrigin(ctx context.Context, dir, remote string) error {
	origin, err := runFeedGit(ctx, dir, "remote", "get-url", "origin")
	if err != nil {
		return fmt.Errorf("resolve origin of %s: %s: %w", remote, origin, err)
	}
	if strings.TrimSpace(origin) == remote {
		return nil
	}
	if out, err := runFeedGit(ctx, dir, "remote", "set-url", "origin", remote); err != nil {
		return fmt.Errorf("retarget origin to %s: %s: %w", remote, out, err)
	}
	return nil
}

// commitAndPushFeed commits the working tree and pushes it, reporting
// whether anything was published. A clean tree over a remote that already
// holds this clone's HEAD means the feed matches what this instance stands
// behind, so the tick costs a fetch and nothing else.
func commitAndPushFeed(ctx context.Context, dir, tracking, message string) (bool, error) {
	// --force so a stray .gitignore in the feed repository cannot make the
	// job report a clean tree while silently publishing nothing.
	if out, err := runFeedGit(ctx, dir, "add", "--all", "--force", "."); err != nil {
		return false, fmt.Errorf("add: %s: %w", out, err)
	}
	status, err := runFeedGit(ctx, dir, "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("status: %s: %w", status, err)
	}
	if strings.TrimSpace(status) != "" {
		if out, err := runFeedGit(ctx, dir, append(append([]string{}, feedCommitter...), "commit", "--quiet", "-m", message)...); err != nil {
			return false, fmt.Errorf("commit: %s: %w", out, err)
		}
	} else {
		// A clean tree only says the records match this clone's own HEAD, which
		// says nothing about the remote: a feed repository recreated or rolled
		// back under a running instance leaves the clone ahead of it, and
		// stopping here would mean the tier silently never publishes again.
		published, err := feedHeadIsPublished(ctx, dir, tracking)
		if err != nil || published {
			return false, err
		}
	}
	if out, err := runFeedGit(ctx, dir, "push", "--quiet", "origin", "HEAD"); err != nil {
		return false, fmt.Errorf("push: %s: %w", out, err)
	}
	return true, nil
}

// feedHeadIsPublished reports whether the remote already carries this clone's
// HEAD. An empty tracking ref means the remote does not carry the branch at
// all, so nothing local has reached it.
func feedHeadIsPublished(ctx context.Context, dir, tracking string) (bool, error) {
	if tracking == "" {
		return false, nil
	}
	head, err := runFeedGit(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return false, fmt.Errorf("resolve HEAD: %s: %w", head, err)
	}
	remote, err := runFeedGit(ctx, dir, "rev-parse", tracking)
	if err != nil {
		return false, fmt.Errorf("resolve %s: %s: %w", tracking, remote, err)
	}
	return strings.TrimSpace(head) == strings.TrimSpace(remote), nil
}

// feedGitEnv hardens every feed git invocation. GIT_TERMINAL_PROMPT=0 keeps a
// feed remote whose credentials are missing failing fast instead of blocking
// the job on a prompt no one can answer. GIT_ALLOW_PROTOCOL is the same hard
// whitelist the clone package puts on its own remote-touching commands: it
// overrides protocol.*.allow, so an ambient url.<base>.insteadOf rewriting a
// feed remote to ext:: (which hands git a shell command) is refused after
// ValidateFeedRemote has already approved the configured value. The three
// transports are the ones a feed remote is documented with, "file" covering
// both file:// and a local path.
var feedGitEnv = []string{"GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=https:ssh:file"}

// runFeedGit runs one git command against a feed clone under the standard
// network retry policy.
func runFeedGit(ctx context.Context, dir string, args ...string) (string, error) {
	// The label names the subcommand, so the leading "-c key=value" pairs the
	// commit invocation passes its identity with are skipped.
	sub := args
	for len(sub) > 2 && sub[0] == "-c" {
		sub = sub[2:]
	}
	return clone.Retry{}.Do(ctx, clone.Command{
		Label: "feed " + sub[0],
		Dir:   dir,
		Env:   feedGitEnv,
		Args:  args,
	})
}

// feedDirName is a stable, filesystem-safe directory name for a peer
// remote, so two peers never share a working clone and a remote containing
// a path separator or credentials cannot escape the feeds directory.
func feedDirName(remote string) string {
	h := sha256.Sum256([]byte(remote))
	return hex.EncodeToString(h[:8])
}
