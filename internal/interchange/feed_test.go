package interchange

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
)

type rejectingIdentity struct{}

func (*rejectingIdentity) Unwrap([]*age.Stanza) ([]byte, error) {
	return nil, age.ErrIncorrectIdentity
}

func certificate(t *testing.T, status string) Statement {
	t.Helper()
	return NewCertificate(CertificatePredicate{
		Repository: "https://github.com/acme/lib",
		Advisory:   "GHSA-xxxx-yyyy-zzzz",
		Status:     status,
		AuditedAt:  time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	})
}

func optOut(t *testing.T, repo string) Statement {
	t.Helper()
	return NewOptOut(OptOutPredicate{
		Repository:  repo,
		RequestedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	})
}

func testIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// testSSHRecipient returns an SSH identity and the recipient a recipients
// file loads for it, carrying the key the rotation check fingerprints it by.
func testSSHRecipient(t *testing.T) (*agessh.Ed25519Identity, Recipient) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return id, Recipient{Recipient: id.Recipient(), Key: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))}
}

func TestNewCertificatePicksPredicateTypeFromVerdict(t *testing.T) {
	if got := certificate(t, CertificateStatusFixed).PredicateType; got != PredicateTypeCertificate {
		t.Errorf("clean verdict must stay on certificate/v1, got %s", got)
	}
	for _, status := range []string{"bypass", "variant", "regressed"} {
		if got := certificate(t, status).PredicateType; got != PredicateTypeCertificateV2 {
			t.Errorf("%s verdict must use certificate/v2, got %s", status, got)
		}
	}
}

func TestTierCarries(t *testing.T) {
	cases := []struct {
		tier          Tier
		predicateType string
		want          bool
	}{
		{TierPublic, PredicateTypeCertificate, true},
		{TierPublic, PredicateTypeOptOut, true},
		{TierPublic, PredicateTypeRoute, true},
		{TierPublic, PredicateTypeCertificateV2, false},
		{TierPublic, PredicateTypeClaim, false},
		{TierMembers, PredicateTypeCertificateV2, true},
		{TierMembers, PredicateTypeCertificate, false},
		{TierMembers, PredicateTypeOptOut, false},
		{TierMembers, PredicateTypeClaim, false},
		{Tier("other"), PredicateTypeOptOut, false},
	}
	for _, c := range cases {
		if got := c.tier.Carries(c.predicateType); got != c.want {
			t.Errorf("%s.Carries(%s) = %v, want %v", c.tier, c.predicateType, got, c.want)
		}
	}
}

func TestRecordFile(t *testing.T) {
	rec := optOut(t, "https://github.com/acme/lib")
	digest := rec.Subject[0].Digest["sha256"]
	got, err := RecordFile(rec, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("optout", digest+".json"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, _ = RecordFile(rec, true); !strings.HasSuffix(got, ".json.age") {
		t.Errorf("encrypted record must carry the .age suffix, got %q", got)
	}
	if _, err := RecordFile(Statement{PredicateType: "https://example.com/other/v1"}, false); err == nil {
		t.Error("an unknown predicate type must be refused")
	}
	if _, err := RecordFile(Statement{PredicateType: PredicateTypeOptOut}, false); err == nil {
		t.Error("a record without a subject digest must be refused")
	}
}

func TestWriteFeedPublishesAndPrunes(t *testing.T) {
	dir := t.TempDir()
	first := optOut(t, "https://github.com/acme/lib")
	second := optOut(t, "https://github.com/acme/other")
	if err := WriteFeed(dir, TierPublic, []Statement{first, second}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 records on the feed, got %v", names)
	}

	// A withdrawn opt-out must leave the feed, not sit next to the rest.
	if err := WriteFeed(dir, TierPublic, []Statement{first}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	names, err = recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := RecordFile(first, false)
	if len(names) != 1 || names[0] != want {
		t.Fatalf("expected only %q to remain, got %v", want, names)
	}
}

func TestWriteFeedLeavesForeignFilesAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("peer feed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFeed(dir, TierPublic, nil, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Fatalf("the feed repository's own files must survive an export: %v", err)
	}
}

func TestWriteFeedRefusesUnknownTier(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFeed(dir, TierPublic, []Statement{optOut(t, "https://github.com/acme/lib")}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	// The dangerous shape: no records to check the tier against, so nothing
	// refuses the tier itself and the prune runs over a populated feed.
	if err := WriteFeed(dir, Tier("mirror"), nil, FeedKeys{}); err == nil {
		t.Fatal("an unknown tier must be refused")
	}
	if names, _ := recordFiles(dir); len(names) != 1 {
		t.Fatalf("a refused tier must not prune the feed, got %v", names)
	}
}

// Adding a member must give them the records that did not change since they
// joined, and removing one must take those same records away: the ciphertext
// is what carries access, so leaving it in place on a membership change is
// the whole bug.
func TestWriteFeedReEncryptsOnRecipientChange(t *testing.T) {
	dir := t.TempDir()
	first, second := testIdentity(t), testIdentity(t)
	rec := certificate(t, "bypass")
	oneMember := FeedKeys{Recipients: []age.Recipient{first.Recipient()}, Identities: []age.Identity{first}}
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, oneMember); err != nil {
		t.Fatal(err)
	}
	if records, _ := ReadFeed(dir, []age.Identity{second}); records[0].Err == nil {
		t.Fatal("the second identity must not read the feed before it is a recipient")
	}

	bothMembers := FeedKeys{Recipients: []age.Recipient{first.Recipient(), second.Recipient()}, Identities: []age.Identity{first}}
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, bothMembers); err != nil {
		t.Fatal(err)
	}
	for _, id := range []*age.X25519Identity{first, second} {
		records, err := ReadFeed(dir, []age.Identity{id})
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 || records[0].Err != nil {
			t.Fatalf("an added recipient must be able to read the unchanged record: %+v", records)
		}
	}

	// Re-exporting the same records to the same set must still be a no-op,
	// or the rotation check would churn the whole feed on every tick.
	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, names[0])
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, bothMembers); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("an unchanged recipient set must not rewrite the feed")
	}

	if err := WriteFeed(dir, TierMembers, []Statement{rec}, oneMember); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, []age.Identity{second})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err == nil {
		t.Fatalf("a removed recipient must lose access to the unchanged record: %+v", records)
	}
	if records, _ = ReadFeed(dir, []age.Identity{first}); records[0].Err != nil {
		t.Fatalf("the remaining recipient must still read the feed: %v", records[0].Err)
	}
}

func TestWriteFeedPluginFailureDoesNotRewriteExistingRecord(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity(t)
	rec := certificate(t, "bypass")
	keys := FeedKeys{
		Recipients: []age.Recipient{id.Recipient()},
		Identities: []age.Identity{id},
	}
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, keys); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, names[0])
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	const name = "scrutineer-missing-test"
	pluginID, err := plugin.NewIdentityWithoutData(name, &plugin.ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	keys.Identities = []age.Identity{pluginID}
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, keys); err == nil {
		t.Fatal("missing plugin must fail instead of replacing the existing ciphertext")
	} else if !strings.Contains(err.Error(), "age-plugin-"+name) {
		t.Fatalf("error does not identify the missing plugin executable: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a failed identity plugin rewrote the existing ciphertext")
	}
}

func TestDecryptRecordDoesNotReorderIdentities(t *testing.T) {
	id := testIdentity(t)
	raw, err := encryptRecord([]byte("record"), []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	reject := &rejectingIdentity{}
	identities := []age.Identity{reject, id}
	if _, err := decryptRecord(raw, identities); err != nil {
		t.Fatal(err)
	}
	if identities[0] != reject || identities[1] != id {
		t.Fatalf("decryptRecord reordered the caller's identities: %T, %T", identities[0], identities[1])
	}
}

// SSH keys are what scrutineer documents as the default, and an agessh
// recipient renders neither its key nor anything else, so a set holding one is
// the case where a membership change would go unnoticed.
func TestWriteFeedReEncryptsOnMixedSSHRecipientChange(t *testing.T) {
	dir := t.TempDir()
	sshID, sshRec := testSSHRecipient(t)
	x := testIdentity(t)
	rec := certificate(t, "regressed")
	members := FeedKeys{Recipients: []age.Recipient{sshRec, x.Recipient()}, Identities: []age.Identity{sshID}}
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, members); err != nil {
		t.Fatal(err)
	}

	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, names[0])
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, members); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("an unchanged mixed recipient set must not rewrite the feed")
	}

	joinerID, joinerRec := testSSHRecipient(t)
	if records, _ := ReadFeed(dir, []age.Identity{joinerID}); records[0].Err == nil {
		t.Fatal("the joining SSH identity must not read the feed before it is a recipient")
	}
	members.Recipients = append(members.Recipients, joinerRec)
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, members); err != nil {
		t.Fatal(err)
	}
	for _, id := range []age.Identity{sshID, x, joinerID} {
		records, err := ReadFeed(dir, []age.Identity{id})
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 || records[0].Err != nil {
			t.Fatalf("every member of the new set must read the unchanged record: %+v", records)
		}
	}
}

type opaqueRecipient struct{}

func (opaqueRecipient) Wrap([]byte) ([]*age.Stanza, error) { return nil, nil }

func TestWriteFeedRefusesUnfingerprintableRecipient(t *testing.T) {
	id := testIdentity(t)
	keys := FeedKeys{Recipients: []age.Recipient{opaqueRecipient{}}, Identities: []age.Identity{id}}
	if err := WriteFeed(t.TempDir(), TierMembers, []Statement{certificate(t, "bypass")}, keys); err == nil {
		t.Fatal("a recipient that cannot be fingerprinted must be refused, since its removal would go unnoticed")
	}
}

func TestWriteFeedRefusesRecipientWithoutKey(t *testing.T) {
	id := testIdentity(t)
	keys := FeedKeys{Recipients: []age.Recipient{Recipient{Recipient: id.Recipient()}}, Identities: []age.Identity{id}}
	if err := WriteFeed(t.TempDir(), TierMembers, []Statement{certificate(t, "bypass")}, keys); err == nil {
		t.Fatal("a recipient carrying no key must be refused: an empty key digests every member the same")
	}
}

func TestRecipientsDigestIsOrderAndDuplicateStable(t *testing.T) {
	first, second := testIdentity(t).Recipient(), testIdentity(t).Recipient()
	one, err := recipientsDigest([]age.Recipient{first, second})
	if err != nil {
		t.Fatal(err)
	}
	two, err := recipientsDigest([]age.Recipient{second, first, second})
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatalf("the same members must digest identically whatever the order or duplicates: %s != %s", one, two)
	}
	if three, _ := recipientsDigest([]age.Recipient{first}); three == one {
		t.Fatal("a different member set must digest differently")
	}
}

func TestWriteFeedRefusesSymlinkedKindDirectory(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, strings.Repeat("33", 32)+".json")
	if err := os.WriteFile(victim, []byte("not ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "optout")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFeed(dir, TierPublic, []Statement{optOut(t, "https://github.com/acme/lib")}, FeedKeys{}); err == nil {
		t.Fatal("a symlinked kind directory must be refused")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("pruning must never follow a symlink out of the feed: %v", err)
	}
}

func TestWriteFeedRefusesSymlinkedRecordFile(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, "secrets")
	if err := os.WriteFile(victim, []byte("not ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := optOut(t, "https://github.com/acme/lib")
	name, err := RecordFile(rec, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if err := WriteFeed(dir, TierPublic, []Statement{rec}, FeedKeys{}); err == nil {
		t.Fatal("a symlink where a record belongs must be refused")
	}
	body, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "not ours\n" {
		t.Fatalf("writing must never follow a symlink out of the feed, got %q", body)
	}
}

func TestWriteFeedRefusesMisroutedRecord(t *testing.T) {
	dir := t.TempDir()
	err := WriteFeed(dir, TierPublic, []Statement{certificate(t, "bypass")}, FeedKeys{})
	if err == nil {
		t.Fatal("a non-clean certificate must never reach the public feed")
	}
	if names, _ := recordFiles(dir); len(names) != 0 {
		t.Fatalf("a refused export must write nothing, got %v", names)
	}
}

func TestWriteFeedRefusesMembersTierWithoutRecipients(t *testing.T) {
	if err := WriteFeed(t.TempDir(), TierMembers, []Statement{certificate(t, "bypass")}, FeedKeys{}); err == nil {
		t.Fatal("the members feed must refuse to publish without age recipients")
	}
}

func TestFeedRoundTripPlaintext(t *testing.T) {
	dir := t.TempDir()
	rec := optOut(t, "https://github.com/acme/lib")
	if err := WriteFeed(dir, TierPublic, []Statement{rec}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one readable record, got %+v", records)
	}
	var p OptOutPredicate
	if err := DecodePredicate(records[0].Statement, &p); err != nil {
		t.Fatal(err)
	}
	if p.Repository != "https://github.com/acme/lib" || !p.RequestedAt.Equal(time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("predicate did not survive the round trip: %+v", p)
	}
}

func TestFeedRoundTripEncrypted(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity(t)
	rec := certificate(t, "regressed")
	if err := WriteFeed(dir, TierMembers, []Statement{rec}, FeedKeys{Recipients: []age.Recipient{id.Recipient()}, Identities: []age.Identity{id}}); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || !strings.HasSuffix(names[0], ".json.age") {
		t.Fatalf("members records must be written encrypted, got %v", names)
	}
	raw, err := os.ReadFile(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "regressed") {
		t.Fatal("the verdict must not be readable in the encrypted record")
	}
	records, err := ReadFeed(dir, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one readable record, got %+v", records)
	}
	var p CertificatePredicate
	if err := DecodePredicate(records[0].Statement, &p); err != nil {
		t.Fatal(err)
	}
	if p.Status != "regressed" {
		t.Fatalf("status did not survive the round trip: %+v", p)
	}
}

func TestReadFeedReportsUnreadableRecords(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "optout"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := optOut(t, "https://github.com/acme/lib")
	if err := WriteFeed(dir, TierPublic, []Statement{good}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"optout/" + strings.Repeat("11", 32) + ".json": "{not json",
		"optout/" + strings.Repeat("22", 32) + ".json": `{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://github.com/alpha-omega-security/scrutineer/interchange/optout/v1","predicate":{}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 record files, got %d", len(records))
	}
	var ok, failed int
	for _, rec := range records {
		if rec.Err == nil {
			ok++
		} else {
			failed++
		}
	}
	if ok != 1 || failed != 2 {
		t.Fatalf("expected the valid record plus two reported failures, got %d ok / %d failed", ok, failed)
	}
}

// A record-shaped symlink is reported, not skipped. Skipping it would hide the
// entry from both sides: an importer would miss a record without being told,
// and an export would leave the symlink in place while claiming the feed holds
// exactly what it published. Pruning it unlinks the symlink, never its target.
func TestReadFeedReportsSymlinkedRecord(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, "secrets")
	if err := os.WriteFile(victim, []byte("not ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := optOut(t, "https://github.com/acme/lib")
	if err := WriteFeed(dir, TierPublic, []Statement{rec}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "optout", strings.Repeat("44", 32)+".json")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected the published record plus the symlinked one, got %+v", records)
	}
	var ok, failed int
	for _, r := range records {
		if r.Err == nil {
			ok++
		} else {
			failed++
		}
	}
	if ok != 1 || failed != 1 {
		t.Fatalf("expected the valid record plus one reported failure, got %d ok / %d failed", ok, failed)
	}

	if err := WriteFeed(dir, TierPublic, []Statement{rec}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(planted); err == nil {
		t.Fatal("a record-shaped symlink absent from the export must be pruned")
	}
	body, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "not ours\n" {
		t.Fatalf("pruning must unlink the symlink, not touch its target, got %q", body)
	}
}

func TestReadFeedWithoutIdentityReportsEncryptedRecord(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity(t)
	if err := WriteFeed(dir, TierMembers, []Statement{certificate(t, "bypass")}, FeedKeys{Recipients: []age.Recipient{id.Recipient()}, Identities: []age.Identity{id}}); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err == nil {
		t.Fatalf("an undecryptable record must be reported, not silently skipped: %+v", records)
	}
}

// An unchanged record must keep its exact file on both tiers. On the
// members tier that cannot be a byte comparison: age derives a fresh file
// key per call, so re-encrypting the same record yields different
// ciphertext and every export would rewrite the whole feed.
func TestWriteFeedLeavesUnchangedRecordsUntouched(t *testing.T) {
	id := testIdentity(t)
	cases := []struct {
		name string
		tier Tier
		recs []Statement
		keys FeedKeys
	}{
		{"public", TierPublic, []Statement{optOut(t, "https://github.com/acme/lib")}, FeedKeys{}},
		{"members", TierMembers, []Statement{certificate(t, "bypass")},
			FeedKeys{Recipients: []age.Recipient{id.Recipient()}, Identities: []age.Identity{id}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := WriteFeed(dir, tc.tier, tc.recs, tc.keys); err != nil {
				t.Fatal(err)
			}
			names, err := recordFiles(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(names) != 1 {
				t.Fatalf("expected 1 record, got %v", names)
			}
			path := filepath.Join(dir, names[0])
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteFeed(dir, tc.tier, tc.recs, tc.keys); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("re-exporting an unchanged record must not rewrite its file")
			}
		})
	}
}

func TestWriteFeedRewritesAChangedEncryptedRecord(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity(t)
	keys := FeedKeys{Recipients: []age.Recipient{id.Recipient()}, Identities: []age.Identity{id}}
	if err := WriteFeed(dir, TierMembers, []Statement{certificate(t, "bypass")}, keys); err != nil {
		t.Fatal(err)
	}
	// Same advisory, so the same subject digest and therefore the same
	// file: only the verdict changed, and the feed must carry the new one.
	if err := WriteFeed(dir, TierMembers, []Statement{certificate(t, "regressed")}, keys); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one readable record, got %+v", records)
	}
	var p CertificatePredicate
	if err := DecodePredicate(records[0].Statement, &p); err != nil {
		t.Fatal(err)
	}
	if p.Status != "regressed" {
		t.Fatalf("status = %q, want the updated verdict", p.Status)
	}
}

func TestReadFeedReturnsThePublishedBytes(t *testing.T) {
	dir := t.TempDir()
	rec := optOut(t, "https://github.com/acme/lib")
	if err := WriteFeed(dir, TierPublic, []Statement{rec}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil {
		t.Fatalf("expected one readable record, got %+v", records)
	}
	// Raw is what an importer archives, so it must be the publisher's own
	// bytes rather than a re-encode through this version's structs.
	if strings.TrimSpace(string(onDisk)) != strings.TrimSpace(string(records[0].Raw)) {
		t.Fatalf("Raw is not the published bytes:\n%s\n---\n%s", onDisk, records[0].Raw)
	}
}

func TestWriteFeedIsByteStable(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	recs := []Statement{certificate(t, CertificateStatusFixed), optOut(t, "https://github.com/acme/lib")}
	if err := WriteFeed(first, TierPublic, recs, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	// Reversed input: the feed is addressed by subject, so ordering the
	// records differently must not produce a different feed.
	if err := WriteFeed(second, TierPublic, []Statement{recs[1], recs[0]}, FeedKeys{}); err != nil {
		t.Fatal(err)
	}
	names, err := recordFiles(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 records, got %v", names)
	}
	for _, name := range names {
		a, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("%s differs between two exports of the same records", name)
		}
	}
}
