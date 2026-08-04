// Package interchange defines the federation interchange format:
// in-toto Statement v1 envelopes carrying one record per statement, so
// scrutineer instances and non-scrutineer tools can exchange audit
// certificates, finding claims, maintainer opt-outs, and disclosure
// routes without ever exchanging finding bodies, severity, CVSS, or
// health scores. The shipped interchange.schema.json is the normative
// contract; Validate checks a raw record against it.
package interchange

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// StatementType is the in-toto Statement v1 type URI, required on every
// record.
const StatementType = "https://in-toto.io/Statement/v1"

// Predicate type URIs, one per record kind. The path under the project
// URL names the kind and its schema revision; bump the trailing version
// on any breaking predicate change.
//
// Certificates come in two revisions because the verdict decides which
// feed may carry the record: v1 is the clean case and stays pinned to
// "fixed", so a consumer of the public feed still handles exactly the
// values it always has, and v2 carries the non-clean verdicts, which name
// a repository whose advertised fix does not hold and therefore travel
// only on the encrypted members feed.
const (
	PredicateTypeCertificate   = "https://github.com/alpha-omega-security/scrutineer/interchange/certificate/v1"
	PredicateTypeCertificateV2 = "https://github.com/alpha-omega-security/scrutineer/interchange/certificate/v2"
	PredicateTypeClaim         = "https://github.com/alpha-omega-security/scrutineer/interchange/claim/v1"
	PredicateTypeOptOut        = "https://github.com/alpha-omega-security/scrutineer/interchange/optout/v1"
	PredicateTypeRoute         = "https://github.com/alpha-omega-security/scrutineer/interchange/route/v1"
)

// CertificateStatusFixed is the clean fix-audit verdict, the only one a
// certificate/v1 record may carry.
const CertificateStatusFixed = "fixed"

// certificateStatusesV2 are the non-clean verdicts certificate/v2 accepts,
// mirroring the enum in interchange.schema.json. Sorted, so a query built
// from it has stable text. A verdict outside this set and
// CertificateStatusFixed is not publishable at all: exporters filter on it
// rather than handing the schema a record it will reject, since a single
// unpublishable row would otherwise fail the whole export.
var certificateStatusesV2 = []string{"bypass", "regressed", "variant"}

// CertificateStatusesV2 returns those verdicts for the export query that
// filters on them. A copy per call rather than the slice itself: the set is
// the schema's contract, and an exported variable could be reordered or
// extended by any consumer.
func CertificateStatusesV2() []string { return slices.Clone(certificateStatusesV2) }

// recordKinds names the feed subdirectory each predicate type is filed
// under. Both certificate revisions share one directory: they are the same
// record kind at two schema revisions, and the feed tiers already keep
// them apart. Absence from this map means "not an interchange record".
var recordKinds = map[string]string{
	PredicateTypeCertificate:   "certificate",
	PredicateTypeCertificateV2: "certificate",
	PredicateTypeClaim:         "claim",
	PredicateTypeOptOut:        "optout",
	PredicateTypeRoute:         "route",
}

// Kind returns the short record-kind name for a predicate type, used as
// the feed subdirectory. The empty string means the type is unknown.
func Kind(predicateType string) string { return recordKinds[predicateType] }

// Tier names a federation feed. The public feed is a plain git repository
// anyone may clone, so it carries only records that say nothing about a
// live vulnerability: opt-outs, disclosure routes, and clean certificates.
// The members feed is age-encrypted and carries the non-clean
// certificates. Claims are on neither: publishing a hash set would hand
// members something to enumerate offline, so POST /claim-check answers one
// hash at a time instead.
type Tier string

const (
	TierPublic  Tier = "public"
	TierMembers Tier = "members"
)

// Carries reports whether tier may publish a record of this predicate type.
func (t Tier) Carries(predicateType string) bool {
	switch t {
	case TierPublic:
		return predicateType == PredicateTypeCertificate ||
			predicateType == PredicateTypeOptOut ||
			predicateType == PredicateTypeRoute
	case TierMembers:
		return predicateType == PredicateTypeCertificateV2
	}
	return false
}

// Statement is the in-toto Statement v1 envelope. All four fields are
// required by the in-toto spec and by interchange.schema.json, so none
// carries omitempty.
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     any                  `json:"predicate"`
}

// ResourceDescriptor identifies what a statement is about. The in-toto
// spec requires a digest on statement subjects.
type ResourceDescriptor struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// CertificatePredicate attests that an advisory's advertised fix was
// re-audited and held. It carries no severity, CVSS, evidence text, or
// scan internals: those are either instance-local or re-derivable from
// the public advisory, and federation records never publish them.
type CertificatePredicate struct {
	Repository  string    `json:"repository"`
	Advisory    string    `json:"advisory"`
	AdvisoryURL string    `json:"advisory_url,omitempty"`
	Status      string    `json:"status"`
	Commit      string    `json:"commit,omitempty"`
	AuditedAt   time.Time `json:"audited_at"`
}

// ClaimPredicate says the publishing instance holds a finding whose
// salted FindingHash is the subject digest, and how to reach it to
// coordinate. The hash is the only thing published about the finding.
type ClaimPredicate struct {
	Contact string `json:"contact"`
}

// OptOutPredicate records a maintainer's request that federated
// instances neither scan the repository nor contact them about it.
type OptOutPredicate struct {
	Repository  string    `json:"repository"`
	RequestedAt time.Time `json:"requested_at"`
	Reason      string    `json:"reason,omitempty"`
}

// RoutePredicate shares the validated disclosure route for a repository
// so other instances can skip re-deriving it. Channel mirrors
// Repository.DisclosureChannel: an email, GHSA URL, registry owner
// handle, or SECURITY.md URL.
type RoutePredicate struct {
	Repository string    `json:"repository"`
	Channel    string    `json:"channel"`
	VerifiedAt time.Time `json:"verified_at"`
}

// NewCertificate wraps a certificate predicate in its envelope. The
// subject names the advisory and digests the canonical repository URL
// plus the uppercased advisory id, so the same certificate from two
// instances shares a subject whatever case or padding each stored the
// id with. The predicate type follows the verdict, which is what routes
// the record to the public or the members feed.
func NewCertificate(p CertificatePredicate) Statement {
	p.Repository = CanonicalRepo(p.Repository)
	p.Advisory = strings.TrimSpace(p.Advisory)
	predicateType := PredicateTypeCertificateV2
	if p.Status == CertificateStatusFixed {
		predicateType = PredicateTypeCertificate
	}
	return Statement{
		Type:          StatementType,
		Subject:       []ResourceDescriptor{{Name: p.Advisory, Digest: sha256Digest(p.Repository + "\x00" + strings.ToUpper(p.Advisory))}},
		PredicateType: predicateType,
		Predicate:     p,
	}
}

// NewClaim wraps a claim predicate in its envelope. The subject digest
// is the salted FindingHash itself.
func NewClaim(findingHash string, p ClaimPredicate) Statement {
	return Statement{
		Type:          StatementType,
		Subject:       []ResourceDescriptor{{Name: "finding", Digest: map[string]string{"sha256": findingHash}}},
		PredicateType: PredicateTypeClaim,
		Predicate:     p,
	}
}

// NewOptOut wraps an opt-out predicate in its envelope.
func NewOptOut(p OptOutPredicate) Statement {
	p.Repository = CanonicalRepo(p.Repository)
	return Statement{
		Type:          StatementType,
		Subject:       []ResourceDescriptor{{Name: p.Repository, Digest: sha256Digest(p.Repository)}},
		PredicateType: PredicateTypeOptOut,
		Predicate:     p,
	}
}

// NewRoute wraps a route predicate in its envelope.
func NewRoute(p RoutePredicate) Statement {
	p.Repository = CanonicalRepo(p.Repository)
	return Statement{
		Type:          StatementType,
		Subject:       []ResourceDescriptor{{Name: p.Repository, Digest: sha256Digest(p.Repository)}},
		PredicateType: PredicateTypeRoute,
		Predicate:     p,
	}
}

func sha256Digest(s string) map[string]string {
	h := sha256.Sum256([]byte(s))
	return map[string]string{"sha256": hex.EncodeToString(h[:])}
}

//go:embed interchange.schema.json
var schemaJSON []byte

var (
	schemaOnce sync.Once
	schemaVal  *jsonschema.Schema
	schemaErr  error
)

func getSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
		if err != nil {
			schemaErr = fmt.Errorf("parse interchange.schema.json: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		// Draft 2020-12 treats "format" as annotation-only by default;
		// without this the schema's date-time constraints are dead.
		c.AssertFormat()
		if err := c.AddResource("interchange.schema.json", doc); err != nil {
			schemaErr = fmt.Errorf("add interchange.schema.json: %w", err)
			return
		}
		schemaVal, schemaErr = c.Compile("interchange.schema.json")
	})
	return schemaVal, schemaErr
}

// Validate checks one raw interchange record against the shipped
// schema. Import paths must call it before trusting a record from a
// feed; export tests call it so emitted records stay on-contract.
func Validate(raw []byte) error {
	schema, err := getSchema()
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("parse record: %w", err)
	}
	return schema.Validate(inst)
}

// DecodePredicate re-decodes a statement's predicate into p, which must be
// a pointer to the predicate struct matching the statement's type. A
// statement read off a feed carries its predicate as a generic map; this
// gives importers the typed view without a second parse of the whole
// record.
func DecodePredicate(s Statement, p any) error {
	raw, err := json.Marshal(s.Predicate)
	if err != nil {
		return fmt.Errorf("re-encode predicate: %w", err)
	}
	if err := json.Unmarshal(raw, p); err != nil {
		return fmt.Errorf("decode predicate: %w", err)
	}
	return nil
}
