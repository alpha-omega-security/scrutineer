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
	"fmt"
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
const (
	PredicateTypeCertificate = "https://github.com/alpha-omega-security/scrutineer/interchange/certificate/v1"
	PredicateTypeClaim       = "https://github.com/alpha-omega-security/scrutineer/interchange/claim/v1"
	PredicateTypeOptOut      = "https://github.com/alpha-omega-security/scrutineer/interchange/optout/v1"
	PredicateTypeRoute       = "https://github.com/alpha-omega-security/scrutineer/interchange/route/v1"
)

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
// id with.
func NewCertificate(p CertificatePredicate) Statement {
	p.Repository = CanonicalRepo(p.Repository)
	p.Advisory = strings.TrimSpace(p.Advisory)
	return Statement{
		Type:          StatementType,
		Subject:       []ResourceDescriptor{{Name: p.Advisory, Digest: sha256Digest(p.Repository + "\x00" + strings.ToUpper(p.Advisory))}},
		PredicateType: PredicateTypeCertificate,
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
