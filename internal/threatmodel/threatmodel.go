// Package threatmodel parses the parts of a threat-model report that the Go
// side has to act on, rather than hand through to a skill verbatim.
//
// Until now nothing in Go read a field out of a threat model: the document
// moves from Repository.ThreatModel through stageThreatModel to
// ./threat_model.json as opaque text, and only skills look inside it. Controls
// are the first part that the worker itself has to interpret, because matching
// a finding's file against a control's paths is a decision about that finding,
// made before any skill runs.
//
// Parsing is deliberately partial. A Model unmarshals only the fields declared
// here and ignores everything else in the document, so a threat model that
// grows new sections — or that predates controls entirely — still parses. The
// package never rejects a model for what it does not understand; the only
// errors it returns are for controls that are present and malformed.
package threatmodel

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"scrutineer/internal/skills"
)

// Provenance values follow the convention the rest of the threat-model schema
// uses: a documented claim cites a file:line or URL that can be re-read, an
// inferred one is the model's own reading of the code.
const (
	ProvenanceDocumented = "documented"
	ProvenanceInferred   = "inferred"
)

// Kind is an open enum. These are the kinds the schema names, but a model may
// carry one this build has never heard of, and that is not an error: an
// unknown kind still matches paths and still tells a verifier that the author
// believed something guards this code. Consumers that special-case a kind
// (an authorization control implying an authenticated-user prerequisite, say)
// must treat every other value as "a control, effect unknown".
const (
	KindAuthorization   = "authorization"
	KindSandbox         = "sandbox"
	KindInputValidation = "input-validation"
	KindCSRF            = "csrf"
	KindRateLimit       = "rate-limit"
	KindOther           = "other"
)

// Control is one design-level mitigation the threat model claims is in force.
//
// It is a claim, not a proof. A matched control does not make a finding a
// false positive; it names something a verifier has to either demonstrate a
// bypass of or explain away before the finding stands.
type Control struct {
	// ID is unique within a model and is what downstream records cite.
	ID string `json:"id"`
	// Kind is an open enum; see the Kind constants.
	Kind string `json:"kind"`
	// Protects is what this control sits in front of.
	Protects Protects `json:"protects"`
	// Assumptions are the conditions under which the control actually
	// holds — "requests reach this package only through the authenticated
	// router". They are the first thing a bypass argument attacks.
	Assumptions []string `json:"assumptions,omitempty"`
	Provenance  string   `json:"provenance"`
	// Source backs a documented claim: file:line or a URL.
	Source string `json:"source,omitempty"`
}

// Protects is a control's scope. Paths are globs in the same dialect the rest
// of the product uses for path patterns (skills.Match); EntryPoints name
// entries in the model's own entry_points table.
//
// A control with neither is not scoped to anything and cannot be matched. That
// is a defect in the model rather than a control that protects everything, and
// Validate says so.
type Protects struct {
	Paths       []string `json:"paths,omitempty"`
	EntryPoints []string `json:"entry_points,omitempty"`
}

// Model is the subset of a threat-model report this package reads.
type Model struct {
	Controls []Control `json:"controls,omitempty"`
}

// Parse reads a threat-model document. An empty document is not an error: a
// repository with no operator override, or a model written before controls
// existed, yields a Model with no controls and no complaint.
//
// Parse does not validate. Callers that are about to act on the controls call
// Validate; callers that only want to know whether any exist do not have to.
func Parse(raw string) (*Model, error) {
	if strings.TrimSpace(raw) == "" {
		return &Model{}, nil
	}
	var m Model
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("parse threat model: %w", err)
	}
	return &m, nil
}

// Validate reports the first structural problem in the model's controls.
//
// The checks are the ones a matcher depends on and JSON Schema cannot express
// on its own: unique ids, at least one scope, and globs the shared matcher can
// actually evaluate. An unrecognised kind is deliberately not an error.
func (m *Model) Validate() error {
	if m == nil {
		return nil
	}
	seen := make(map[string]int, len(m.Controls))
	for i, c := range m.Controls {
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("controls[%d]: id is required", i)
		}
		if first, dup := seen[c.ID]; dup {
			return fmt.Errorf("controls[%d]: duplicate id %q, first used by controls[%d]", i, c.ID, first)
		}
		seen[c.ID] = i
		if strings.TrimSpace(c.Kind) == "" {
			return fmt.Errorf("controls[%d] (%s): kind is required", i, c.ID)
		}
		switch c.Provenance {
		case ProvenanceDocumented, ProvenanceInferred:
		default:
			return fmt.Errorf("controls[%d] (%s): provenance must be %q or %q, got %q",
				i, c.ID, ProvenanceDocumented, ProvenanceInferred, c.Provenance)
		}
		if len(c.Protects.Paths) == 0 && len(c.Protects.EntryPoints) == 0 {
			return fmt.Errorf("controls[%d] (%s): protects needs at least one of paths or entry_points", i, c.ID)
		}
		for j, p := range c.Protects.Paths {
			if strings.TrimSpace(p) == "" {
				return fmt.Errorf("controls[%d] (%s): protects.paths[%d] is empty", i, c.ID, j)
			}
			if err := skills.ValidateGlob(p); err != nil {
				return fmt.Errorf("controls[%d] (%s): protects.paths[%d] %q is not a valid glob: %w", i, c.ID, j, p, err)
			}
		}
	}
	return nil
}

// MatchPath returns the controls whose protects.paths cover the given
// repository-relative file, in the order they appear in the model.
//
// The path must be relative to the repository root, in the same namespace the
// globs are authored in. Callers holding a path from a subpath-scoped scan
// have to rebase it first; this package cannot tell the two apart, and
// matching a subpath-relative path against root-relative globs returns an
// empty set rather than an error, which is the quiet failure worth avoiding.
func (m *Model) MatchPath(path string) []Control {
	if m == nil || path == "" {
		return nil
	}
	path = strings.TrimPrefix(path, "./")
	var out []Control
	for _, c := range m.Controls {
		for _, pattern := range c.Protects.Paths {
			if skills.Match(pattern, path) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// MatchEntryPoint returns the controls that name the given entry point. The
// comparison is exact: entry-point names come from the model's own
// entry_points table, not from user input, so a near miss is an authoring
// error worth surfacing rather than smoothing over.
func (m *Model) MatchEntryPoint(name string) []Control {
	if m == nil || name == "" {
		return nil
	}
	var out []Control
	for _, c := range m.Controls {
		for _, ep := range c.Protects.EntryPoints {
			if ep == name {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// IDs returns the sorted, de-duplicated ids of a control set. It exists so
// that anything recording "which controls matched" — a note, a rubric row, a
// log line — is stable across runs rather than reflecting model ordering.
func IDs(controls []Control) []string {
	if len(controls) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(controls))
	out := make([]string, 0, len(controls))
	for _, c := range controls {
		if _, dup := seen[c.ID]; dup {
			continue
		}
		seen[c.ID] = struct{}{}
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}
