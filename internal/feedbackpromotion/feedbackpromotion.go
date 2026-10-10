// Package feedbackpromotion defines host-owned known_non_findings entries that
// are promoted from analyst decisions after repeated independent confirmation.
// The functions are pure JSON transformations with no database access.
package feedbackpromotion

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxReasonChars bounds why_safe. It matches the analyst review reason limit.
const MaxReasonChars = 4096

const (
	listKey       = "known_non_findings"
	provenanceKey = "promoted_from"
)

// ErrNotObject is returned when the contract is not a JSON object.
var ErrNotObject = errors.New("threat model is not a JSON object")

// ErrMalformedProvenance is returned when known_non_findings is not an array
// but carries promoted_from, so host provenance cannot be verified or stripped.
var ErrMalformedProvenance = errors.New("known_non_findings is not an array but carries promoted_from")

// Confirmation is one independent re-check that relied on the decision.
type Confirmation struct {
	ScanID uint   `json:"scan_id"`
	Commit string `json:"commit"`
}

// Provenance marks an entry as host-owned and names its source decision.
type Provenance struct {
	ReviewID      uint           `json:"review_id"`
	FindingID     uint           `json:"finding_id"`
	SourceCommit  string         `json:"source_commit"`
	Confirmations []Confirmation `json:"confirmations"`
}

// Entry is a known_non_findings item carrying host-owned provenance.
type Entry struct {
	ReportedAs   string     `json:"reported_as"`
	WhySafe      string     `json:"why_safe"`
	PromotedFrom Provenance `json:"promoted_from"`
}

// Source is the decision snapshot an entry is built from.
type Source struct {
	ReviewID      uint
	FindingID     uint
	SourceCommit  string
	CWE           string
	Path          string
	Title         string
	Reason        string
	Confirmations []Confirmation
}

// NewEntry builds a bounded entry from a decision snapshot.
func NewEntry(src Source) Entry {
	parts := []string{"Analyst-dismissed finding"}
	if src.CWE != "" {
		parts = append(parts, src.CWE)
	}
	parts = append(parts, "in "+src.Path)
	reported := strings.Join(parts, " ")
	if title := strings.TrimSpace(src.Title); title != "" {
		reported += ": " + title
	}
	reason := []rune(strings.TrimSpace(src.Reason))
	if len(reason) > MaxReasonChars {
		reason = reason[:MaxReasonChars]
	}
	return Entry{
		ReportedAs: reported,
		WhySafe:    string(reason),
		PromotedFrom: Provenance{
			ReviewID:      src.ReviewID,
			FindingID:     src.FindingID,
			SourceCommit:  src.SourceCommit,
			Confirmations: src.Confirmations,
		},
	}
}

// provenance reports whether an item carries promoted_from and its review ID.
// An item that is not an object, or has no such key, is model-authored.
func provenance(item json.RawMessage) (present bool, reviewID uint) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(item, &fields) != nil {
		return false, 0
	}
	raw, ok := fields[provenanceKey]
	if !ok {
		return false, 0
	}
	var p struct {
		ReviewID uint `json:"review_id"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return true, 0
	}
	return true, p.ReviewID
}

func decodeObject(model string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(model), &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, ErrNotObject
	}
	return object, nil
}

func decodeItems(object map[string]json.RawMessage) ([]json.RawMessage, error) {
	raw, ok := object[listKey]
	if !ok {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%s is not an array: %w", listKey, err)
	}
	return items, nil
}

func encode(object map[string]json.RawMessage, items []json.RawMessage) (string, error) {
	if items == nil {
		items = []json.RawMessage{}
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	object[listKey] = raw
	out, err := json.MarshalIndent(object, "", "  ")
	return string(out), err
}

// Merge inserts or replaces the item promoted from entry's review. Every other
// key and item is left untouched.
func Merge(model string, entry Entry) (string, error) {
	object, err := decodeObject(model)
	if err != nil {
		return "", err
	}
	items, err := decodeItems(object)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	next := make([]json.RawMessage, 0, len(items)+1)
	placed := false
	for _, item := range items {
		if present, id := provenance(item); present && id == entry.PromotedFrom.ReviewID {
			if !placed {
				next = append(next, raw)
				placed = true
			}
			continue
		}
		next = append(next, item)
	}
	if !placed {
		next = append(next, raw)
	}
	return encode(object, next)
}

// Preserve carries host-promoted items from previous into a refreshed contract.
// Any promoted_from the model wrote into next is removed first so a model
// cannot forge host provenance.
func Preserve(previous, next string) (string, error) {
	fresh, err := decodeObject(next)
	if err != nil {
		return "", err
	}
	items, err := decodeItems(fresh)
	if err != nil {
		// A malformed list without provenance is the model's own business. One
		// that carries promoted_from cannot be stripped, so reject the refresh
		// and keep the previous contract rather than save forged provenance.
		if HasPromoted(string(fresh[listKey])) {
			return "", ErrMalformedProvenance
		}
		return next, nil //nolint:nilerr
	}
	kept := make([]json.RawMessage, 0, len(items))
	changed := false
	for _, item := range items {
		if present, _ := provenance(item); present {
			changed = true
			continue
		}
		kept = append(kept, item)
	}
	for _, item := range hostItems(previous) {
		kept = append(kept, item)
		changed = true
	}
	if !changed {
		return next, nil
	}
	return encode(fresh, kept)
}

// hostItems returns the valid promoted items of an earlier contract.
func hostItems(previous string) []json.RawMessage {
	if strings.TrimSpace(previous) == "" {
		return nil
	}
	old, err := decodeObject(previous)
	if err != nil {
		return nil
	}
	items, err := decodeItems(old)
	if err != nil {
		return nil
	}
	var out []json.RawMessage
	seen := map[uint]bool{}
	for _, item := range items {
		if present, id := provenance(item); present && id != 0 && !seen[id] {
			seen[id] = true
			out = append(out, item)
		}
	}
	return out
}

// Filter drops promoted items whose review is no longer eligible. Input that is
// not a parsable object is returned unchanged. A malformed list that carries
// promoted_from is dropped whole, since its provenance cannot be checked.
func Filter(model string, eligible func(reviewID uint) bool) string {
	object, err := decodeObject(model)
	if err != nil {
		return model
	}
	items, err := decodeItems(object)
	if err != nil {
		if !HasPromoted(string(object[listKey])) {
			return model
		}
		delete(object, listKey)
		out, err := json.MarshalIndent(object, "", "  ")
		if err != nil {
			return model
		}
		return string(out)
	}
	kept := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		if present, id := provenance(item); present && (id == 0 || !eligible(id)) {
			continue
		}
		kept = append(kept, item)
	}
	if len(kept) == len(items) {
		return model
	}
	out, err := encode(object, kept)
	if err != nil {
		return model
	}
	return out
}

// StripPromoted drops every promoted item. Promotions belong only to the
// repository contract, so any promoted_from in a raw threat-model scan report
// was copied or forged by the model and must not reach a skill.
func StripPromoted(model string) string {
	return Filter(model, func(uint) bool { return false })
}

// HasPromoted reports whether the contract text may contain promoted items.
func HasPromoted(model string) bool {
	return strings.Contains(model, `"`+provenanceKey+`"`)
}

// IsObject reports whether the contract is a JSON object.
func IsObject(model string) bool {
	_, err := decodeObject(model)
	return err == nil
}
