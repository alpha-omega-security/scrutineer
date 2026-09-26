// Package reflection defines bounded, evidence-backed operational scan notes.
package reflection

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MaxScans   = 128
	MaxNotes   = 100
	MaxText    = 1000
	Window     = 8192
	MaxExcerpt = 4096
	TailBudget = MaxExcerpt / 2
)

type Source struct {
	ScanID    uint   `json:"scan_id"`
	Stage     string `json:"stage"`
	Commit    string `json:"commit"`
	Status    string `json:"status"`
	Missing   bool   `json:"missing"`
	Truncated bool   `json:"truncated"`
	Excerpt   string `json:"excerpt"`
}

type Input struct {
	TriageScanID uint     `json:"triage_scan_id"`
	Sources      []Source `json:"sources"`
}

type Note struct {
	Stage    string `json:"stage"`
	ScanID   uint   `json:"scan_id"`
	Kind     string `json:"kind"`
	Summary  string `json:"summary"`
	Evidence string `json:"evidence"`
}

type Report struct {
	Notes []Note `json:"notes"`
}

type StoredNote struct {
	Note
	TriageScanID     uint   `json:"triage_scan_id"`
	ReflectionScanID uint   `json:"reflection_scan_id"`
	Commit           string `json:"commit"`
}

// Excerpt examines a bounded prefix for errors and reserves half the budget
// for the final output. Callers fetch only these windows, never a full log.
func Excerpt(prefix, tail string) string {
	var out strings.Builder
	for line := range strings.SplitSeq(prefix, "\n") {
		lower := strings.ToLower(line)
		match := false
		for _, marker := range []string{"error", "failed", "cannot", "unable", "giving up", "not found"} {
			match = match || strings.Contains(lower, marker)
		}
		if match && out.Len()+len(line)+1 <= TailBudget {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	tail = clipTail(tail, TailBudget)
	out.WriteString(tail)
	return strings.ToValidUTF8(out.String(), "")
}

func clipTail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func ValidateInput(input Input) error {
	if input.TriageScanID == 0 || len(input.Sources) == 0 || len(input.Sources) > MaxScans {
		return fmt.Errorf("invalid reflection input")
	}
	seen := map[uint]bool{}
	for _, source := range input.Sources {
		if source.ScanID == 0 || seen[source.ScanID] || strings.TrimSpace(source.Stage) == "" || len(source.Excerpt) > MaxExcerpt || !utf8.ValidString(source.Excerpt) {
			return fmt.Errorf("invalid reflection source %d", source.ScanID)
		}
		seen[source.ScanID] = true
	}
	return nil
}

func Validate(input Input, report Report) error {
	if err := ValidateInput(input); err != nil {
		return err
	}
	stages := map[string]bool{}
	sources := map[uint]Source{}
	for _, source := range input.Sources {
		stages[source.Stage] = true
		sources[source.ScanID] = source
	}
	if len(report.Notes) != len(stages) {
		return fmt.Errorf("reflection must report exactly one outcome per stage")
	}
	seen := map[string]bool{}
	for _, note := range report.Notes {
		source, ok := sources[note.ScanID]
		if !ok || source.Stage != note.Stage || seen[note.Stage] {
			return fmt.Errorf("invalid or duplicate reflection source for stage %q", note.Stage)
		}
		seen[note.Stage] = true
		for _, other := range input.Sources {
			if other.Stage == note.Stage && other.Missing && note.Kind != "missing_transcript" {
				return fmt.Errorf("stage %q must record its missing transcript", note.Stage)
			}
		}
		if strings.TrimSpace(note.Summary) == "" || len(note.Summary) > MaxText || len(note.Evidence) > MaxText {
			return fmt.Errorf("invalid reflection text for stage %q", note.Stage)
		}
		if err := validateNote(source, note); err != nil {
			return err
		}
	}
	return nil
}

// Preserve keeps host-owned notes when a new model replaces the contract.
// Models cannot manufacture or remove operational evidence through this path.
func Preserve(previous, next string) (string, error) {
	var old, fresh map[string]json.RawMessage
	if strings.TrimSpace(previous) != "" {
		if err := json.Unmarshal([]byte(previous), &old); err != nil {
			// The workbench historically accepts any JSON value. A valid
			// non-object has no notes to retain and must not block refresh.
			var typeErr *json.UnmarshalTypeError
			if !errors.As(err, &typeErr) {
				return "", err
			}
		}
	}
	if err := json.Unmarshal([]byte(next), &fresh); err != nil {
		return "", err
	}
	if fresh == nil {
		return "", fmt.Errorf("threat model must be an object")
	}
	delete(fresh, "reflection_notes")
	if notes, ok := old["reflection_notes"]; ok {
		fresh["reflection_notes"] = notes
	}
	raw, err := json.MarshalIndent(fresh, "", "  ")
	return string(raw), err
}

func validateNote(source Source, note Note) error {
	switch note.Kind {
	case "missing_transcript":
		if !source.Missing || note.Evidence != "" {
			return fmt.Errorf("missing transcript claim must match its source")
		}
	case "no_observation":
		if source.Missing || note.Evidence != "" {
			return fmt.Errorf("empty observation must have a readable transcript and no evidence")
		}
	case "tool_failure", "missing_dependency", "reproducer_entrypoint":
		if source.Missing || strings.TrimSpace(note.Evidence) == "" || !strings.Contains(source.Excerpt, note.Evidence) {
			return fmt.Errorf("reflection evidence must quote the staged excerpt")
		}
	default:
		return fmt.Errorf("unknown reflection kind %q", note.Kind)
	}
	return nil
}

// Merge changes only reflection_notes. Replays replace the same run/stage;
// retention is ordered by source triage ID, not model completion order.
func Merge(model string, input Input, report Report, scanID uint) (string, error) {
	if err := Validate(input, report); err != nil {
		return "", err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(model), &object); err != nil {
		return "", err
	}
	if object == nil {
		return "", fmt.Errorf("reflection requires an existing threat-model object")
	}
	var notes []StoredNote
	if raw, ok := object["reflection_notes"]; ok {
		if err := json.Unmarshal(raw, &notes); err != nil {
			return "", err
		}
	}
	byKey := map[string]StoredNote{}
	for _, note := range notes {
		byKey[fmt.Sprintf("%d:%s", note.TriageScanID, note.Stage)] = note
	}
	commits := map[uint]string{}
	for _, source := range input.Sources {
		commits[source.ScanID] = source.Commit
	}
	for _, note := range report.Notes {
		stored := StoredNote{Note: note, TriageScanID: input.TriageScanID, ReflectionScanID: scanID, Commit: commits[note.ScanID]}
		key := fmt.Sprintf("%d:%s", input.TriageScanID, note.Stage)
		if prior, ok := byKey[key]; ok && prior.ReflectionScanID > scanID {
			continue
		}
		byKey[key] = stored
	}
	notes = make([]StoredNote, 0, len(byKey))
	for _, note := range byKey {
		notes = append(notes, note)
	}
	sort.Slice(notes, func(i, j int) bool {
		if notes[i].TriageScanID != notes[j].TriageScanID {
			return notes[i].TriageScanID > notes[j].TriageScanID
		}
		return notes[i].Stage < notes[j].Stage
	})
	if len(notes) > MaxNotes {
		notes = notes[:MaxNotes]
	}
	raw, err := json.Marshal(notes)
	if err != nil {
		return "", err
	}
	object["reflection_notes"] = raw
	result, err := json.MarshalIndent(object, "", "  ")
	return string(result), err
}
