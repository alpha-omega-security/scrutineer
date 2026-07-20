package worker

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaValidationError carries the formatted validator output for a report
// that did not pass schema or skill-specific semantic validation. wrap() treats it like
// FailOnThresholdError: the scan is marked failed but Scan.Report is kept so
// the operator can inspect what was produced.
type SchemaValidationError struct {
	Skill  string
	Detail string
}

func (e *SchemaValidationError) Error() string {
	return fmt.Sprintf("report.json failed report validation for skill %q: %s", e.Skill, e.Detail)
}

const maxSchemaErrors = 8

// ValidateSkillReport validates both a skill's JSON Schema and any
// skill-specific semantic contract. Schema validation always runs first so a
// malformed report keeps the established JSON/schema error path.
func ValidateSkillReport(skillName, schemaJSON, report string) string {
	if detail := ValidateReportSchema(schemaJSON, report); detail != "" {
		return detail
	}
	return ValidateReportSemantics(skillName, report)
}

// ValidateReportSemantics checks report invariants that JSON Schema cannot
// express. It intentionally applies only to skills with an explicit contract;
// all other skills retain their existing schema-only validation behavior.
func ValidateReportSemantics(skillName, report string) string {
	if skillName != deepDiveSkillName {
		return ""
	}
	var parsed deepDiveSemanticReport
	if err := json.Unmarshal([]byte(report), &parsed); err != nil {
		return "report.json is not valid JSON: " + err.Error()
	}
	return validateDeepDiveSinkDispositions(parsed)
}

// ValidateReportSchema compiles schemaJSON and validates report against it.
// Returns "" when valid, otherwise a one-line-per-failure summary capped at
// maxSchemaErrors. A schema that does not compile, or a report that is not
// JSON, returns a single line saying so; both are treated as validation
// failures rather than scan errors so a malformed schema cannot fail every
// scan in strict mode.
//
// It is exported so the web API can offer skills a server-side validation
// endpoint that uses the exact same validator as the harness, sparing them
// from installing a JSON Schema library inside the runner container.
func ValidateReportSchema(schemaJSON, report string) string {
	c := jsonschema.NewCompiler()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schemaJSON))
	if err != nil {
		return "schema.json is not valid JSON: " + err.Error()
	}
	if err := c.AddResource("schema.json", doc); err != nil {
		return "schema.json could not be loaded: " + err.Error()
	}
	sch, err := c.Compile("schema.json")
	if err != nil {
		return "schema.json could not be compiled: " + err.Error()
	}

	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(report))
	if err != nil {
		return "report.json is not valid JSON: " + err.Error()
	}
	verr := sch.Validate(inst)
	if verr == nil {
		return ""
	}
	ve, ok := verr.(*jsonschema.ValidationError)
	if !ok {
		return verr.Error()
	}
	return formatValidationError(ve)
}

// formatValidationError flattens a jsonschema validation error into one line
// per leaf failure as "/json/pointer: message". The library's BasicOutput
// already produces a flat list; we just trim it to something readable in a
// scan log.
func formatValidationError(ve *jsonschema.ValidationError) string {
	out := ve.BasicOutput()
	var lines []string
	for _, u := range out.Errors {
		if u.Error == nil {
			continue
		}
		loc := u.InstanceLocation
		if loc == "" {
			loc = "/"
		}
		lines = append(lines, loc+": "+u.Error.String())
		if len(lines) >= maxSchemaErrors {
			lines = append(lines, fmt.Sprintf("... (%d more)", len(out.Errors)-maxSchemaErrors))
			break
		}
	}
	if len(lines) == 0 {
		return ve.Error()
	}
	return strings.Join(lines, "\n")
}

// deepDiveSemanticReport holds only the cross-reference fields needed to
// verify the inventory coverage invariant. Keeping this separate from finding
// ingestion means validation does not tighten unrelated report fields.
type deepDiveSemanticReport struct {
	Inventory []struct {
		ID string `json:"id"`
	} `json:"inventory"`
	Findings []struct {
		ID    string   `json:"id"`
		Sinks []string `json:"sinks"`
	} `json:"findings"`
	RuledOut []struct {
		Sinks []string `json:"sinks"`
	} `json:"ruled_out"`
}

func validateDeepDiveSinkDispositions(report deepDiveSemanticReport) string {
	inventory := make(map[string]struct{}, len(report.Inventory))
	inventoryOrder := make([]string, 0, len(report.Inventory))
	var errs []string
	for i, sink := range report.Inventory {
		id := strings.TrimSpace(sink.ID)
		if id == "" {
			errs = append(errs, fmt.Sprintf("inventory[%d] has an empty id", i))
			continue
		}
		if _, exists := inventory[id]; exists {
			errs = append(errs, fmt.Sprintf("inventory sink %s is duplicated", id))
			continue
		}
		inventory[id] = struct{}{}
		inventoryOrder = append(inventoryOrder, id)
	}

	findingSinks := make(map[string]struct{})
	for i, finding := range report.Findings {
		label := fmt.Sprintf("finding[%d]", i)
		if id := strings.TrimSpace(finding.ID); id != "" {
			label = "finding " + id
		}
		errs = append(errs, validateDispositionReferences(label, finding.Sinks, inventory, findingSinks)...)
	}
	ruledOutSinks := make(map[string]struct{})
	for i, ruledOut := range report.RuledOut {
		label := fmt.Sprintf("ruled_out[%d]", i)
		errs = append(errs, validateDispositionReferences(label, ruledOut.Sinks, inventory, ruledOutSinks)...)
	}

	for _, id := range inventoryOrder {
		_, found := findingSinks[id]
		_, ruledOut := ruledOutSinks[id]
		switch {
		case found && ruledOut:
			errs = append(errs, fmt.Sprintf("sink %s appears in both findings and ruled_out", id))
		case !found && !ruledOut:
			errs = append(errs, fmt.Sprintf("inventory sink %s has no disposition", id))
		}
	}
	return formatSemanticValidationErrors(errs)
}

func validateDispositionReferences(label string, sinks []string, inventory, dispositions map[string]struct{}) []string {
	var errs []string
	seen := make(map[string]struct{}, len(sinks))
	for _, rawID := range sinks {
		id := strings.TrimSpace(rawID)
		if _, repeated := seen[id]; repeated {
			errs = append(errs, fmt.Sprintf("%s repeats sink %s", label, id))
			continue
		}
		seen[id] = struct{}{}
		if _, known := inventory[id]; !known {
			errs = append(errs, fmt.Sprintf("%s references unknown sink %s", label, id))
			continue
		}
		dispositions[id] = struct{}{}
	}
	return errs
}

func formatSemanticValidationErrors(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	if len(errs) <= maxSchemaErrors {
		return strings.Join(errs, "\n")
	}
	return strings.Join(errs[:maxSchemaErrors], "\n") + fmt.Sprintf("\n... (%d more)", len(errs)-maxSchemaErrors)
}
