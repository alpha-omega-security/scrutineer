package worker

import (
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaValidationError carries the formatted validator output for a report
// that did not match its skill's schema. wrap() treats it like
// FailOnThresholdError: the scan is marked failed but Scan.Report is kept so
// the operator can inspect what was produced.
type SchemaValidationError struct {
	Skill  string
	Detail string
}

func (e *SchemaValidationError) Error() string {
	return fmt.Sprintf("report.json failed schema validation for skill %q: %s", e.Skill, e.Detail)
}

const maxSchemaErrors = 8

// validateReportSchema compiles schemaJSON and validates report against it.
// Returns "" when valid, otherwise a one-line-per-failure summary capped at
// maxSchemaErrors. A schema that does not compile, or a report that is not
// JSON, returns a single line saying so; both are treated as validation
// failures rather than scan errors so a malformed schema cannot fail every
// scan in strict mode.
func validateReportSchema(schemaJSON, report string) string {
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
