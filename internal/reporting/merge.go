package reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
)

// Input is one export to merge, with the name messages should call it by:
// the path as given, since curl -OJ names every instance's export
// identically and only the directory tells them apart.
type Input struct {
	Name   string
	Export Export
}

// Options tunes Merge.
type Options struct {
	// Severity, when set, requires every input to carry exactly this
	// minimum-severity floor, spelled as the ?severity= value the export was
	// generated with; "all" requires unfiltered inputs. The export carries
	// only aggregated counts, so a floor cannot be re-applied at merge time:
	// a laxer input would overstate the merged findings counts and a
	// stricter one understate them, which is why a mismatch is an error
	// rather than a warning.
	Severity string
	// AllowMixedPeriods turns ErrMixedPeriods into a warning. The merged
	// in_period figures then pool windows of different lengths and are a
	// corpus-wide total only in the loosest sense.
	AllowMixedPeriods bool
}

// ErrMixedPeriods is returned (wrapped, naming the keys) when the inputs
// were exported over different windows, such as a week export beside a
// month one. Their activity_in_period totals and in_period averages would
// pool two windows into one figure that is true of neither.
var ErrMixedPeriods = errors.New("inputs cover different windows")

// ReposScannedCaveat is appended to a merged report's measured_by. The
// per-source repository counts are each distinct within their instance,
// and the merged figure is their sum, which is exact only when the corpora
// are disjoint; the archived file has to say so itself, since a stderr
// warning does not survive archiving.
const ReposScannedCaveat = "repositories_scanned sums per-source distinct counts"

// Decode reads one export. It refuses a document whose fields are not
// exactly Export's at every level: an unknown field means the export comes
// from a scrutineer newer than this tool and would be dropped from the
// merge, a missing one that the export predates a field and would be
// merged as zero. The fix is the same either way, exporting every input
// from an instance at the tool's version, so the check runs before any
// merge rather than leaving one figure quietly wrong in the result.
func Decode(r io.Reader) (Export, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Export{}, err
	}
	var export Export
	if err := json.Unmarshal(raw, &export); err != nil {
		return Export{}, fmt.Errorf("not a /reporting JSON export: %w", err)
	}
	if export.GeneratedAt == "" || export.Period.EndsAt == "" {
		return Export{}, errors.New("not a /reporting JSON export (expected an object with generated_at and period.ends_at)")
	}
	stamps := map[string]*string{
		"generated_at":     &export.GeneratedAt,
		"period.ends_at":   &export.Period.EndsAt,
		"period.starts_at": export.Period.StartsAt,
	}
	for _, field := range sortedKeys(stamps) {
		if stamp := stamps[field]; stamp != nil {
			if _, err := time.Parse(time.RFC3339, *stamp); err != nil {
				return Export{}, fmt.Errorf("%s: %q is not an RFC 3339 timestamp", field, *stamp)
			}
		}
	}
	if err := checkShape(raw, export); err != nil {
		return Export{}, fmt.Errorf("%w: the document's shape differs from this tool's report.json; export every input from a scrutineer at the same version", err)
	}
	return export, nil
}

// checkShape compares the document's field names with Export's, level by
// level, by decoding the raw document and a re-encoding of its typed form
// to the same untyped tree. Values are not compared, only which keys exist.
func checkShape(raw []byte, export Export) error {
	var got, want any
	if err := json.Unmarshal(raw, &got); err != nil {
		return err
	}
	typed, err := json.Marshal(export)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(typed, &want); err != nil {
		return err
	}
	return shapeDiff(got, want, "")
}

func shapeDiff(got, want any, path string) error {
	switch want := want.(type) {
	case map[string]any:
		gotObj, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not an object", path)
		}
		for _, key := range sortedKeys(gotObj) {
			if _, ok := want[key]; !ok {
				return fmt.Errorf("unknown field %s", joinPath(path, key))
			}
		}
		for _, key := range sortedKeys(want) {
			gotVal, ok := gotObj[key]
			if !ok {
				return fmt.Errorf("missing field %s", joinPath(path, key))
			}
			if err := shapeDiff(gotVal, want[key], joinPath(path, key)); err != nil {
				return err
			}
		}
	case []any:
		gotList, ok := got.([]any)
		if !ok || len(gotList) != len(want) {
			return fmt.Errorf("%s is not an array of %d elements", path, len(want))
		}
		for i := range want {
			if err := shapeDiff(gotList[i], want[i], fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Merge folds the inputs into one export in the same shape, as if a single
// instance had scanned every input's corpus: counts summed, averages pooled
// by scans_averaged, rows keyed by date or model combined, and the union of
// the windows as the period. Warnings describe inputs that merged but look
// wrong (differing filters, a likely duplicate, mixed windows when
// allowed); an error means nothing was merged.
//
// The sums are only meaningful because the sources are discrete instances
// with disjoint corpora. Two exports of one instance would double-count
// overlapping scans, repositories active in both, and (in all_time) the
// older export's whole population, which the newer one already contains.
func Merge(inputs []Input, opts Options) (Export, []string, error) {
	if len(inputs) == 0 {
		return Export{}, nil, errors.New("no inputs to merge")
	}
	if opts.Severity != "" {
		if err := checkSeverity(inputs, opts.Severity); err != nil {
			return Export{}, nil, err
		}
	}
	var warnings []string
	keys := periodKeys(inputs)
	if len(keys) > 1 {
		if !opts.AllowMixedPeriods {
			return Export{}, nil, fmt.Errorf("%w (period keys: %s): the in_period figures would pool different windows",
				ErrMixedPeriods, strings.Join(keys, ", "))
		}
		warnings = append(warnings, fmt.Sprintf("inputs cover different windows (period keys: %s); the in_period figures pool them",
			strings.Join(keys, ", ")))
	}
	warnings = append(warnings, metadataWarnings(inputs)...)

	activity, err := mergeRows(pick(inputs, func(e Export) Activity { return e.Activity }))
	if err != nil {
		return Export{}, nil, err
	}
	activity.MeasuredBy = withCaveat(activity.MeasuredBy)
	inPeriod, err := mergeRows(pick(inputs, func(e Export) Averages { return e.CostAverages.InPeriod }))
	if err != nil {
		return Export{}, nil, err
	}
	allTime, err := mergeRows(pick(inputs, func(e Export) Averages { return e.CostAverages.AllTime }))
	if err != nil {
		return Export{}, nil, err
	}
	days, err := mergeGroups(gather(inputs, func(e Export) []DayRow { return e.ByDay }), func(r DayRow) string { return r.Date })
	if err != nil {
		return Export{}, nil, err
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Date > days[j].Date })
	models, err := mergeGroups(gather(inputs, func(e Export) []ModelRow { return e.ByModel }), func(r ModelRow) string { return r.Model })
	if err != nil {
		return Export{}, nil, err
	}
	sortModelRows(models)

	sources := flattenSources(inputs)
	period, err := mergePeriod(inputs, keys, len(sources))
	if err != nil {
		return Export{}, nil, err
	}
	generated, err := extremeStamp(pick(inputs, func(e Export) string { return e.GeneratedAt }), true)
	if err != nil {
		return Export{}, nil, err
	}
	return Export{
		GeneratedAt: generated,
		Period:      period,
		Filters:     mergeFilters(inputs),
		Activity:    activity,
		CostAverages: CostAverages{
			Population: firstNonEmpty(pick(inputs, func(e Export) string { return e.CostAverages.Population })),
			InPeriod:   inPeriod,
			AllTime:    allTime,
		},
		ByModel: models,
		ByDay:   days,
		Sources: sources,
	}, warnings, nil
}

// sortModelRows puts the rows in the order the reporting page uses —
// findings, then cost, then name — so a merged export reads like a single
// instance's. The single-instance test in internal/web holds the two
// orderings to each other.
func sortModelRows(rows []ModelRow) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		if a.CostUSD != b.CostUSD {
			return a.CostUSD > b.CostUSD
		}
		return a.Model < b.Model
	})
}

// checkSeverity enforces Options.Severity against every input's recorded
// floor. The level is resolved the way the server's ?severity= parser
// resolves it, so the option accepts what the export URL accepts.
func checkSeverity(inputs []Input, want string) error {
	level := strings.ToLower(strings.TrimSpace(want))
	if level == "all" {
		for _, in := range inputs {
			if floor := in.Export.Filters.MinimumSeverity; floor != nil {
				return fmt.Errorf("%s was exported with a minimum severity of %q, and an unfiltered merge needs unfiltered inputs", in.Name, *floor)
			}
		}
		return nil
	}
	canonical, err := canonicalSeverity(level, inputs)
	if err != nil {
		return err
	}
	for _, in := range inputs {
		floor := in.Export.Filters.MinimumSeverity
		if floor != nil && strings.EqualFold(*floor, canonical) {
			continue
		}
		have := "no severity floor"
		if floor != nil {
			have = fmt.Sprintf("a %q floor", *floor)
		}
		return fmt.Errorf("%s was exported with %s; a merged %s report needs every input exported with ?severity=%s",
			in.Name, have, canonical, level)
	}
	return nil
}

// canonicalSeverity resolves a lowercased level against the levels the
// inputs name in filters.severity_ordering, folding case and accepting
// "moderate" for Medium as the server's displaySeverity does. MixedSeverity
// is deliberately not a level: a merged file carrying it can satisfy no
// floor. Inputs naming no levels at all leave the spelling as typed, and
// the case-insensitive comparison in checkSeverity still applies.
func canonicalSeverity(level string, inputs []Input) (string, error) {
	if level == "moderate" {
		level = "medium"
	}
	ordering := firstOrdering(inputs)
	if len(ordering) == 0 {
		return level, nil
	}
	for _, known := range ordering {
		if strings.EqualFold(known, level) {
			return known, nil
		}
	}
	return "", fmt.Errorf("unknown severity %q (one of: %s, or all)", level, strings.Join(ordering, ", "))
}

func firstOrdering(inputs []Input) []string {
	for _, in := range inputs {
		if len(in.Export.Filters.SeverityOrdering) > 0 {
			return in.Export.Filters.SeverityOrdering
		}
	}
	return nil
}

// periodKeys lists the distinct windows the inputs were exported over,
// sorted. A merged input counts for the windows of the exports folded into
// it rather than for "merged", so re-merging stays exactly as strict as
// merging the originals would have been.
func periodKeys(inputs []Input) []string {
	seen := map[string]struct{}{}
	for _, in := range inputs {
		if len(in.Export.Sources) == 0 {
			seen[in.Export.Period.Key] = struct{}{}
			continue
		}
		for _, src := range in.Export.Sources {
			seen[src.PeriodKey] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

// metadataWarnings flags inputs that merged but probably should not have.
func metadataWarnings(inputs []Input) []string {
	var warnings []string
	first := inputs[0]
	for _, in := range inputs[1:] {
		if !reflect.DeepEqual(in.Export.Filters, first.Export.Filters) {
			warnings = append(warnings, fmt.Sprintf("filters in %s differ from %s", in.Name, first.Name))
		}
	}
	// Two exports of one instance share its all-time averages until a new
	// scan completes, whatever their generated_at say; two instances with
	// their own corpora agree on seven averages only by coincidence.
	seen := map[Averages]string{}
	for _, in := range inputs {
		fingerprint := in.Export.CostAverages.AllTime
		if prev, dup := seen[fingerprint]; dup {
			warnings = append(warnings, fmt.Sprintf("%s and %s have identical all-time cost averages -- two exports of the same instance?", in.Name, prev))
			continue
		}
		seen[fingerprint] = in.Name
	}
	return warnings
}

// mergeFilters keeps the first input's filters, with the floor replaced by
// MixedSeverity when the inputs disagree on it: the merged counts then mix
// inputs filtered at different levels, so no single floor is true of them,
// and the file must not claim the first input's.
func mergeFilters(inputs []Input) Filters {
	filters := inputs[0].Export.Filters
	for _, in := range inputs[1:] {
		if !sameFloor(filters.MinimumSeverity, in.Export.Filters.MinimumSeverity) {
			mixed := MixedSeverity
			filters.MinimumSeverity = &mixed
			break
		}
	}
	return filters
}

func sameFloor(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// mergePeriod is the union of the inputs' windows: earliest start, latest
// end, and no start at all if any input was unbounded (interval=all).
func mergePeriod(inputs []Input, keys []string, sourceCount int) (Period, error) {
	var starts, ends []string
	unbounded := false
	for _, in := range inputs {
		p := in.Export.Period
		if p.StartsAt == nil {
			unbounded = true
		} else {
			starts = append(starts, *p.StartsAt)
		}
		ends = append(ends, p.EndsAt)
	}
	period := Period{
		Key:   "merged",
		Label: "Merged",
		Meaning: fmt.Sprintf("union of %d source reports (period keys: %s) assumed to come from discrete "+
			"scanner instances with disjoint corpora; totals summed; rows present in more than one source "+
			"have averages weighted by scans_averaged; all_time averages pooled across sources",
			sourceCount, strings.Join(keys, ", ")),
	}
	end, err := extremeStamp(ends, true)
	if err != nil {
		return Period{}, err
	}
	period.EndsAt = end
	if !unbounded {
		start, err := extremeStamp(starts, false)
		if err != nil {
			return Period{}, err
		}
		period.StartsAt = &start
	}
	return period, nil
}

// extremeStamp returns the latest (or earliest) of the RFC 3339 stamps, as
// written: the chosen string itself rather than a re-formatting, so the
// merged document keeps the server's own spelling.
func extremeStamp(stamps []string, latest bool) (string, error) {
	var best string
	var bestAt time.Time
	for i, stamp := range stamps {
		at, err := time.Parse(time.RFC3339, stamp)
		if err != nil {
			return "", fmt.Errorf("timestamp %q: %w", stamp, err)
		}
		if i == 0 || (latest && at.After(bestAt)) || (!latest && at.Before(bestAt)) {
			best, bestAt = stamp, at
		}
	}
	return best, nil
}

// flattenSources lists every original export behind the inputs. An input
// that is itself a merged file contributes the sources recorded in it, not
// an entry of its own, so the provenance of a re-merge is complete and
// independent of how the originals were grouped on the way.
func flattenSources(inputs []Input) []Source {
	sources := make([]Source, 0, len(inputs))
	for _, in := range inputs {
		if len(in.Export.Sources) > 0 {
			sources = append(sources, in.Export.Sources...)
			continue
		}
		p := in.Export.Period
		sources = append(sources, Source{
			File:            in.Name,
			GeneratedAt:     in.Export.GeneratedAt,
			MinimumSeverity: in.Export.Filters.MinimumSeverity,
			PeriodKey:       p.Key,
			StartsAt:        p.StartsAt,
			EndsAt:          p.EndsAt,
		})
	}
	return sources
}

// withCaveat appends ReposScannedCaveat to a measured_by text once, so a
// merged file merged again does not stack it.
func withCaveat(measuredBy string) string {
	switch {
	case strings.Contains(measuredBy, ReposScannedCaveat):
		return measuredBy
	case measuredBy == "":
		return ReposScannedCaveat
	}
	return measuredBy + "; " + ReposScannedCaveat
}

func firstNonEmpty(values []string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func pick[T any](inputs []Input, field func(Export) T) []T {
	out := make([]T, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, field(in.Export))
	}
	return out
}

func gather[T any](inputs []Input, field func(Export) []T) []T {
	var out []T
	for _, in := range inputs {
		out = append(out, field(in.Export)...)
	}
	return out
}

// mergeGroups merges the rows that share a key, in first-seen key order.
// Rows present in only one input pass through mergeRows unchanged.
func mergeGroups[T any](rows []T, key func(T) string) ([]T, error) {
	var order []string
	groups := map[string][]T{}
	for _, row := range rows {
		k := key(row)
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], row)
	}
	merged := make([]T, 0, len(order))
	for _, k := range order {
		row, err := mergeRows(groups[k])
		if err != nil {
			return nil, err
		}
		merged = append(merged, row)
	}
	return merged, nil
}

// mergeRule is a struct field's `merge` tag: how Merge folds that field
// across the rows being combined.
type mergeRule string

const (
	// ruleKey identifies the row (a date, a model); every row in a group
	// carries the same value.
	ruleKey mergeRule = "key"
	// ruleSum is an additive count or total.
	ruleSum mergeRule = "sum"
	// ruleWeight is additive, and is the weight of the row's ruleMean fields.
	ruleWeight mergeRule = "weight"
	// ruleMean is a per-scan mean, pooled across rows by their ruleWeight
	// field: Σ(mean × weight) / Σ weight, the mean a single instance would
	// have computed over the union of the populations.
	ruleMean mergeRule = "mean"
	// ruleFirst is descriptive text; the first non-empty value is kept.
	ruleFirst mergeRule = "first"
)

// mergePlan is one row type's rules by field index, checked against the
// field types once per type.
type mergePlan struct {
	rules  []mergeRule
	weight int // index of the ruleWeight field, or noWeight
}

// noWeight is mergePlan.weight for a row type with no ruleWeight field.
const noWeight = -1

// planFor reads a row type's merge tags. A field without a valid tag is an
// error: that is what turns a figure added to the export into a decision
// about how it merges, instead of a number quietly summed.
func planFor(t reflect.Type) (mergePlan, error) {
	plan := mergePlan{rules: make([]mergeRule, t.NumField()), weight: noWeight}
	for i := range t.NumField() {
		field := t.Field(i)
		rule := mergeRule(field.Tag.Get("merge"))
		if !ruleFits(rule, field.Type.Kind()) {
			return mergePlan{}, fmt.Errorf("%s.%s: %s field has no merge rule (tag %q); tag it key, sum, weight, mean or first",
				t.Name(), field.Name, field.Type, rule)
		}
		if rule == ruleWeight {
			if plan.weight != noWeight {
				return mergePlan{}, fmt.Errorf("%s: more than one weight field", t.Name())
			}
			plan.weight = i
		}
		plan.rules[i] = rule
	}
	if slices.Contains(plan.rules, ruleMean) && plan.weight == noWeight {
		return mergePlan{}, fmt.Errorf("%s: mean fields need a weight field", t.Name())
	}
	return plan, nil
}

func ruleFits(rule mergeRule, kind reflect.Kind) bool {
	switch rule {
	case ruleKey, ruleFirst:
		return kind == reflect.String
	case ruleSum:
		return kind == reflect.Int || kind == reflect.Float64
	case ruleWeight:
		return kind == reflect.Int
	case ruleMean:
		return kind == reflect.Float64
	}
	return false
}

// mergeRows folds rows of one type into one, field by field, by each
// field's merge tag. The rows of a group all describe the same key, and a
// single row comes back unchanged.
//
//nolint:ireturn // T is a concrete struct at every call site, not an interface
func mergeRows[T any](rows []T) (T, error) {
	var out T
	plan, err := planFor(reflect.TypeOf(out))
	if err != nil {
		return out, err
	}
	if len(rows) == 0 {
		return out, nil
	}
	values := make([]reflect.Value, len(rows))
	for i, row := range rows {
		values[i] = reflect.ValueOf(row)
	}
	dst := reflect.ValueOf(&out).Elem()
	for i, rule := range plan.rules {
		switch rule {
		case ruleKey:
			if err := mergeKey(dst.Field(i), values, i, dst.Type().Field(i).Name); err != nil {
				return out, err
			}
		case ruleFirst:
			mergeFirst(dst.Field(i), values, i)
		case ruleSum, ruleWeight:
			mergeSum(dst.Field(i), values, i)
		case ruleMean:
			mergeMean(dst.Field(i), values, i, plan.weight)
		}
	}
	return out, nil
}

func mergeKey(dst reflect.Value, rows []reflect.Value, field int, name string) error {
	key := rows[0].Field(field).String()
	for _, row := range rows[1:] {
		if other := row.Field(field).String(); other != key {
			return fmt.Errorf("%s: rows %q and %q merged as one", name, key, other)
		}
	}
	dst.SetString(key)
	return nil
}

func mergeFirst(dst reflect.Value, rows []reflect.Value, field int) {
	for _, row := range rows {
		if s := row.Field(field).String(); s != "" {
			dst.SetString(s)
			return
		}
	}
}

func mergeSum(dst reflect.Value, rows []reflect.Value, field int) {
	if dst.Kind() == reflect.Int {
		var sum int64
		for _, row := range rows {
			sum += row.Field(field).Int()
		}
		dst.SetInt(sum)
		return
	}
	var sum float64
	for _, row := range rows {
		sum += row.Field(field).Float()
	}
	dst.SetFloat(sum)
}

// mergeMean pools a per-scan mean by the rows' weights. Zero total weight
// (no scan to average anywhere) leaves the mean at zero, as the server
// reports an empty population.
func mergeMean(dst reflect.Value, rows []reflect.Value, field, weightField int) {
	var weighted, weight float64
	for _, row := range rows {
		w := float64(row.Field(weightField).Int())
		weighted += row.Field(field).Float() * w
		weight += w
	}
	if weight > 0 {
		dst.SetFloat(weighted / weight)
	}
}
