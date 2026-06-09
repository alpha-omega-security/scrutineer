// Package skills loads claude-code skill directories from disk and upserts
// them into the database. A skill is a directory containing a SKILL.md file
// with YAML frontmatter plus optional supporting files; see the spec at
// https://agentskills.io/specification.
//
// agentskills.io spec violations (name format, field lengths) are lenient:
// they log a warning and the skill loads anyway, per the client guide. The
// scrutineer.* metadata keys are scrutineer's own and are checked strictly:
// an unknown key, a bad output_kind, or an unsupported scrutineer.version is
// a hard parse error and stops server startup.
package skills

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"scrutineer/internal/db"
)

const (
	skillFile           = "SKILL.md"
	schemaFile          = "schema.json"
	maxNameLen          = 64
	maxDescLen          = 1024
	maxCompatLen        = 500
	metaOutputFile      = "scrutineer.output_file"
	metaOutputKind      = "scrutineer.output_kind"
	metaMaxTurns        = "scrutineer.max_turns"
	metaModel           = "scrutineer.model"
	metaVersion         = "scrutineer.version"
	metaMinConfidence   = "scrutineer.min_confidence"
	metaReportOn        = "scrutineer.report_on"
	metaFailOn          = "scrutineer.fail_on"
	metaRequiresRemote  = "scrutineer.requires_remote"
	metaRequiresProfile = "scrutineer.requires_profile"
	metaPaths           = "scrutineer.paths"
	metaIgnorePaths     = "scrutineer.ignore_paths"
	metaRequires        = "scrutineer.requires"

	// SchemaVersion is the only scrutineer.version this build accepts.
	// Skills omitting the key are treated as version 1. Bump when the
	// scrutineer.* metadata keys change shape so old skill repos fail
	// loudly instead of silently misbehaving.
	SchemaVersion = 1
)

// scrutineerKeys is the closed set of scrutineer.* metadata keys this
// build understands. Anything else under that prefix is rejected at
// parse time so a typo like scrutineer.outputkind surfaces immediately
// rather than after a worker falls through to freeform.
var scrutineerKeys = map[string]bool{
	metaOutputFile:      true,
	metaOutputKind:      true,
	metaMaxTurns:        true,
	metaModel:           true,
	metaVersion:         true,
	metaMinConfidence:   true,
	metaReportOn:        true,
	metaFailOn:          true,
	metaRequiresRemote:  true,
	metaRequiresProfile: true,
	metaPaths:           true,
	metaIgnorePaths:     true,
	metaRequires:        true,
}

var confidenceLevels = map[string]bool{"low": true, "medium": true, "high": true}
var severityLevels = map[string]bool{"Low": true, "Medium": true, "High": true, "Critical": true}

// OutputKinds is the set of values scrutineer.output_kind may take.
// "freeform" and the empty string both mean "store the report verbatim
// without parsing"; everything else maps to a parser in
// internal/worker/skill.go.
var OutputKinds = map[string]bool{
	"":                true,
	"freeform":        true,
	"findings":        true,
	"maintainers":     true,
	"repo_metadata":   true,
	"packages":        true,
	"advisories":      true,
	"dependents":      true,
	"dependencies":    true,
	"finding_dedup":   true,
	"verify":          true,
	"revalidate":      true,
	"breaking_change": true,
	"mitigation":      true,
	"release_watch":   true,
	"subprojects":     true,
	"repo_overview":   true,
	"posture":         true,
	"patch":           true,
	"threat_model":    true,
	"exposure":        true,
}

var nameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ModelValidator gates the scrutineer.model metadata key. When non-nil, a
// skill declaring a model preference the validator rejects gets a warning and
// the field is left empty (the scan falls back to the high tier).
// Wired from main.go after the model list is configured.
var ModelValidator func(string) bool

// ProfileValidator gates the scrutineer.requires_profile metadata key.
// When non-nil, a skill declaring a profile the validator rejects fails
// at parse time so a typo surfaces at startup rather than at scan time.
// Wired from main.go after the profile registry is set.
var ProfileValidator func(string) bool

// Parsed is a SKILL.md-plus-neighbours as extracted from disk. It mirrors the
// Skill model shape so the caller can persist it without further work.
type Parsed struct {
	Name          string
	Description   string
	License       string
	Compatibility string
	AllowedTools  string
	Metadata      map[string]any

	Body            string
	SchemaJSON      string
	OutputFile      string
	OutputKind      string
	MaxTurns        int
	Model           string
	MinConfidence   string
	ReportOn        string
	FailOn          string
	RequiresRemote  bool
	RequiresProfile string
	Paths           []string
	IgnorePaths     []string
	Requires        []string

	SourcePath string // absolute path to the skill directory
	SourceHash string // sha256 of SKILL.md + schema.json contents

	Warnings []string
}

type frontmatter struct {
	Name          string         `yaml:"name"`
	Description   string         `yaml:"description"`
	License       string         `yaml:"license"`
	Compatibility string         `yaml:"compatibility"`
	AllowedTools  string         `yaml:"allowed-tools"`
	Metadata      map[string]any `yaml:"metadata"`
}

// ParseFile reads a single SKILL.md (with its sibling schema.json if any)
// and returns a Parsed. Errors here are hard failures: unparseable YAML,
// missing description, or IO trouble. Softer issues land in p.Warnings.
func ParseFile(path string) (*Parsed, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	fm, body, err := splitFrontmatter(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var f frontmatter
	if err := yaml.Unmarshal(fm, &f); err != nil {
		return nil, fmt.Errorf("yaml %s: %w", path, err)
	}
	if strings.TrimSpace(f.Description) == "" {
		return nil, fmt.Errorf("%s: description is required", path)
	}
	p := &Parsed{
		Name:          strings.TrimSpace(f.Name),
		Description:   strings.TrimSpace(f.Description),
		License:       strings.TrimSpace(f.License),
		Compatibility: strings.TrimSpace(f.Compatibility),
		AllowedTools:  strings.TrimSpace(f.AllowedTools),
		Metadata:      f.Metadata,
		Body:          strings.TrimSpace(body),
		SourcePath:    filepath.Dir(path),
	}
	p.validate()
	if err := p.validateMetadata(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.extractMetadataKeys()
	p.loadSchema()
	p.hash(raw)
	return p, nil
}

var frontmatterRE = regexp.MustCompile(`(?s)\A---\r?\n(.*?)\r?\n---\r?\n?(.*)\z`)

func splitFrontmatter(raw []byte) (fm []byte, body string, err error) {
	m := frontmatterRE.FindSubmatch(raw)
	if m == nil {
		return nil, "", fmt.Errorf("no yaml frontmatter delimited by ---")
	}
	return m[1], string(m[2]), nil
}

func (p *Parsed) validate() {
	dir := filepath.Base(p.SourcePath)
	if p.Name == "" {
		p.Warnings = append(p.Warnings, "name missing, using directory name")
		p.Name = dir
	}
	if p.Name != dir {
		p.Warnings = append(p.Warnings, fmt.Sprintf("name %q does not match directory %q", p.Name, dir))
	}
	if len(p.Name) > maxNameLen {
		p.Warnings = append(p.Warnings, fmt.Sprintf("name %q exceeds %d characters", p.Name, maxNameLen))
	}
	if !nameRE.MatchString(p.Name) {
		p.Warnings = append(p.Warnings, fmt.Sprintf("name %q is not spec-conformant (lowercase, digits, hyphens only)", p.Name))
	}
	if len(p.Description) > maxDescLen {
		p.Warnings = append(p.Warnings, fmt.Sprintf("description exceeds %d characters", maxDescLen))
	}
	if len(p.Compatibility) > maxCompatLen {
		p.Warnings = append(p.Warnings, fmt.Sprintf("compatibility exceeds %d characters", maxCompatLen))
	}
}

// validateMetadata checks the scrutineer.* keys strictly. agentskills.io
// spec violations stay as warnings (see validate); scrutineer-specific
// keys are a closed set under our control so typos are hard errors.
func (p *Parsed) validateMetadata() error {
	for k := range p.Metadata {
		if strings.HasPrefix(k, "scrutineer.") && !scrutineerKeys[k] {
			return fmt.Errorf("unknown metadata key %q", k)
		}
	}
	if v, ok := p.Metadata[metaVersion]; ok {
		got, ok := v.(int)
		if !ok {
			return fmt.Errorf("%s must be an integer, got %T", metaVersion, v)
		}
		if got != SchemaVersion {
			return fmt.Errorf("%s %d not supported (this build accepts %d)", metaVersion, got, SchemaVersion)
		}
	}
	if v, ok := p.Metadata[metaOutputKind]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s must be a string, got %T", metaOutputKind, v)
		}
		if !OutputKinds[strings.TrimSpace(s)] {
			return fmt.Errorf("%s %q is not a recognised parser", metaOutputKind, s)
		}
	}
	if v, ok := p.Metadata[metaMaxTurns]; ok {
		if _, ok := v.(int); !ok {
			return fmt.Errorf("%s must be an integer, got %T", metaMaxTurns, v)
		}
	}
	if v, ok := p.Metadata[metaRequiresRemote]; ok {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%s must be a boolean, got %T", metaRequiresRemote, v)
		}
	}
	if err := checkRequiresProfile(p.Metadata); err != nil {
		return err
	}
	if err := checkEnum(p.Metadata, metaMinConfidence, confidenceLevels); err != nil {
		return err
	}
	if err := checkEnum(p.Metadata, metaReportOn, severityLevels); err != nil {
		return err
	}
	if err := checkEnum(p.Metadata, metaFailOn, severityLevels); err != nil {
		return err
	}
	if err := checkGlobList(p.Metadata, metaPaths); err != nil {
		return err
	}
	if err := checkGlobList(p.Metadata, metaIgnorePaths); err != nil {
		return err
	}
	if err := checkStringList(p.Metadata, metaRequires); err != nil {
		return err
	}
	return nil
}

func checkStringList(m map[string]any, key string) error {
	v, ok := m[key]
	if !ok {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("%s must be a list of strings, got %T", key, v)
	}
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return fmt.Errorf("%s[%d] must be a string, got %T", key, i, item)
		}
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s[%d] must not be empty", key, i)
		}
	}
	return nil
}

func checkGlobList(m map[string]any, key string) error {
	v, ok := m[key]
	if !ok {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("%s must be a list of strings, got %T", key, v)
	}
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return fmt.Errorf("%s[%d] must be a string, got %T", key, i, item)
		}
		if err := ValidateGlob(s); err != nil {
			return fmt.Errorf("%s[%d] %q: %w", key, i, s, err)
		}
	}
	return nil
}

func checkRequiresProfile(m map[string]any) error {
	v, ok := m[metaRequiresProfile]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%s must be a string, got %T", metaRequiresProfile, v)
	}
	s = strings.TrimSpace(s)
	if s == "" || s == "default" {
		return fmt.Errorf("%s must name a registered profile, got %q", metaRequiresProfile, s)
	}
	if ProfileValidator != nil && !ProfileValidator(s) {
		return fmt.Errorf("%s %q is not a registered profile", metaRequiresProfile, s)
	}
	return nil
}

func checkEnum(m map[string]any, key string, allowed map[string]bool) error {
	v, ok := m[key]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%s must be a string, got %T", key, v)
	}
	if !allowed[strings.TrimSpace(s)] {
		return fmt.Errorf("%s %q is not a valid level", key, s)
	}
	return nil
}

func (p *Parsed) extractMetadataKeys() {
	if v, ok := p.Metadata[metaOutputFile].(string); ok {
		p.OutputFile = strings.TrimSpace(v)
	}
	if v, ok := p.Metadata[metaOutputKind].(string); ok {
		p.OutputKind = strings.TrimSpace(v)
	}
	if v, ok := p.Metadata[metaMaxTurns].(int); ok && v > 0 {
		p.MaxTurns = v
	}
	if v, ok := p.Metadata[metaModel].(string); ok {
		m := strings.TrimSpace(v)
		if m != "" {
			if ModelValidator == nil || ModelValidator(m) {
				p.Model = m
			} else {
				p.Warnings = append(p.Warnings, fmt.Sprintf("model preference %q is not a configured model or tier, ignoring", m))
			}
		}
	}
	if v, ok := p.Metadata[metaMinConfidence].(string); ok {
		p.MinConfidence = strings.TrimSpace(v)
	}
	if v, ok := p.Metadata[metaReportOn].(string); ok {
		p.ReportOn = strings.TrimSpace(v)
	}
	if v, ok := p.Metadata[metaFailOn].(string); ok {
		p.FailOn = strings.TrimSpace(v)
	}
	if v, ok := p.Metadata[metaRequiresRemote].(bool); ok {
		p.RequiresRemote = v
	}
	if v, ok := p.Metadata[metaRequiresProfile].(string); ok {
		p.RequiresProfile = strings.TrimSpace(v)
	}
	p.Paths = extractStringList(p.Metadata, metaPaths)
	p.IgnorePaths = extractStringList(p.Metadata, metaIgnorePaths)
	p.Requires = extractStringList(p.Metadata, metaRequires)
}

func extractStringList(m map[string]any, key string) []string {
	v, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, item := range v {
		if s, ok := item.(string); ok {
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p *Parsed) loadSchema() {
	b, err := os.ReadFile(filepath.Join(p.SourcePath, schemaFile))
	if err != nil {
		return
	}
	p.SchemaJSON = string(b)
}

func (p *Parsed) hash(skillMD []byte) {
	h := sha256.New()
	h.Write(skillMD)
	if p.SchemaJSON != "" {
		h.Write([]byte(p.SchemaJSON))
	}
	p.SourceHash = hex.EncodeToString(h.Sum(nil))
}

// ToModel converts a Parsed to a Skill DB row with Source pre-filled.
// Version is left at zero; the caller bumps it relative to any existing row.
func (p *Parsed) ToModel(source string) (*db.Skill, error) {
	meta := ""
	if len(p.Metadata) > 0 {
		b, err := json.Marshal(p.Metadata)
		if err != nil {
			return nil, fmt.Errorf("marshal metadata: %w", err)
		}
		meta = string(b)
	}
	return &db.Skill{
		Name:            p.Name,
		Description:     p.Description,
		License:         p.License,
		Compatibility:   p.Compatibility,
		AllowedTools:    p.AllowedTools,
		Metadata:        meta,
		Body:            p.Body,
		SchemaJSON:      p.SchemaJSON,
		OutputFile:      p.OutputFile,
		OutputKind:      p.OutputKind,
		MaxTurns:        p.MaxTurns,
		Model:           p.Model,
		MinConfidence:   p.MinConfidence,
		ReportOn:        p.ReportOn,
		FailOn:          p.FailOn,
		RequiresRemote:  p.RequiresRemote,
		RequiresProfile: p.RequiresProfile,
		Paths:           JoinPatterns(p.Paths),
		IgnorePaths:     JoinPatterns(p.IgnorePaths),
		Requires:        JoinPatterns(p.Requires),
		Active:          true,
		Source:          source,
		SourcePath:      p.SourcePath,
		SourceHash:      p.SourceHash,
	}, nil
}
