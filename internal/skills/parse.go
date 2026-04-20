// Package skills loads claude-code skill directories from disk and upserts
// them into the database. A skill is a directory containing a SKILL.md file
// with YAML frontmatter plus optional supporting files; see the spec at
// https://agentskills.io/specification.
//
// Lenient parsing: we warn on spec violations but load the skill anyway, in
// line with the client-implementation guide. Only an unparseable SKILL.md or
// a missing description causes a skip.
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
	skillFile      = "SKILL.md"
	schemaFile     = "schema.json"
	maxNameLen     = 64
	maxDescLen     = 1024
	maxCompatLen   = 500
	metaOutputFile = "scrutineer.output_file"
	metaOutputKind = "scrutineer.output_kind"
)

var nameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Parsed is a SKILL.md-plus-neighbours as extracted from disk. It mirrors the
// Skill model shape so the caller can persist it without further work.
type Parsed struct {
	Name        string
	Description string
	License     string
	Compatibility string
	AllowedTools  string
	Metadata      map[string]any

	Body       string
	SchemaJSON string
	OutputFile string
	OutputKind string

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

func (p *Parsed) extractMetadataKeys() {
	if v, ok := p.Metadata[metaOutputFile].(string); ok {
		p.OutputFile = strings.TrimSpace(v)
	}
	if v, ok := p.Metadata[metaOutputKind].(string); ok {
		p.OutputKind = strings.TrimSpace(v)
	}
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
		Name:          p.Name,
		Description:   p.Description,
		License:       p.License,
		Compatibility: p.Compatibility,
		AllowedTools:  p.AllowedTools,
		Metadata:      meta,
		Body:          p.Body,
		SchemaJSON:    p.SchemaJSON,
		OutputFile:    p.OutputFile,
		OutputKind:    p.OutputKind,
		Active:        true,
		Source:        source,
		SourcePath:    p.SourcePath,
		SourceHash:    p.SourceHash,
	}, nil
}
