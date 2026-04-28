// Package config loads scrutineer's YAML config file. The config is
// opt-in: without a config file, every value falls back to its compile-
// time default (see the flag definitions in cmd/scrutineer/main.go).
// Config overrides those defaults; command-line flags still win when set.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the path scrutineer checks for when -config is not set.
// Keeping it alongside the binary makes "drop a config next to it" work.
const DefaultPath = "./scrutineer.yaml"

// Config mirrors the supported YAML keys. Every field is optional; missing
// fields leave the corresponding flag at its built-in default.
type Config struct {
	Addr         string   `yaml:"addr"`
	Data         string   `yaml:"data"`
	Effort       string   `yaml:"effort"`
	DefaultModel string   `yaml:"default_model"`
	Models       []Model  `yaml:"models"`
	Skills       []string `yaml:"skills"`
	SkillsRepo   string   `yaml:"skills_repo"`
	NoDocker     *bool    `yaml:"no_docker"`
	RunnerImage  string   `yaml:"runner_image"`
	// EgressAllow extends the docker runner's egress proxy allowlist with
	// extra hostnames. Entries are appended to worker.DefaultEgressAllow,
	// not replacing it. "*.example.com" matches subdomains.
	EgressAllow []string `yaml:"egress_allow"`
	// Concurrency controls how many scans the worker runs in parallel.
	// 0 or negative leaves the built-in default (see queue.DefaultWorkerConcurrency).
	Concurrency int `yaml:"concurrency"`
}

// Model is a display-name plus the claude model id it resolves to. The
// shape matches web.Model so main.go can pipe one into the other without
// the two packages depending on each other.
type Model struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
}

// Load reads a YAML config from path. Returns (nil, nil) when the file
// does not exist and the caller passed "" or DefaultPath — making config
// fully opt-in. Explicit paths that don't exist are an error.
func Load(path string) (*Config, error) {
	explicit := path != "" && path != DefaultPath
	if path == "" {
		path = DefaultPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return nil, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}
