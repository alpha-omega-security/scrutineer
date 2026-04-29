package main

import (
	"testing"
	"time"

	"scrutineer/internal/config"
)

func fullConfig() *config.Config {
	yes := true
	return &config.Config{
		Addr:            "0.0.0.0:9090",
		Data:            "/var/lib/scrutineer",
		Effort:          "medium",
		NoDocker:        &yes,
		RunnerImage:     "custom:v1",
		SkillsRepo:      "https://example.com/skills.git",
		Skills:          []string{"/etc/skills"},
		Concurrency:     8,
		Clone:           "full",
		ScanTimeout:     "30m",
		MaxTurns:        200,
		AnthropicBaseURL: "https://proxy.corp.com/v1",
	}
}

func TestFlagsMerge_configFillsUnset(t *testing.T) {
	cfg := fullConfig()
	f := &flags{addr: "127.0.0.1:8080", cloneMode: "shallow", set: map[string]bool{}}
	f.merge(cfg)
	if f.addr != cfg.Addr {
		t.Errorf("addr = %q, want %q", f.addr, cfg.Addr)
	}
	if f.dataDir != cfg.Data {
		t.Errorf("dataDir = %q", f.dataDir)
	}
	if !f.noDocker {
		t.Errorf("noDocker not applied")
	}
	if f.concurrency != 8 {
		t.Errorf("concurrency = %d", f.concurrency)
	}
	if !f.fullClone() {
		t.Errorf("cloneMode = %q, want full", f.cloneMode)
	}
	if len(f.skillLocal) != 1 || f.skillLocal[0] != "/etc/skills" {
		t.Errorf("skillLocal = %v", f.skillLocal)
	}
	if f.scanTimeout != 30*time.Minute {
		t.Errorf("scanTimeout = %v", f.scanTimeout)
	}
	if f.maxTurns != 200 {
		t.Errorf("maxTurns = %d", f.maxTurns)
	}
	if f.anthropicBaseURL != cfg.AnthropicBaseURL {
		t.Errorf("anthropicBaseURL = %q, want %q", f.anthropicBaseURL, cfg.AnthropicBaseURL)
	}
}

func TestFlagsMerge_cliFlagWins(t *testing.T) {
	cfg := fullConfig()
	f := &flags{
		addr: "127.0.0.1:8080", cloneMode: "shallow", concurrency: 2,
		anthropicBaseURL: "https://my-flag.example.com/v1",
		set:             map[string]bool{"addr": true, "clone": true, "concurrency": true, "anthropic-base-url": true},
	}
	f.merge(cfg)
	if f.addr != "127.0.0.1:8080" {
		t.Errorf("addr overridden despite explicit flag: %q", f.addr)
	}
	if f.cloneMode != "shallow" {
		t.Errorf("cloneMode overridden despite explicit flag: %q", f.cloneMode)
	}
	if f.concurrency != 2 {
		t.Errorf("concurrency overridden despite explicit flag: %d", f.concurrency)
	}
	// effort wasn't in set, so config still applies
	if f.effort != cfg.Effort {
		t.Errorf("effort = %q, want %q", f.effort, cfg.Effort)
	}
	if f.anthropicBaseURL != "https://my-flag.example.com/v1" {
		t.Errorf("anthropicBaseURL overridden despite explicit flag: %q", f.anthropicBaseURL)
	}
}

func TestFlagsMerge_zeroConfigLeavesDefaults(t *testing.T) {
	f := &flags{addr: "127.0.0.1:8080", concurrency: 4, scanTimeout: time.Hour, set: map[string]bool{}}
	f.merge(&config.Config{})
	if f.addr != "127.0.0.1:8080" {
		t.Errorf("empty config clobbered addr: %q", f.addr)
	}
	if f.concurrency != 4 {
		t.Errorf("zero concurrency clobbered default: %d", f.concurrency)
	}
	if f.scanTimeout != time.Hour {
		t.Errorf("empty scan_timeout clobbered default: %v", f.scanTimeout)
	}
	if f.anthropicBaseURL != "" {
		t.Errorf("empty config set anthropicBaseURL: %q", f.anthropicBaseURL)
	}
}

func TestBaseURLHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"https://api.anthropic.com", "api.anthropic.com"},
		{"https://my-proxy.corp.com/v1", "my-proxy.corp.com"},
		{"https://my-proxy.corp.com:8443/v1", "my-proxy.corp.com"},
		{"http://localhost:4000", "localhost"},
		{"://broken", ""},
	}
	for _, tc := range cases {
		if got := baseURLHost(tc.in); got != tc.want {
			t.Errorf("baseURLHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
