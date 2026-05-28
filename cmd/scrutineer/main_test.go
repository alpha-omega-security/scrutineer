package main

import (
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/worker"
)

func fullConfig() *config.Config {
	return &config.Config{
		Addr:             "0.0.0.0:9090",
		Data:             "/var/lib/scrutineer",
		Effort:           "medium",
		NoDocker:         new(true),
		Hardened:         new(true),
		RunnerImage:      "custom:v1",
		SkillsRepo:       "https://example.com/skills.git",
		Skills:           []string{"/etc/skills"},
		Concurrency:      8,
		Clone:            "full",
		ScanTimeout:      "30m",
		MaxTurns:         200,
		AnthropicBaseURL: "https://proxy.corp.com/v1",
		ForkOrg:          "fork-central",
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
	if !f.hardened {
		t.Errorf("hardened not applied")
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
	if f.forkOrg != cfg.ForkOrg {
		t.Errorf("forkOrg = %q, want %q", f.forkOrg, cfg.ForkOrg)
	}
}

func TestFlagsMerge_cliFlagWins(t *testing.T) {
	cfg := fullConfig()
	f := &flags{
		addr: "127.0.0.1:8080", cloneMode: "shallow", concurrency: 2,
		anthropicBaseURL: "https://my-flag.example.com/v1",
		set:              map[string]bool{"addr": true, "clone": true, "concurrency": true, "anthropic-base-url": true},
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

func TestFlagsMerge_hardenedCliWinsOverConfig(t *testing.T) {
	// CLI hardened=false must not be overridden by config hardened:true.
	cfg := &config.Config{Hardened: new(true)}
	f := &flags{set: map[string]bool{"hardened": true}}
	f.merge(cfg)
	if f.hardened {
		t.Errorf("CLI --hardened=false was overridden by config")
	}
}

func TestBuildEgressAllow_defaultIncludesConfigAndAnthropicHost(t *testing.T) {
	cfg := &config.Config{EgressAllow: []string{"artifactory.internal", "*.mycorp.net"}}
	allow := buildEgressAllow(false, cfg, "https://proxy.corp.com/v1", quietLog())

	if !slices.Contains(allow, "*.ecosyste.ms") {
		t.Errorf("default mode dropped DefaultEgressAllow entries: %v", allow)
	}
	if !slices.Contains(allow, "artifactory.internal") || !slices.Contains(allow, "*.mycorp.net") {
		t.Errorf("default mode did not honour egress_allow: %v", allow)
	}
	if !slices.Contains(allow, "proxy.corp.com") {
		t.Errorf("default mode did not auto-add anthropic base URL host: %v", allow)
	}
}

func TestBuildEgressAllow_hardenedDropsConfigKeepsAnthropic(t *testing.T) {
	cfg := &config.Config{EgressAllow: []string{"artifactory.internal"}}
	allow := buildEgressAllow(true, cfg, "https://proxy.corp.com/v1", quietLog())

	if slices.Contains(allow, "*.ecosyste.ms") {
		t.Errorf("hardened leaked DefaultEgressAllow entries: %v", allow)
	}
	if slices.Contains(allow, "artifactory.internal") {
		t.Errorf("hardened honoured egress_allow when it must not: %v", allow)
	}
	if !slices.Contains(allow, "*.anthropic.com") || !slices.Contains(allow, worker.HostGatewayAlias) {
		t.Errorf("hardened did not include HardenedEgressAllow entries: %v", allow)
	}
	if !slices.Contains(allow, "proxy.corp.com") {
		t.Errorf("hardened dropped the anthropic base URL host: %v", allow)
	}
}

func TestBuildEgressAllow_hardenedNilConfig(t *testing.T) {
	allow := buildEgressAllow(true, nil, "", quietLog())
	if len(allow) != len(worker.HardenedEgressAllow) {
		t.Errorf("hardened minimal allow = %v, want exactly HardenedEgressAllow", allow)
	}
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
