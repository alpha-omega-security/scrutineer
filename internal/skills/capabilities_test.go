package skills

import (
	"strings"
	"testing"
)

func TestCapabilityMetadata(t *testing.T) {
	path := writeSkill(t, t.TempDir(), "capability", `---
name: capability
description: Test runtime requirements.
metadata:
  scrutineer.requires_commands: [cargo, node]
  scrutineer.requires_features: [network-egress, fuse]
  scrutineer.degraded_mode: true
---
Use reduced coverage when runtime support is missing.
`)
	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	row, err := parsed.ToModel("local")
	if err != nil {
		t.Fatal(err)
	}
	if row.RequiresCommands != "cargo\nnode" || row.RequiresFeatures != "network-egress\nfuse" || !row.DegradedMode {
		t.Fatalf("requirements not persisted: %+v", row)
	}
}

func TestCapabilityMetadataRejectsInvalid(t *testing.T) {
	for _, metadata := range []string{
		"scrutineer.requires_commands: cargo",
		"scrutineer.requires_commands: [4]",
		"scrutineer.requires_commands: ['']",
		"scrutineer.requires_commands: [cargo, cargo]",
		"scrutineer.requires_commands: ['/usr/bin/cargo']",
		"scrutineer.requires_commands: ['cargo --version']",
		"scrutineer.requires_commands: ['$(touch pwned)']",
		"scrutineer.requires_features: [network]",
		"scrutineer.requires_features: [fuse, fuse]",
		"scrutineer.degraded_mode: 'true'",
	} {
		t.Run(metadata, func(t *testing.T) {
			path := writeSkill(t, t.TempDir(), "capability", "---\nname: capability\ndescription: Runtime requirements.\nmetadata:\n  "+metadata+"\n---\nbody\n")
			if _, err := ParseFile(path); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
	if err := ValidateCapabilities([]string{strings.Repeat("x", 129)}, nil); err == nil {
		t.Fatal("accepted oversized command")
	}
	if err := ValidateCapabilities(make([]string, 65), nil); err == nil {
		t.Fatal("accepted oversized list")
	}
}
