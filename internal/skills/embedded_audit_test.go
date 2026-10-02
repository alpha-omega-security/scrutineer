package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledEmbeddedAuditMetadata(t *testing.T) {
	dir := filepath.Join("..", "..", "skills", "audit-embedded")
	skill, err := ParseFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if skill.Name != "audit-embedded" || skill.OutputKind != "findings" || skill.Model != "high" || skill.MaxTurns != 48 || skill.MinConfidence != "high" || skill.SchemaJSON == "" {
		t.Fatalf("invalid audit metadata: %+v", skill)
	}
	for _, path := range []string{"firmware/ota.py", "src/main.c", "boot/bootloader.c", "partitions.csv"} {
		if !PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("excluded %s", path)
		}
	}
	for _, path := range []string{"build/app.c", "vendor/sdk/driver.c", "third_party/lwip/tcp.c", "images/fw.bin", "images/fw.hex", "out/fw.elf"} {
		if PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("included %s", path)
		}
	}
	ref, err := os.ReadFile(filepath.Join(dir, "references", "threat-model.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Findings persist these links as references, so they must name the
	// immutable 1.0RC tag. Branch links keep moving after release.
	if !strings.Contains(string(ref), "/1.0RC/") || strings.Contains(string(ref), "/master/") || strings.Contains(string(ref), "/blob/main/") {
		t.Error("ISVS links must be pinned to the 1.0RC tag, not a moving branch")
	}
	for _, section := range []string{"ISVS 1.0RC", "Firmware updates and rollback", "Boot chain", "Provisioning and device credentials", "Debug interfaces and physical access", "Device communication", "Evidence discipline"} {
		if !strings.Contains(string(ref), section) {
			t.Errorf("reference missing %q", section)
		}
	}
}
