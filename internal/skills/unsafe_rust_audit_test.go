package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBundledAuditUnsafeRustMetadata checks the audit-unsafe-rust skill's
// metadata and path filters, and that the vendored upstream method still
// carries every section ID the wrapper cites.
func TestBundledAuditUnsafeRustMetadata(t *testing.T) {
	dir := filepath.Join("..", "..", "skills", "audit-unsafe-rust")
	skill, err := ParseFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if skill.OutputKind != "findings" || skill.Model != "high" || skill.MaxTurns != 48 || skill.MinConfidence != "high" || skill.SchemaJSON == "" {
		t.Fatalf("invalid audit metadata: %+v", skill)
	}
	for _, path := range []string{"src/lib.rs", "crates/core/src/raw.rs", "build.rs", "Cargo.toml", "vendor/foo/src/lib.rs",
		// Checked-in generated Rust ships in the crate and must stay in the inventory.
		"generated/bindings.rs", "crates/sys/src/__generated__/ffi.rs",
	} {
		if !PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("excluded %s", path)
		}
	}
	for _, path := range []string{"target/debug/build/out.rs", "crates/x/target/release/gen.rs", "crates/x/target/debug/build/x-1/out/generated/bindings.rs"} {
		if PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("included %s", path)
		}
	}

	for _, text := range []string{"`include!`", "whatever its extension", "Checked-in generated Rust", "`OUT_DIR`", "`$RUST_STD_SRC`"} {
		if !strings.Contains(skill.Body, text) {
			t.Errorf("SKILL.md body missing %q", text)
		}
	}
	// The prompt points at $RUST_STD_SRC for std contracts under any profile,
	// so the shared runner image every profile builds on must set it.
	runner, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile.runner"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runner), "ENV RUST_STD_SRC=") {
		t.Error("Dockerfile.runner must set RUST_STD_SRC for audit-unsafe-rust")
	}

	// The method is vendored from google/rust-skills. The wrapper cites its
	// section IDs, so a re-sync that renames or drops one must fail here
	// rather than leave the prompt pointing at nothing (see UPSTREAM.md).
	ref, err := os.ReadFile(filepath.Join(dir, "references", "unsafe-rust-review.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ref), "github.com/google/rust-skills") || strings.HasPrefix(string(ref), "---") {
		t.Error("vendored method must keep its provenance header and have its upstream frontmatter stripped")
	}
	for _, id := range []string{
		"fact.classify", "conv.anti-gullibility", "conv.dedup", "comment.operation", "comment.contract",
		"comment.still-hold", "evidence.caller-code", "dep.caller-adversarial", "dep.trait-laws", "dep.hostile",
		"doc.complete", "doc.folklore", "doc.hidden-obligations", "rej.no-panic", "rej.trait-law",
		"ref.creation", "ref.uninit", "hazard", "axiom",
	} {
		tag := "`[" + id + "]`"
		if !strings.Contains(skill.Body, tag) {
			t.Errorf("wrapper no longer cites %s; drop it from this list", tag)
		}
		if !strings.Contains(string(ref), tag) {
			t.Errorf("vendored method missing section %s cited by SKILL.md", tag)
		}
	}
	for _, name := range []string{"UPSTREAM.md", "LICENSE.upstream.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing provenance file %s: %v", name, err)
		}
	}
	if strings.Contains(skill.Body, "UPSTREAM.md") {
		t.Error("SKILL.md body is the model prompt; keep maintainer provenance in frontmatter comments")
	}
}

// Triage routes unsafe Rust by source evidence, not project type: the
// unsafe-rust mode must enqueue both Rust-relevant memory audits and keep
// the exclude pathspecs in glob form, since the short ':!' form does not
// match top-level target/ or tests/ directories.
func TestTriageUnsafeRustMode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "skills", "triage", "references", "modes.md"))
	if err != nil {
		t.Fatal(err)
	}
	modes := string(raw)
	_, section, ok := strings.Cut(modes, "\n## unsafe-rust\n")
	if !ok {
		t.Fatal("triage modes missing unsafe-rust section")
	}
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	for _, text := range []string{
		"Enqueue both `audit-unsafe-rust` and `audit-memory`",
		"git grep -nw unsafe -- '*.rs'",
		"':(exclude,glob)**/target/**'",
		"':(exclude,glob)**/vendor/**'",
		"#[cfg(test)]",
		"forbid(unsafe_code)",
		"does not depend on what kind of software",
		"run the same `git grep` again from that manifest's directory",
		"exits with status 1 when it finds no matches",
	} {
		if !strings.Contains(section, text) {
			t.Errorf("unsafe-rust mode missing %q", text)
		}
	}
	if strings.Contains(section, "':!:") {
		t.Error("unsafe-rust mode uses short ':!' excludes, which miss top-level directories")
	}
}

// Rust crates that vendor C or C++ get audit-memory regardless of project
// type or whether the vendored code was modified.
func TestTriageNativeMemoryMode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "skills", "triage", "references", "modes.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), "\n## native-memory\n")
	if !ok {
		t.Fatal("triage modes missing native-memory section")
	}
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	for _, text := range []string{
		"Enqueue `audit-memory` for a match",
		"whether or not this repository has modified it",
		"':(glob)**/Cargo.toml'",
		"':(glob)**/*.c'",
		"':(exclude,glob)**/target/**'",
		"':(glob)**/build.rs'",
		"':(glob)**/build/**/*.rs'",
		".gitmodules",
		"belongs to a Rust project",
		"belongs to a separate project",
		"exits with status 1 when it finds",
	} {
		if !strings.Contains(section, text) {
			t.Errorf("native-memory mode missing %q", text)
		}
	}
	// Vendored C is the point of this mode; excluding it would defeat it.
	for _, text := range []string{"exclude,glob)**/vendor/", "exclude,glob)**/third_party/", "':!:"} {
		if strings.Contains(section, text) {
			t.Errorf("native-memory mode must not contain %q", text)
		}
	}
}
