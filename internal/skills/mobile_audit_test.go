package skills

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestBundledMobileAuditMetadata(t *testing.T) {
	dir := filepath.Join("..", "..", "skills", "audit-mobile")
	skill, err := ParseFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if skill.Name != "audit-mobile" || skill.OutputKind != "findings" || skill.Model != "high" || skill.MaxTurns != 48 || skill.MinConfidence != "high" || skill.SchemaJSON == "" {
		t.Fatalf("invalid audit metadata: %+v", skill)
	}
	// Only build output at the root or inside an app module is excluded, so a
	// source package named build stays in scope.
	for _, path := range []string{"app/src/main/java/com/example/notes/DeepLinkActivity.kt", "NotesApp/Info.plist", "app/src/main/AndroidManifest.xml", "lib/main.dart", "ios/Runner/AppDelegate.swift", "app/src/main/java/com/example/build/Config.kt"} {
		if !PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("excluded %s", path)
		}
	}
	for _, path := range []string{"node_modules/react-native/index.js", "ios/Pods/AFNetworking/a.m", "app/build/generated/R.java", "android/app/build/outputs/app.apk", "build/ios/Runner.app/Info.plist", ".gradle/caches/x", "vendor/dep/dep.go", "third_party/lib/a.c", "bundle.min.js"} {
		if PathIncluded(path, skill.Paths, skill.IgnorePaths) {
			t.Errorf("included %s", path)
		}
	}
	ref, err := os.ReadFile(filepath.Join(dir, "references", "threat-model.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Findings persist these links as references, so every MASVS link must
	// name a control file at the immutable v2.1.0 tag rather than a moving
	// branch or the rendered site.
	control := regexp.MustCompile(`^https://github\.com/OWASP/masvs/blob/v2\.1\.0/controls/MASVS-(STORAGE|CRYPTO|AUTH|NETWORK|PLATFORM|CODE|RESILIENCE|PRIVACY)-[0-9]\.md$`)
	links := regexp.MustCompile(`https?://[^\s)\]]*(?:masvs|mas\.owasp)[^\s)\]]*`).FindAllString(string(ref), -1)
	controls := 0
	for _, link := range links {
		if strings.HasSuffix(link, ".md") {
			controls++
			if !control.MatchString(link) {
				t.Errorf("MASVS link %q is not a tag-pinned control link", link)
			}
		}
		if strings.Contains(link, "mas.owasp.org") || !strings.Contains(link, "/v2.1.0") {
			t.Errorf("link %q is not pinned to the v2.1.0 tag", link)
		}
	}
	if controls == 0 {
		t.Error("reference must link MASVS controls")
	}
	for _, section := range []string{"Reference and limits", "Actors and assets", "Local data storage", "Cryptography and keys", "Authentication and sessions", "Network communication", "Platform interaction", "WebViews and embedded content", "Code and dependencies", "Privacy and resilience boundaries", "Evidence discipline"} {
		if !strings.Contains(string(ref), "## "+section) {
			t.Errorf("reference missing %q", section)
		}
	}
}
