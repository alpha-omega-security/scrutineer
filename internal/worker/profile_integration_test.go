package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIntegration_DetectRubyProfile(t *testing.T) {
	image := os.Getenv("SCRUTINEER_TEST_RUNNER_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_RUNNER_IMAGE to run profile detection in Docker")
	}
	for _, tt := range []struct {
		name    string
		subPath string
		files   map[string]string
	}{
		{"gemspec subproject", "packages/parser", map[string]string{
			"Gemfile":                        "source 'https://rubygems.org'\ngem 'rake'\n",
			"packages/parser/parser.gemspec": "Gem::Specification.new do |spec|\n  spec.name = 'parser'\nend\n",
		}},
		{"gem with secondary Ruby", ".", map[string]string{
			"parser.gemspec": "Gem::Specification.new do |spec|\n  spec.name = 'parser'\nend\n",
			"lib/parser.rb":  "module Parser\nend\n",
			"lib/one.py":     "print('one')\n",
			"lib/two.py":     "print('two')\n",
			"lib/three.py":   "print('three')\n",
		}},
		{"Hoe", ".", map[string]string{
			"Rakefile": "require 'hoe'\nHoe.spec 'parser' do\nend\n",
		}},
		{"alternate Bundler manifest", ".", map[string]string{
			"gems.rb": "source 'https://rubygems.org'\ngem 'rake'\n",
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for path, content := range tt.files {
				full := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := DetectProfile(t.Context(), ContainerRuntime{Bin: "docker"}, image, filepath.Join(root, tt.subPath), false)
			if got.Name != "ruby" {
				t.Errorf("DetectProfile = %q, want ruby", got.Name)
			}
		})
	}
}
