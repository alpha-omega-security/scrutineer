package worker

import "testing"

func TestValidateGitURL(t *testing.T) {
	good := []string{
		"https://github.com/splitrb/split",
		"https://gitlab.com/foo/bar.git",
	}
	for _, u := range good {
		if err := validateGitURL(u); err != nil {
			t.Errorf("should allow %q: %v", u, err)
		}
	}

	bad := []string{
		"http://github.com/foo/bar",
		"git@github.com:foo/bar.git",
		"ssh://git@host/repo",
		"file:///etc/passwd",
		"--upload-pack=/bin/sh",
		"-c core.fsmonitor=evil",
		"ext::sh -c evil",
		"",
	}
	for _, u := range bad {
		if err := validateGitURL(u); err == nil {
			t.Errorf("should reject %q", u)
		}
	}
}
