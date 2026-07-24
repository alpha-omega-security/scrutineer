package interchange

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
)

// FindingHash is the salted federation identifier for one finding:
// sha256 over salt, canonical repository URL, canonical repo-relative
// location, and canonical CWE, joined with NUL bytes. Two instances
// sharing the salt derive the same hash for the same vulnerability
// without exchanging finding bodies; without the salt the hash reveals
// nothing enumerable. The canonicalisation here is a wire contract
// shared across instances, so it is deliberately self-contained instead
// of reusing findingnorm or the fingerprint helpers: an internal
// normalisation tweak must never silently change every published hash.
func FindingHash(salt, repoURL, subPath, location, cwe string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		salt,
		CanonicalRepo(repoURL),
		canonicalLocation(subPath, location),
		strings.ToUpper(strings.TrimSpace(cwe)),
	}, "\x00")))
	return hex.EncodeToString(h[:])
}

// CanonicalRepo lowercases the repository URL and strips the trailing
// slash and ".git" suffix so checkout-style and web-style URLs of the
// same repository hash identically.
func CanonicalRepo(url string) string {
	u := strings.ToLower(strings.TrimSpace(url))
	u = strings.TrimSuffix(u, "/")
	return strings.TrimSuffix(u, ".git")
}

// canonicalLocation reduces a finding location to a lowercased,
// repo-root-relative file path: first line only, positional suffix
// stripped (":42", ":42:7", and the ":10-20" range form), backslashes
// normalised, and the scan sub_path prepended since stored locations are
// relative to it.
func canonicalLocation(subPath, location string) string {
	loc := strings.TrimSpace(strings.Split(location, "\n")[0])
	for {
		i := strings.LastIndexByte(loc, ':')
		if i < 0 || !positionalSuffix(loc[i+1:]) {
			break
		}
		loc = loc[:i]
	}
	loc = cleanPath(loc)
	if sp := cleanPath(strings.Trim(subPath, "/")); sp != "" && sp != "." {
		loc = path.Join(sp, loc)
	}
	return strings.ToLower(loc)
}

func cleanPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	for strings.HasPrefix(p, "./") {
		p = strings.TrimPrefix(p, "./")
	}
	if p == "" {
		return ""
	}
	return path.Clean(p)
}

// positionalSuffix reports whether s is a line ("42") or range ("10-20")
// location suffix.
func positionalSuffix(s string) bool {
	start, end, isRange := strings.Cut(s, "-")
	if isRange {
		return allDigits(start) && allDigits(end)
	}
	return allDigits(start)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
