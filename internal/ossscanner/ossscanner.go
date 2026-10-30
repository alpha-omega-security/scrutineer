// Package ossscanner resolves a repository against Anthropic's OSS Scanner
// registry (https://github.com/anthropics/oss-scanner).
package ossscanner

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultRegistryURL is the public OSS Scanner registry.
const DefaultRegistryURL = "https://github.com/anthropics/oss-scanner"

// MaxFileBytes caps the size of a staged file.
const MaxFileBytes = 256 << 10

const (
	// OriginRegistry marks a Source under the registry root.
	OriginRegistry = "registry"
	// OriginRepository marks a Source under the scanned checkout.
	OriginRepository = "repository"

	conventionalDockerfile  = ".oss-scanner/Dockerfile"
	conventionalThreatModel = ".oss-scanner/threat_model.md"
)

// Project is the subset of a registry project.yaml scrutineer reads.
type Project struct {
	Repo        string `yaml:"repo"`
	Disabled    bool   `yaml:"disabled"`
	Dockerfile  string `yaml:"dockerfile"`
	ThreatModel string `yaml:"threat_model"`
}

// Source locates one maintainer file. Path is relative to the registry root
// for the registry origin and to the checkout root for the repository origin.
type Source struct {
	Origin string `json:"origin"`
	Path   string `json:"path"`
}

// Enrollment is the result of a lookup.
type Enrollment struct {
	Project     string  `json:"project,omitempty"`
	Registry    bool    `json:"registry"`
	Disabled    bool    `json:"disabled,omitempty"`
	Dockerfile  *Source `json:"dockerfile,omitempty"`
	ThreatModel *Source `json:"threat_model,omitempty"`
}

// SameRepo reports whether two repository URLs name the same repository.
// Fragments, a trailing slash or .git, the http/https difference and case are
// ignored. Empty or unparseable input never matches.
func SameRepo(a, b string) bool {
	ka, okA := repoKey(a)
	kb, okB := repoKey(b)
	return okA && okB && ka == kb
}

func repoKey(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	p := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), ".git")
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "", false
	}
	return strings.ToLower(u.Host) + strings.ToLower(p), true
}

// Resolve looks repoURL up in the registry checked out at registryRoot (""
// skips the registry) and locates the maintainer files. srcRoot is the
// checkout of the scanned repository. It returns nil, nil when nothing applies.
func Resolve(registryRoot, srcRoot, repoURL string) (*Enrollment, error) {
	if registryRoot != "" {
		name, project, err := findProject(registryRoot, repoURL)
		if err != nil {
			return nil, err
		}
		if project != nil {
			return enrolled(registryRoot, srcRoot, name, project)
		}
	}
	return conventional(srcRoot)
}

func findProject(registryRoot, repoURL string) (string, *Project, error) {
	root, err := os.OpenRoot(registryRoot)
	if err != nil {
		return "", nil, fmt.Errorf("open registry: %w", err)
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), "projects")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil, nil
		}
		return "", nil, fmt.Errorf("read registry projects: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		p, ok := readProject(root, name)
		if ok && SameRepo(p.Repo, repoURL) {
			return name, p, nil
		}
	}
	return "", nil, nil
}

func readProject(root *os.Root, name string) (*Project, bool) {
	data, err := readRooted(root, path.Join("projects", name, "project.yaml"), MaxFileBytes)
	if err != nil {
		return nil, false
	}
	var p Project
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, false
	}
	return &p, true
}

func enrolled(registryRoot, srcRoot, name string, p *Project) (*Enrollment, error) {
	e := &Enrollment{Project: name, Registry: true, Disabled: p.Disabled}
	reg, err := os.OpenRoot(registryRoot)
	if err != nil {
		return nil, fmt.Errorf("open registry: %w", err)
	}
	defer func() { _ = reg.Close() }()
	var src *os.Root
	if srcRoot != "" {
		if src, err = os.OpenRoot(srcRoot); err == nil {
			defer func() { _ = src.Close() }()
		} else {
			src = nil
		}
	}
	e.Dockerfile = pick(reg, src, name, "Dockerfile", p.Dockerfile)
	e.ThreatModel = pick(reg, src, name, "threat_model.md", p.ThreatModel)
	return e, nil
}

// pick prefers the registry copy of file and falls back to the in-repo key path.
func pick(reg, src *os.Root, name, file, key string) *Source {
	rel := path.Join("projects", name, file)
	if isRegular(reg, rel) {
		return &Source{Origin: OriginRegistry, Path: rel}
	}
	if src != nil && validRepoPath(key) {
		key = cleanRepoPath(key)
		if isRegular(src, key) {
			return &Source{Origin: OriginRepository, Path: key}
		}
	}
	return nil
}

func conventional(srcRoot string) (*Enrollment, error) {
	if srcRoot == "" {
		return nil, nil
	}
	src, err := os.OpenRoot(srcRoot)
	if err != nil {
		return nil, nil //nolint:nilerr // an unreadable checkout simply has no files
	}
	defer func() { _ = src.Close() }()
	e := &Enrollment{}
	if isRegular(src, conventionalDockerfile) {
		e.Dockerfile = &Source{Origin: OriginRepository, Path: conventionalDockerfile}
	}
	if isRegular(src, conventionalThreatModel) {
		e.ThreatModel = &Source{Origin: OriginRepository, Path: conventionalThreatModel}
	}
	if e.Dockerfile == nil && e.ThreatModel == nil {
		return nil, nil
	}
	return e, nil
}

func cleanRepoPath(p string) string {
	return path.Clean(strings.TrimPrefix(p, "./"))
}

func validRepoPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, `\`) {
		return false
	}
	trimmed := strings.TrimPrefix(p, "./")
	c := path.Clean(trimmed)
	if c != trimmed || c == "." {
		return false
	}
	for _, el := range strings.Split(c, "/") {
		if el == ".." {
			return false
		}
	}
	return true
}

func isRegular(root *os.Root, rel string) bool {
	info, err := root.Lstat(rel)
	return err == nil && info.Mode().IsRegular()
}

func readRooted(root *os.Root, rel string, limit int64) ([]byte, error) {
	info, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit", rel, info.Size(), limit)
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is over the %d byte limit", rel, limit)
	}
	return data, nil
}

// ReadSource returns the content of s, read through the matching root so that
// symlinks cannot escape it. Non-regular files and files over MaxFileBytes are
// rejected.
func ReadSource(registryRoot, srcRoot string, s *Source) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil source")
	}
	base := srcRoot
	if s.Origin == OriginRegistry {
		base = registryRoot
	}
	if base == "" {
		return nil, fmt.Errorf("no %s root", s.Origin)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return readRooted(root, s.Path, MaxFileBytes)
}
