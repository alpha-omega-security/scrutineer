package worker

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"scrutineer/internal/db"
)

const (
	ExplorationRandomDig        = "random-dig"
	ExplorationAdversarialSweep = "adversarial-sweep"
)

// ValidateExploration rejects combinations that would turn an exploratory
// source audit into a planned, finding-scoped, or diff-only audit.
func ValidateExploration(scan *db.Scan, skill string) error {
	if scan.ExplorationMode == "" && scan.ExplorationPath == "" {
		return nil
	}
	if skill != deepDiveSkillName || scan.FocusArea != "" || scan.RescanMode == db.ScanRescanModeDiff || scan.FindingID != nil {
		return fmt.Errorf("invalid exploratory audit inputs")
	}
	switch scan.ExplorationMode {
	case ExplorationRandomDig:
	case ExplorationAdversarialSweep:
		if scan.ExplorationPath == "" {
			return fmt.Errorf("adversarial sweep requires a target path")
		}
	default:
		return fmt.Errorf("invalid exploratory audit inputs")
	}
	if target := scan.ExplorationPath; target != "" && target != "." {
		clean, err := CleanSubPath(target)
		if err != nil || clean != target {
			return fmt.Errorf("invalid exploratory audit path %q", target)
		}
	}
	return nil
}

// ValidateExplorationRunner rejects host execution, where an agent can bypass
// callback-token restrictions through the unauthenticated loopback exports.
func (w *Worker) ValidateExplorationRunner(skill string) error {
	runner := w.Runner
	for {
		switch r := runner.(type) {
		case LocalClaude, *LocalClaude:
			return fmt.Errorf("exploratory audit requires a container runner; host execution is not supported")
		case HostSplitRunner:
			runner = r.runnerFor(skill)
		case *HostSplitRunner:
			runner = r.runnerFor(skill)
		default:
			return nil
		}
	}
}

// ExplorationInstructions is shared by enqueue preflight and workspace staging
// so skill overrides without the reference pack never queue exploratory scans.
func ExplorationInstructions(skill *db.Skill, mode string) ([]byte, error) {
	if skill.SourcePath == "" {
		return nil, fmt.Errorf("exploratory audit requires a skill reference pack")
	}
	switch mode {
	case ExplorationRandomDig, ExplorationAdversarialSweep:
	default:
		return nil, fmt.Errorf("unknown exploration mode %q", mode)
	}
	body, err := os.ReadFile(filepath.Join(skill.SourcePath, "references", mode+".md"))
	if err != nil {
		return nil, fmt.Errorf("read %s instructions: %w", mode, err)
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil, fmt.Errorf("%s instructions are empty", mode)
	}
	return body, nil
}

type skillContextExploration struct {
	Mode string `json:"mode"`
	Path string `json:"path"`
}

// prepareExploration runs after all operator and skill path filters. Only
// directories containing regular source files are candidates, never symlinks.
// Persisting the chosen directory keeps explicit retries on the same target.
func (w *Worker) prepareExploration(ctx context.Context, workRoot string, scan *db.Scan) error {
	if scan.ExplorationMode == "" {
		return nil
	}
	if err := ValidateExploration(scan, scan.SkillName); err != nil {
		return err
	}
	if err := w.ValidateExplorationRunner(scan.SkillName); err != nil {
		return err
	}
	if scan.ExplorationMode == ExplorationAdversarialSweep {
		dirs, err := adversarialDirectories(ctx, filepath.Join(workRoot, "src"), scan.SubPath)
		if err != nil {
			return fmt.Errorf("select adversarial source directory: %w", err)
		}
		candidates := AdversarialSweepPaths(scan.Repository.ThreatModel, scan.SubPath)
		if slices.Contains(candidates, scan.ExplorationPath) && explorationPathAvailable(dirs, scan.ExplorationPath) {
			return nil
		}
		scan.ExplorationMode = ExplorationRandomDig
		scan.ExplorationPath = ""
	}
	return w.prepareRandomDig(ctx, workRoot, scan)
}

func (w *Worker) prepareRandomDig(ctx context.Context, workRoot string, scan *db.Scan) error {
	dirs, err := exploratoryDirectories(ctx, filepath.Join(workRoot, "src"), scan.SubPath)
	if err != nil {
		return fmt.Errorf("select exploratory source directory: %w", err)
	}
	if len(dirs) == 0 {
		return fmt.Errorf("no eligible source directory for exploratory audit")
	}
	if scan.ExplorationPath != "" {
		if !slices.Contains(dirs, scan.ExplorationPath) {
			return fmt.Errorf("exploratory directory %q is no longer eligible", scan.ExplorationPath)
		}
		return nil
	}
	seed := scan.ID
	if scan.TriageScanID != nil {
		seed = *scan.TriageScanID
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "random-dig:%d", seed))
	target := dirs[binary.BigEndian.Uint64(sum[:])%uint64(len(dirs))]
	result := w.DB.Model(scan).Updates(map[string]any{
		"exploration_mode": ExplorationRandomDig,
		"exploration_path": target,
	})
	if result.Error != nil {
		return fmt.Errorf("persist exploratory directory: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("scan disappeared before exploratory directory was saved")
	}
	scan.ExplorationPath = target
	return nil
}

func AdversarialSweepPaths(raw, subPath string) []string {
	var report struct {
		Components []struct {
			Name    string `json:"name"`
			InScope *bool  `json:"in_scope"`
		} `json:"components"`
		OutOfScope json.RawMessage `json:"out_of_scope"`
	}
	if json.Unmarshal([]byte(raw), &report) != nil {
		return nil
	}
	var exclusions []struct {
		Item string `json:"item"`
	}
	_ = json.Unmarshal(report.OutOfScope, &exclusions)
	rawPaths := make([]string, 0, len(exclusions)+len(report.Components))
	for _, exclusion := range exclusions {
		rawPaths = append(rawPaths, exclusion.Item)
	}
	for _, component := range report.Components {
		if component.InScope != nil && !*component.InScope {
			rawPaths = append(rawPaths, component.Name)
		}
	}
	cleanSubPath, err := CleanSubPath(subPath)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(rawPaths))
	paths := make([]string, 0, len(rawPaths))
	for _, rawPath := range rawPaths {
		candidate, ok := adversarialSweepPath(rawPath, cleanSubPath)
		if !ok {
			continue
		}
		if _, duplicate := seen[candidate]; duplicate {
			continue
		}
		seen[candidate] = struct{}{}
		paths = append(paths, candidate)
	}
	slices.Sort(paths)
	return paths
}

func adversarialSweepPath(raw, subPath string) (string, bool) {
	raw = strings.Trim(strings.TrimSpace(raw), "`")
	if raw == "" || strings.HasPrefix(raw, "/") || strings.Contains(raw, ":") ||
		strings.Contains(raw, "\\") || strings.ContainsAny(raw, "*?[]{}") ||
		strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return "", false
	}
	clean, err := CleanSubPath(raw)
	if err != nil || clean == "" {
		return "", false
	}
	if exploratorySourceFile(clean) {
		clean = path.Dir(clean)
		if clean == "." {
			return "", false
		}
	}
	if subPath != "" && clean != subPath && !strings.HasPrefix(clean, subPath+"/") {
		clean = path.Join(subPath, clean)
	}
	return clean, true
}

func explorationPathAvailable(dirs []string, target string) bool {
	for _, dir := range dirs {
		if dir == target || strings.HasPrefix(dir, target+"/") {
			return true
		}
	}
	return false
}

func exploratoryDirectories(ctx context.Context, src, subPath string) ([]string, error) {
	return sourceDirectories(ctx, src, subPath, exploratorySkipDirectories)
}

func adversarialDirectories(ctx context.Context, src, subPath string) ([]string, error) {
	return sourceDirectories(ctx, src, subPath, []string{".git"})
}

func sourceDirectories(ctx context.Context, src, subPath string, skipDirectories []string) ([]string, error) {
	clean, err := CleanSubPath(subPath)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(src)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	dirs := map[string]bool{}
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if slices.Contains(skipDirectories, strings.ToLower(entry.Name())) {
				return fs.SkipDir
			}
			if clean != "" && name != "." && name != clean && !strings.HasPrefix(clean, name+"/") && !strings.HasPrefix(name, clean+"/") {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || (clean != "" && !strings.HasPrefix(name, clean+"/")) {
			return nil
		}
		if exploratorySourceFile(name) {
			dirs[path.Dir(name)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(dirs))
	for dir := range dirs {
		result = append(result, dir)
	}
	slices.Sort(result)
	return result, nil
}

// A conservative source-only candidate set avoids sampling docs, lockfiles,
// binary assets, or manifests as the sole target of an expensive audit.
var exploratorySourceExtensions = strings.Fields(".c .h .cc .cpp .cxx .hpp .m .mm .go .rs .py .pyw .js .jsx .ts .tsx .mjs .cjs .rb .php .java .kt .kts .scala .sc .cs .fs .fsx .swift .pl .pm .lua .sh .bash .zsh .ex .exs .erl .hrl .hs .ml .mli .clj .cljs .cljc .dart .r .jl .zig .f .f90 .f95 .sol .vue .svelte")

var exploratorySkipDirectories = strings.Fields(".git vendor vendored third_party third-party node_modules dist test tests testdata fixtures __tests__ example examples")

func exploratorySourceFile(name string) bool {
	return slices.Contains(exploratorySourceExtensions, strings.ToLower(path.Ext(name)))
}

func stageExploratoryWorkspace(workRoot, skillDir, apiBase string, scan *db.Scan, skill *db.Skill) (skillContext, error) {
	if err := ValidateExploration(scan, skill.Name); err != nil {
		return skillContext{}, err
	}
	if scan.ExplorationPath == "" {
		return skillContext{}, fmt.Errorf("exploratory audit requires a selected directory")
	}
	body, err := ExplorationInstructions(skill, scan.ExplorationMode)
	if err != nil {
		return skillContext{}, err
	}
	// The loaded skill is scan-local. Update it too so the logged prompt and
	// any report-repair invocation describe the instructions actually staged.
	skill.Body = string(body)
	if err := stageSkill(skill, workRoot, skillDir); err != nil {
		return skillContext{}, err
	}
	staged := *scan
	staged.Repository.ScanConfig = ""
	if scan.ExplorationMode == ExplorationRandomDig {
		staged.Repository.ThreatModel = ""
	}
	document, err := buildSkillContext(apiBase, "", "", &staged, &staged.Repository, nil, nil, nil)
	if err != nil {
		return skillContext{}, err
	}
	if err := writeSkillContext(workRoot, skillDir, document); err != nil {
		return skillContext{}, err
	}
	if scan.ExplorationMode == ExplorationAdversarialSweep {
		if err := stageThreatModel(workRoot, staged.SubPath, staged.Repository.ThreatModel); err != nil {
			return skillContext{}, err
		}
	}
	return document, nil
}
