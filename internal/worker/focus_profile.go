package worker

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/repoconfig"
	"scrutineer/internal/skills"
)

func (d ContainerRunner) resolveSkillProfile(ctx context.Context, job SkillJob, src string, emit func(Event)) (string, string, error) {
	requested := job.Profile
	if requested == "" && job.FocusArea != "" && d.ProfilesDir != "" {
		area, err := repoconfig.DecodeFocusAreaJSON(job.FocusArea)
		if err != nil {
			return "", "", fmt.Errorf("profile focus area: %w", err)
		}
		profile, err := d.focusProfile(ctx, src, job.SubPath, area.Paths)
		switch {
		case err != nil:
			emit(Event{Kind: KindText, Text: "profile: focus-area detection failed; using scan scope: " + err.Error()})
		case profile.IsDefault():
			emit(Event{Kind: KindText, Text: "profile: no focus-area match; using scan scope"})
		default:
			requested = profile.Name
			emit(Event{Kind: KindText, Text: "profile: focus area selected " + requested})
		}
	}
	profile, image := d.resolveProfile(ctx, requested, src, job.SubPath, emit)
	return profile, image, nil
}

func (d ContainerRunner) focusProfile(ctx context.Context, src, subPath string, paths []string) (Profile, error) {
	view, err := os.MkdirTemp(filepath.Dir(src), "profile-focus-")
	if err != nil {
		return Profile{}, err
	}
	defer func() { _ = os.RemoveAll(view) }()
	if err := copyFocusFiles(ctx, src, view, subPath, paths); err != nil {
		return Profile{}, err
	}
	out, err := runBrief(ctx, d.Runtime, d.image(), view, d.SELinuxRelabel)
	if err != nil {
		return Profile{}, err
	}
	return matchFocusProfile(out), nil
}

func matchFocusProfile(out []byte) Profile {
	detections := briefDetections(out)
	profiles := map[string]string{
		"javascript": "node", "typescript": "node", "php": "php",
		"ruby": "ruby", "python": "python", "go": "go", "rust": "rust",
		"java": "java", "kotlin": "kotlin", "scala": "scala",
		"c": "c-cpp", "c++": "c-cpp", "c#": "dotnet", "f#": "dotnet",
		"elixir": "beam", "erlang": "beam", "swift": "swift", "ocaml": "ocaml", "perl": "perl",
	}
	matched := matchProfile(out)
	for language := range detections[briefLanguage] {
		name := profiles[language]
		if name == "" {
			break
		}
		if matched.Name == name || matched.Name == name+"-ext" || matched.BaseProfile == name || matched.FallbackProfile == name {
			return matched
		}
		return ProfileByName(name)
	}
	return matched
}

// Detection uses a separate view; the scan retains its build inputs and callers.
func copyFocusFiles(ctx context.Context, src, dst, subPath string, paths []string) error {
	clean, err := CleanSubPath(subPath)
	if err != nil {
		return err
	}
	workspace, err := os.OpenRoot(filepath.Dir(src))
	if err != nil {
		return err
	}
	defer func() { _ = workspace.Close() }()
	root, err := workspace.OpenRoot(filepath.Base(src))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if rel == ".git" || skills.DirAllExcluded(rel, paths, nil) {
				return fs.SkipDir
			}
			return nil
		}
		if rel == ".git" || !entry.Type().IsRegular() || !skills.PathIncluded(rel, paths, nil) {
			return nil
		}
		if clean != "" && !strings.HasPrefix(rel, clean+"/") {
			return nil
		}
		return copyFocusFile(root, rel, filepath.Join(dst, filepath.FromSlash(rel)))
	})
}

func copyFocusFile(root *os.Root, rel, dst string) error {
	in, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
