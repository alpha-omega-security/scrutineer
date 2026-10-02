package worker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"scrutineer/internal/db"
	"scrutineer/internal/poc"
)

func resetSkillWorkspace(workRoot string, scan *db.Scan, skill *db.Skill, emit func(Event)) error {
	if scan.SessionID == "" || (skill.OutputKind != "findings" && skill.OutputKind != "advisory_audit") {
		return resetWorkspace(workRoot)
	}
	saved, err := os.MkdirTemp(filepath.Dir(workRoot), ".resume-poc-")
	if errors.Is(err, os.ErrNotExist) {
		return resetWorkspace(workRoot)
	}
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(saved) }()
	// Copy validated bytes outside the agent's mount before clearing it.
	if err := preserveResumePoCs(workRoot, saved, emit); err != nil {
		emit(Event{Kind: KindError, Text: fmt.Sprintf("preserve PoC on resume: %v", err)})
	}
	if err := resetWorkspace(workRoot); err != nil {
		return err
	}
	err = os.Rename(filepath.Join(saved, "poc"), filepath.Join(workRoot, "poc"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func preserveResumePoCs(workRoot, saved string, emit func(Event)) error {
	root, err := os.OpenRoot(workRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	pocRoot, err := poc.OpenDir(root, "poc")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = pocRoot.Close() }()
	dir, err := pocRoot.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	for {
		entries, err := dir.ReadDir(1)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			id := entry.Name()
			if !pocFindingID.MatchString(id) {
				emit(Event{Kind: KindError, Text: fmt.Sprintf("preserve PoC %q: invalid finding ID", id)})
				continue
			}
			files, err := capturePoCFiles(workRoot, id)
			if err != nil {
				emit(Event{Kind: KindError, Text: fmt.Sprintf("preserve PoC %s: %v", id, err)})
				continue
			}
			if err := writePoCFiles(saved, "poc/"+id+"/", files); err != nil {
				return fmt.Errorf("preserve PoC %s: %w", id, err)
			}
		}
	}
}
