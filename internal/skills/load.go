package skills

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const maxWalkDepth = 6

// LoadDirectory walks root looking for */SKILL.md files, parses each, and
// upserts into the DB. Returns the number of skills seen and any hard errors
// encountered; soft warnings are logged per-skill.
//
// The source string is stored on each upserted row so UI and tests can tell
// local/remote/ui skills apart. Pass "local" for a user-supplied directory
// and "remote" for a cloned git repo.
func LoadDirectory(gdb *gorm.DB, log *slog.Logger, root, source string) (int, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return 0, err
	}
	n := 0
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // ignore unreadable dirs, continue
		}
		if d.IsDir() {
			if depth(abs, path) > maxWalkDepth {
				return fs.SkipDir
			}
			if shouldSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != skillFile {
			return nil
		}
		p, perr := ParseFile(path)
		if perr != nil {
			log.Warn("skill parse failed", "path", path, "err", perr)
			return nil
		}
		for _, w := range p.Warnings {
			log.Warn("skill warning", "name", p.Name, "path", path, "warn", w)
		}
		if err := Upsert(gdb, p, source); err != nil {
			log.Warn("skill upsert failed", "name", p.Name, "err", err)
			return nil
		}
		n++
		return nil
	})
	if err != nil {
		return n, fmt.Errorf("walk %s: %w", abs, err)
	}
	return n, nil
}

func depth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return 0
	}
	if rel == "." {
		return 0
	}
	return len(filepath.SplitList(rel)) + len(splitSep(rel))
}

func splitSep(p string) []string {
	var out []string
	for _, s := range filepath.SplitList(p) {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".venv", "__pycache__", "vendor":
		return true
	}
	return false
}

// Upsert inserts a new Skill row or updates the existing row with matching
// name. If the existing row's SourceHash differs from the parsed one, the
// row's Version is bumped so older scans keep their snapshot. If the hash
// matches, only bookkeeping fields are refreshed.
func Upsert(gdb *gorm.DB, p *Parsed, source string) error {
	want, err := p.ToModel(source)
	if err != nil {
		return err
	}
	var rows []db.Skill
	if err := gdb.Where("name = ?", want.Name).Limit(1).Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		want.Version = 1
		return gdb.Create(want).Error
	}
	existing := rows[0]
	if existing.SourceHash == want.SourceHash {
		existing.Source = want.Source
		existing.SourcePath = want.SourcePath
		return gdb.Save(&existing).Error
	}
	want.ID = existing.ID
	want.Version = existing.Version + 1
	want.CreatedAt = existing.CreatedAt
	return gdb.Save(want).Error
}
