package db

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

// SubsumedNotePrefix starts the first line of the note finding-dedup writes
// on a finding whose bug is only reachable through another finding.
const SubsumedNotePrefix = "finding-dedup: subsumed by finding #"

// maxDuplicateHops bounds the walk along duplicate_of_id links, which a bad
// edit could turn into a cycle.
const maxDuplicateHops = 16

// SubsumingParent returns the finding that subsumes f according to its
// finding-dedup notes, or 0 when none does. A note names the parent as it was
// when the note was written. A later dedup run can merge that parent as a
// duplicate, so the parent is followed along duplicate_of_id to its current
// canonical. A note whose parent resolves back to f itself is stale (the two
// were later found to be the same bug, with f as the canonical) and is
// ignored. A parent that cannot be loaded still counts, so a deleted row does
// not silently lift the block.
func SubsumingParent(gdb *gorm.DB, f Finding, notes []FindingNote) (uint, error) {
	for _, n := range notes {
		id, ok := subsumedNoteParent(n.Body)
		if !ok {
			continue
		}
		parent, err := canonicalFindingID(gdb, id)
		if err != nil {
			return 0, err
		}
		if parent != f.ID {
			return parent, nil
		}
	}
	return 0, nil
}

func subsumedNoteParent(body string) (uint, bool) {
	first, _, _ := strings.Cut(body, "\n")
	rest, ok := strings.CutPrefix(strings.TrimSpace(first), SubsumedNotePrefix)
	if !ok {
		return 0, false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	id, err := strconv.ParseUint(rest[:end], 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return uint(id), true
}

// canonicalFindingID follows duplicate_of_id from id until it reaches a
// finding that is not a linked duplicate, a missing row or a cycle.
func canonicalFindingID(gdb *gorm.DB, id uint) (uint, error) {
	seen := map[uint]bool{}
	for range maxDuplicateHops {
		if seen[id] {
			return id, nil
		}
		seen[id] = true
		var f Finding
		err := gdb.Select("id, status, duplicate_of_id").First(&f, id).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return id, nil
		}
		if err != nil {
			return 0, fmt.Errorf("load finding %d: %w", id, err)
		}
		if f.Status != FindingDuplicate || f.DuplicateOfID == 0 {
			return id, nil
		}
		id = f.DuplicateOfID
	}
	return id, nil
}
