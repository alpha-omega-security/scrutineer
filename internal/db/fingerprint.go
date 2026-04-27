package db

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"gorm.io/gorm"
)

// FingerprintFinding returns a stable hash for deduplicating the same
// vulnerability reported across repeated scans of one repository.
//
// The inputs are the producing skill, the scan sub-path, the CWE, and the
// file path from Location with any :line:col suffix stripped. File-level
// (not line-level) matching means a finding that drifts a few lines
// between commits still dedupes; the cost is that two distinct same-CWE
// issues in the same file collide into one row. When both CWE and
// Location are empty the title is folded in so freeform-style findings
// still get a key.
func FingerprintFinding(skillName, subPath, cwe, location, title string) string {
	loc := normaliseLocation(location)
	parts := []string{
		strings.ToLower(skillName),
		strings.ToLower(strings.Trim(subPath, "/")),
		strings.ToUpper(strings.TrimSpace(cwe)),
		loc,
	}
	if cwe == "" && loc == "" {
		parts = append(parts, strings.ToLower(strings.TrimSpace(title)))
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

// normaliseLocation reduces "path/to/file.go:42:7" to "path/to/file.go".
// A leading "./" is stripped so "./src/x.go" and "src/x.go" agree.
func normaliseLocation(loc string) string {
	loc = strings.TrimSpace(loc)
	loc = strings.TrimPrefix(loc, "./")
	if i := strings.IndexByte(loc, ':'); i >= 0 {
		loc = loc[:i]
	}
	return strings.ToLower(loc)
}

// BackfillFindingFingerprints fills Finding.Fingerprint for rows created
// before the column existed, joining through Scan for skill_name. It does
// not merge existing duplicates; it just sets the column so future scans
// dedupe against them. Safe to call on every startup.
func BackfillFindingFingerprints(gdb *gorm.DB) {
	type row struct {
		ID        uint
		SubPath   string
		CWE       string
		Location  string
		Title     string
		SkillName string
	}
	var rows []row
	gdb.Raw(`
		SELECT f.id, f.sub_path, f.cwe, f.location, f.title, s.skill_name
		FROM findings f JOIN scans s ON s.id = f.scan_id
		WHERE f.fingerprint IS NULL OR f.fingerprint = ''
	`).Scan(&rows)
	for _, r := range rows {
		fp := FingerprintFinding(r.SkillName, r.SubPath, r.CWE, r.Location, r.Title)
		gdb.Model(&Finding{}).Where("id = ?", r.ID).
			Updates(map[string]any{
				"fingerprint":       fp,
				"last_seen_scan_id": gorm.Expr("COALESCE(NULLIF(last_seen_scan_id, 0), scan_id)"),
				"last_seen_commit":  gorm.Expr(`COALESCE(NULLIF(last_seen_commit, ''), "commit")`),
				"seen_count":        gorm.Expr("CASE WHEN seen_count = 0 THEN 1 ELSE seen_count END"),
			})
	}
}
