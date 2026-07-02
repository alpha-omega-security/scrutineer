package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// bundleManifest is the small header file the disclosure bundle carries
// alongside the per-format documents. It names the finding, fixes the
// generator version, and lists what's inside so a coordinator unzipping
// the archive can tell at a glance whether they're looking at the right
// vulnerability and what each file is for. The shape mirrors the OSS
// SIRT intake brief (see docs/disclosure-fallback.md): one summary
// line, an aliases block for cross-system identifiers, and an explicit
// contents map.
type bundleManifest struct {
	GeneratedAt  string            `json:"generated_at"`
	GeneratorURL string            `json:"generator_url"`
	FindingID    uint              `json:"finding_id"`
	Repository   string            `json:"repository"`
	Title        string            `json:"title"`
	Severity     string            `json:"severity,omitempty"`
	CWE          string            `json:"cwe,omitempty"`
	Aliases      []string          `json:"aliases,omitempty"`
	Status       string            `json:"status"`
	Contents     map[string]string `json:"contents"`
	Note         string            `json:"note,omitempty"`
}

// findingBundleDownload writes a tar.gz containing every per-finding
// export scrutineer produces (OSV, CSAF, markdown report, patch.diff
// when one is on file) plus a manifest naming the finding and the
// archive contents. The route is intentionally a composition over the
// existing per-format builders: a coordinator who already pulls
// /findings/{id}/osv.json by hand gets exactly the same bytes inside
// the archive.
//
// Duplicates and findings with absent repository rows return errors so
// the archive is never half-built; a missing patch.diff or a finding
// without OSV-friendly versioning is fine and just means the bundle
// has fewer entries.
func (s *Server) findingBundleDownload(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var f db.Finding
	if err := s.DB.First(&f, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if f.Status == db.FindingDuplicate {
		http.Error(w, "finding is a duplicate; export not available", http.StatusGone)
		return
	}
	var repo db.Repository
	if err := s.DB.First(&repo, f.RepositoryID).Error; err != nil {
		http.Error(w, "repository missing for finding", http.StatusInternalServerError)
		return
	}

	entries, err := s.bundleEntries(&f, &repo)
	if err != nil {
		s.Log.Error("disclosure bundle", "finding", f.ID, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	body, err := buildTarGz(entries)
	if err != nil {
		s.Log.Error("disclosure bundle tar", "finding", f.ID, "err", err)
		http.Error(w, "failed to build archive", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("scrutineer-finding-%d-disclosure-%s.tar.gz",
		f.ID, time.Now().UTC().Format("20060102"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write(body)
}

// bundleEntry is one file written into the archive: path inside the
// tar plus its raw contents.
type bundleEntry struct {
	Name string
	Data []byte
}

func (s *Server) bundleEntries(f *db.Finding, repo *db.Repository) ([]bundleEntry, error) {
	// Coordinator bundles need to fail loudly: a silent half-build that
	// drops references or packages can produce an advisory that looks
	// complete but is missing crucial context. Each Find() is tolerant
	// of an empty result (gorm returns no error for zero rows on a Find),
	// but a real DB failure bubbles up.
	var refs []db.FindingReference
	if err := s.DB.Where("finding_id = ?", f.ID).Order("id desc").Find(&refs).Error; err != nil {
		return nil, fmt.Errorf("load references: %w", err)
	}
	var pkgs []db.Package
	if err := s.DB.Where("repository_id = ?", f.RepositoryID).Find(&pkgs).Error; err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}
	var fdRows []db.FindingDependent
	if err := s.DB.Where("finding_id = ?", f.ID).Find(&fdRows).Error; err != nil {
		return nil, fmt.Errorf("load finding dependents: %w", err)
	}
	deps := loadFindingDependents(s, fdRows)
	var dependentCount int64
	if err := s.DB.Model(&db.Dependent{}).Where("repository_id = ?", f.RepositoryID).Count(&dependentCount).Error; err != nil {
		return nil, fmt.Errorf("count dependents: %w", err)
	}
	// Scan load is best-effort: a finding with a missing parent scan
	// row (e.g. a scan that was deleted) still has a valid bundle to
	// produce, since the bundle does not embed scan-specific fields.
	var scan db.Scan
	if err := s.DB.First(&scan, f.ScanID).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("load scan: %w", err)
	}

	// Aliases give a coordinator their cross-system identifiers up front:
	// the OSV builder already collects them from CVE plus any GHSA-shaped
	// references, so reuse rather than duplicate the rule.
	aliases := osvAliases(*f, refs)

	contents := map[string]string{}
	var entries []bundleEntry

	osvRaw, err := json.MarshalIndent(buildOSV(*f, *repo, refs, pkgs), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("build OSV: %w", err)
	}
	entries = append(entries, bundleEntry{Name: "osv.json", Data: osvRaw})
	contents["osv.json"] = "OSV 1.6.0 record (machine-readable advisory)"

	if dependentCount > 0 {
		csafRaw, err := json.MarshalIndent(buildCSAF(*f, *repo, refs, pkgs, fdRows, deps), "", "  ")
		if err != nil {
			return nil, fmt.Errorf("build CSAF: %w", err)
		}
		entries = append(entries, bundleEntry{Name: "csaf.json", Data: csafRaw})
		contents["csaf.json"] = "CSAF 2.0 document (with VEX product_status for dependents)"
	}

	report := renderFindingReport(s.DB, f, &scan, repo)
	entries = append(entries, bundleEntry{Name: "report.md", Data: []byte(report)})
	contents["report.md"] = "Human-readable markdown report for the recipient"

	if f.SuggestedFix != "" {
		entries = append(entries, bundleEntry{Name: "patch.diff", Data: []byte(f.SuggestedFix)})
		contents["patch.diff"] = "Suggested unified diff; applied to commit recorded in the OSV affected[] git range"
	}

	manifest := bundleManifest{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		GeneratorURL: "https://github.com/alpha-omega-security/scrutineer",
		FindingID:    f.ID,
		Repository:   firstNonEmpty(repo.FullName, repo.Name, repo.URL),
		Title:        f.Title,
		Severity:     f.Severity,
		CWE:          f.CWE,
		Aliases:      aliases,
		Status:       string(f.Status),
		Contents:     contents,
		Note:         "Bundle composed from data already on the finding; the per-file exports are the same bytes the corresponding /findings/{id}/{file} endpoint serves directly.",
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	// Prepend the manifest so a `tar tzf` listing leads with it.
	entries = append([]bundleEntry{{Name: "manifest.json", Data: manifestRaw}}, entries...)
	return entries, nil
}

// buildTarGz writes the entries to a gzipped tar archive. Files land
// at the archive root with 0644; the bundle is meant to be unpacked,
// inspected, and forwarded by a coordinator, not installed.
func buildTarGz(entries []bundleEntry) ([]byte, error) {
	const filePerm = 0o644
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	now := time.Now()
	for _, e := range entries {
		hdr := &tar.Header{
			Name:    e.Name,
			Mode:    filePerm,
			Size:    int64(len(e.Data)),
			ModTime: now,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
