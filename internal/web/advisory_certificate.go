package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"scrutineer/internal/db"
)

const advisoryAuditFixed = "fixed"

type advisoryCertificate struct {
	Format      string                     `json:"format"`
	Version     int                        `json:"version"`
	GeneratedAt time.Time                  `json:"generated_at"`
	Repository  advisoryCertificateRepo    `json:"repository"`
	Advisory    advisoryCertificateSubject `json:"advisory"`
	Audit       advisoryCertificateAudit   `json:"audit"`
}

type advisoryCertificateRepo struct {
	Name     string `json:"name"`
	FullName string `json:"full_name,omitempty"`
	URL      string `json:"url"`
}

type advisoryCertificateSubject struct {
	UUID           string  `json:"uuid"`
	URL            string  `json:"url,omitempty"`
	Title          string  `json:"title"`
	Severity       string  `json:"severity,omitempty"`
	CVSSScore      float64 `json:"cvss_score,omitempty"`
	Classification string  `json:"classification,omitempty"`
}

type advisoryCertificateAudit struct {
	Status    string    `json:"status"`
	Commit    string    `json:"commit,omitempty"`
	ScanID    uint      `json:"scan_id"`
	AuditedAt time.Time `json:"audited_at"`
	Evidence  string    `json:"evidence"`
}

// advisoryCertificateDownload serves a public attestation that the advisory's
// advertised fix was re-audited and held. It requires the latest fix-audit
// verdict for the advisory to be fixed; any other verdict (or no audit yet)
// means there is nothing to certify and the response is 404.
func (s *Server) advisoryCertificateDownload(w http.ResponseWriter, r *http.Request) {
	adv, ok := loadByID[db.Advisory](s, w, r)
	if !ok {
		return
	}
	var audit db.AdvisoryAudit
	res := s.DB.Where("repository_id = ? AND advisory_uuid = ?", adv.RepositoryID, adv.UUID).
		Order("id desc").Limit(1).Find(&audit)
	if res.Error != nil {
		s.Log.Error("certificate audit lookup", "advisory", adv.ID, "err", res.Error)
		http.Error(w, "failed to load audit verdict", http.StatusInternalServerError)
		return
	}
	if res.RowsAffected == 0 || audit.Status != advisoryAuditFixed {
		http.Error(w, "no fixed audit verdict for this advisory", http.StatusNotFound)
		return
	}
	var repo db.Repository
	if err := s.DB.Select("id, url, name, full_name").First(&repo, adv.RepositoryID).Error; err != nil {
		s.Log.Error("certificate repository", "advisory", adv.ID, "repository", adv.RepositoryID, "err", err)
		http.Error(w, "failed to load repository", http.StatusInternalServerError)
		return
	}

	cert := advisoryCertificate{
		Format:      "scrutineer-fix-audit-certificate",
		Version:     1,
		GeneratedAt: time.Now().UTC(),
		Repository:  advisoryCertificateRepo{Name: repo.Name, FullName: repo.FullName, URL: repo.URL},
		Advisory: advisoryCertificateSubject{
			UUID:           adv.UUID,
			URL:            adv.URL,
			Title:          adv.Title,
			Severity:       adv.Severity,
			CVSSScore:      adv.CVSSScore,
			Classification: adv.Classification,
		},
		Audit: advisoryCertificateAudit{
			Status:    audit.Status,
			Commit:    audit.Commit,
			ScanID:    audit.ScanID,
			AuditedAt: audit.CreatedAt.UTC(),
			Evidence:  audit.Evidence,
		},
	}
	raw, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		s.Log.Error("certificate marshal", "advisory", adv.ID, "err", err)
		http.Error(w, "failed to generate certificate", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("scrutineer-advisory-%d-certificate-%s.json", adv.ID, time.Now().UTC().Format("20060102"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write(raw)
}

// latestAdvisoryAuditStatuses returns the newest fix-audit status per
// advisory row, keyed by Advisory.ID, for badge rendering. Advisories with
// no audit are absent from the map.
func (s *Server) latestAdvisoryAuditStatuses(advisories []db.Advisory) map[uint]string {
	if len(advisories) == 0 {
		return nil
	}
	repoIDs := make([]uint, 0, len(advisories))
	uuids := make([]string, 0, len(advisories))
	for _, a := range advisories {
		repoIDs = append(repoIDs, a.RepositoryID)
		uuids = append(uuids, a.UUID)
	}
	var audits []db.AdvisoryAudit
	if err := s.DB.Select("repository_id, advisory_uuid, status").
		Where("repository_id IN ? AND advisory_uuid IN ?", repoIDs, uuids).
		Order("id asc").Find(&audits).Error; err != nil {
		s.Log.Warn("advisory audit statuses", "err", err)
		return nil
	}
	type key struct {
		repoID uint
		uuid   string
	}
	latest := make(map[key]string, len(audits))
	for _, a := range audits {
		latest[key{a.RepositoryID, a.AdvisoryUUID}] = a.Status
	}
	out := make(map[uint]string, len(advisories))
	for _, a := range advisories {
		if st, ok := latest[key{a.RepositoryID, a.UUID}]; ok {
			out[a.ID] = st
		}
	}
	return out
}
