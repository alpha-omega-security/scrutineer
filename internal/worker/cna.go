package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"scrutineer/internal/db"
)

// CNAListURL is the public CVE Program partner list. Served as a static
// JSON file from the cve.org website repo, so no auth needed.
const CNAListURL = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"

// SyncCNAs fetches the public CNA partner list and upserts every entry
// into the cnas table keyed on short_name. Safe to re-run; existing rows
// are updated in place. The list is ~500 entries and changes slowly, so a
// once-at-startup call is enough.
func SyncCNAs(ctx context.Context, gdb *gorm.DB, url string) (int, error) {
	if url == "" {
		url = CNAListURL
	}
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("fetch CNA list: %s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return 0, err
	}

	rows, err := parseCNAList(body)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if err := gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "short_name"}},
		UpdateAll: true,
	}).Create(&rows).Error; err != nil {
		return 0, fmt.Errorf("upsert CNAs: %w", err)
	}
	return len(rows), nil
}

type cnaEntry struct {
	ShortName        string `json:"shortName"`
	CNAID            string `json:"cnaID"`
	OrganizationName string `json:"organizationName"`
	Scope            string `json:"scope"`
	Country          string `json:"country"`
	Contact          []struct {
		Email   []struct{ EmailAddr string } `json:"email"`
		Contact []struct{ URL string }       `json:"contact"`
	} `json:"contact"`
	DisclosurePolicy []struct{ URL string } `json:"disclosurePolicy"`
	SecurityAdvisories struct {
		Advisories []struct{ URL string } `json:"advisories"`
	} `json:"securityAdvisories"`
	CNA struct {
		Root struct{ ShortName string } `json:"root"`
		Type []string                   `json:"type"`
	} `json:"CNA"`
}

func parseCNAList(data []byte) ([]db.CNA, error) {
	var entries []cnaEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse CNA list: %w", err)
	}
	now := time.Now()
	out := make([]db.CNA, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		if e.ShortName == "" {
			continue
		}
		raw, _ := json.Marshal(e)
		out = append(out, db.CNA{
			ShortName:    e.ShortName,
			CNAID:        e.CNAID,
			Organization: e.OrganizationName,
			Scope:        e.Scope,
			Email:        firstEmail(e),
			ContactURL:   firstContactURL(e),
			PolicyURL:    firstURL(e.DisclosurePolicy),
			AdvisoryURL:  firstURL(e.SecurityAdvisories.Advisories),
			Root:         e.CNA.Root.ShortName,
			Types:        strings.Join(e.CNA.Type, ","),
			Country:      e.Country,
			Metadata:     string(raw),
			FetchedAt:    &now,
		})
	}
	return out, nil
}

func firstEmail(e *cnaEntry) string {
	for _, c := range e.Contact {
		for _, em := range c.Email {
			if em.EmailAddr != "" {
				return em.EmailAddr
			}
		}
	}
	return ""
}

func firstContactURL(e *cnaEntry) string {
	for _, c := range e.Contact {
		for _, u := range c.Contact {
			if u.URL != "" {
				return u.URL
			}
		}
	}
	return ""
}

func firstURL(xs []struct{ URL string }) string {
	for _, x := range xs {
		if x.URL != "" {
			return x.URL
		}
	}
	return ""
}
