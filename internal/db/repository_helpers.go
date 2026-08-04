package db

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// FederationNotOptedOut is the SQL predicate for a repository whose
// maintainer has not asked federated instances to leave it alone. Every
// query that must honour an opt-out shares this text so a sixth surface
// cannot be written with a subtly different one.
const FederationNotOptedOut = "repositories.federation_opt_out_at IS NULL"

// FederationHasOptedOut is its inverse, for the queries that select the
// opted-out repositories rather than exclude them: the public feed's optout
// records and the bulk-resume subquery. Same reason as above, one text.
const FederationHasOptedOut = "repositories.federation_opt_out_at IS NOT NULL"

// FederationOptedOut reports whether this repository's maintainer asked
// federated instances neither to scan it nor to contact them. The Go-side
// counterpart of FederationNotOptedOut, for the paths that hold a loaded
// row rather than a query.
func (r Repository) FederationOptedOut() bool { return r.FederationOptOutAt != nil }

// SetDisclosureChannel writes a repository's disclosure channel and, only
// when the value actually changes, stamps DisclosureChannelAt. That
// timestamp is published as verified_at on the interchange route record, so
// bumping it on an unchanged re-write would rewrite the record and churn
// the public feed with no new information.
//
// The comparison reads the stored value in the same transaction as the write
// rather than trusting a row the caller loaded earlier: the maintainers skill
// hands over a repository it read when the scan started, which an analyst may
// have edited during the hour since.
//
// The value is trimmed here rather than at each call site: the skill hands
// over whatever the model emitted, so an answer that differs from the stored
// one only by a trailing newline would otherwise read as a change, re-stamp
// the timestamp, and republish the route record it exists to hold still.
func SetDisclosureChannel(gdb *gorm.DB, repoID uint, value string) error {
	value = strings.TrimSpace(value)
	return gdb.Transaction(func(tx *gorm.DB) error {
		var repo Repository
		if err := tx.Select("id, disclosure_channel").First(&repo, repoID).Error; err != nil {
			return err
		}
		updates := map[string]any{"disclosure_channel": value}
		if repo.DisclosureChannel != value {
			now := time.Now().UTC()
			updates["disclosure_channel_at"] = &now
		}
		return tx.Model(&Repository{}).Where("id = ?", repoID).Updates(updates).Error
	})
}
