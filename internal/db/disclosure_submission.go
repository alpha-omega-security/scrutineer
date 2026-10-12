package db

import (
	"slices"
	"time"

	"gorm.io/gorm"
)

const (
	DisclosureChannelVINCE   = "vince"
	DisclosureChannelAkrites = "akrites"
	DisclosureChannelPVR     = "pvr"
)

// DisclosureSubmission is one report sent to an outside recipient: the payload
// as sent, where it went, the recipient's identifier for it and its status
// there. A finding can have several, on one channel or many. Rows stay out of
// finding exports because an Akrites receipt grants access to intake status.
type DisclosureSubmission struct {
	ID        uint   `gorm:"primaryKey"`
	FindingID uint   `gorm:"not null;index:idx_disclosure_submission_finding,priority:1"`
	Channel   string `gorm:"not null;index:idx_disclosure_submission_finding,priority:2"`
	Endpoint  string
	// ExternalID is the recipient's identifier: a VINCE VRF ID, an Akrites
	// receipt or a GHSA ID.
	ExternalID   string
	URL          string
	Status       string
	StatusAt     *time.Time
	NextPollAt   *time.Time `gorm:"index"`
	PollAttempts int
	LastError    string
	Actor        string
	// Request is the payload exactly as sent, JSON-encoded. Response keeps the
	// recipient's acceptance where it carries more than the identifier.
	Request   string `gorm:"type:text"`
	Response  string `gorm:"type:text"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// FindingDisclosureSubmissions lists a finding's submissions on one channel,
// newest first.
func FindingDisclosureSubmissions(gdb *gorm.DB, findingID uint, channel string) ([]DisclosureSubmission, error) {
	var rows []DisclosureSubmission
	err := gdb.Where("finding_id = ? AND channel = ?", findingID, channel).Order("id desc").Find(&rows).Error
	return rows, err
}

// DisclosureOutreach is what an accepted submission adds to the finding's
// record alongside the submission row.
type DisclosureOutreach struct {
	ReferenceURL, ReferenceTags, ReferenceSummary string
	CommunicationChannel                          string
	CommunicationActor, CommunicationBody         string
	AuditKind                                     string
	AuditSource                                   FindingSource
	AuditPayload                                  map[string]any
}

// RecordDisclosureSubmission saves an accepted submission and its outreach in
// one transaction: the row, an optional reference, an outbound communication,
// the move to reported for a finding not yet reported, and the channel's audit
// event.
func RecordDisclosureSubmission(gdb *gorm.DB, submission *DisclosureSubmission, outreach DisclosureOutreach) error {
	return FindingWriteTransaction(gdb, submission.FindingID, func(tx *gorm.DB) error {
		if err := tx.Save(submission).Error; err != nil {
			return err
		}
		if outreach.ReferenceURL != "" {
			if _, err := AddFindingReference(tx, submission.FindingID, outreach.ReferenceURL, outreach.ReferenceTags, outreach.ReferenceSummary); err != nil {
				return err
			}
		}
		if _, err := AddFindingCommunication(tx, submission.FindingID, outreach.CommunicationChannel, "outbound", outreach.CommunicationActor, outreach.CommunicationBody, "", time.Now(), SourceSystem); err != nil {
			return err
		}
		var finding Finding
		if err := tx.Select("id, status").First(&finding, submission.FindingID).Error; err != nil {
			return err
		}
		if slices.Contains([]FindingLifecycle{FindingNew, FindingEnriched, FindingTriaged, FindingReady}, finding.Status) {
			if err := WriteFindingField(tx, submission.FindingID, "status", string(FindingReported), SourceSystem, submission.Channel); err != nil {
				return err
			}
		}
		payload := map[string]any{"submission_id": submission.ID}
		for k, v := range outreach.AuditPayload {
			payload[k] = v
		}
		return LogEvent(tx, AuditEventInput{
			Kind: outreach.AuditKind, SubjectType: AuditSubjectFinding, SubjectID: submission.FindingID,
			Source: outreach.AuditSource, Payload: payload,
		})
	})
}
