package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
)

const (
	AuditSubjectScan       = "scan"
	AuditSubjectFinding    = "finding"
	AuditSubjectRepository = "repository"

	AuditEventRepositoryCreated = "repo.created"
	AuditEventRepositoryDeleted = "repo.deleted"

	AuditEventFindingStatusChanged   = "finding.status_changed"
	AuditEventFindingSeverityChanged = "finding.severity_changed"
	AuditEventFindingLabelsChanged   = "finding.labels_changed"

	AuditEventScanStarted             = "scan.started"
	AuditEventScanFinished            = "scan.finished"
	AuditEventScanFailed              = "scan.failed"
	AuditEventScanCancelled           = "scan.cancelled"
	AuditEventScanPaused              = "scan.paused"
	AuditEventScanRetryRequested      = "scan.retry_requested"
	AuditEventScanRetryEnqueueFailed  = "scan.retry_enqueue_failed"
	AuditEventScanResumeRequested     = "scan.resume_requested"
	AuditEventScanResumeEnqueueFailed = "scan.resume_enqueue_failed"
	AuditEventScanCancelRequested     = "scan.cancel_requested"

	AuditEventDisclosureRequested             = "disclosure.requested"
	AuditEventDisclosureVINCESubmitted        = "disclosure.vince_submitted"
	AuditEventDisclosureAkritesSubmitted      = "disclosure.akrites_submitted"
	AuditEventDisclosurePVRSubmitted          = "disclosure.pvr_submitted"
	AuditEventDisclosureDraftUpdated          = "disclosure.draft_updated"
	AuditEventDisclosureCommunicationRecorded = "disclosure.communication_recorded"
	AuditEventDisclosureChannelChanged        = "disclosure.channel_changed"
)

// AuditKeyRepositoryID is the payload key audit events use for the repository
// they belong to.
const AuditKeyRepositoryID = "repository_id"

type auditScanKey struct{}

type auditScanActor struct {
	ID        uint
	SkillName string
}

// WithAuditScan carries authenticated scan attribution without retaining its token.
// It overrides caller-supplied actor text for finding audit events only.
func WithAuditScan(ctx context.Context, scanID uint, skillName string) context.Context {
	return context.WithValue(ctx, auditScanKey{}, auditScanActor{ID: scanID, SkillName: skillName})
}

// AuditScanAttribution attributes an event to the authenticated scan carried
// by ctx. It adds scan_id and skill_name to payload and returns the actor text
// that replaces by. Without a scan in ctx it returns by unchanged.
func AuditScanAttribution(ctx context.Context, by string, payload map[string]any) string {
	scan, ok := ctx.Value(auditScanKey{}).(auditScanActor)
	if !ok {
		return by
	}
	payload["scan_id"] = scan.ID
	payload["skill_name"] = scan.SkillName
	if scan.SkillName != "" {
		return fmt.Sprintf("%s (scan %d)", scan.SkillName, scan.ID)
	}
	return fmt.Sprintf("scan %d", scan.ID)
}

// findingMutationPayload builds the event for a finding field write. The
// disclosure draft is free text, so only its length before and after is kept.
func findingMutationPayload(finding *Finding, field string, oldValue, newValue any) (string, map[string]any, bool) {
	payload := map[string]any{AuditKeyRepositoryID: finding.RepositoryID, "field": field}
	switch field {
	case "status":
		payload["old_value"], payload["new_value"] = oldValue, newValue
		return AuditEventFindingStatusChanged, payload, true
	case "severity":
		payload["old_value"], payload["new_value"] = oldValue, newValue
		return AuditEventFindingSeverityChanged, payload, true
	case "labels":
		payload["old_value"], payload["new_value"] = oldValue, newValue
		return AuditEventFindingLabelsChanged, payload, true
	case "disclosure_draft":
		payload["old_length"], payload["new_length"] = runeLength(oldValue), runeLength(newValue)
		return AuditEventDisclosureDraftUpdated, payload, true
	default:
		return "", nil, false
	}
}

func runeLength(v any) int {
	s, _ := v.(string)
	return utf8.RuneCountInString(s)
}

func logFindingMutation(tx *gorm.DB, finding *Finding, field string, oldValue, newValue any, source FindingSource, by string) error {
	kind, payload, ok := findingMutationPayload(finding, field, oldValue, newValue)
	if !ok {
		return nil
	}
	by = AuditScanAttribution(tx.Statement.Context, by, payload)
	return LogEvent(tx, AuditEventInput{
		Kind: kind, SubjectType: AuditSubjectFinding, SubjectID: finding.ID,
		Source: source, Actor: by, Payload: payload,
	})
}

// AuditEventInput is the write-only form of AuditEvent. Payload is marshaled
// by LogEvent so callers cannot persist malformed JSON accidentally.
type AuditEventInput struct {
	Kind        string
	SubjectType string
	SubjectID   uint
	Actor       string
	Source      FindingSource
	Payload     any
}

// LogEvent appends one audit event. Call it from the transaction that mutates
// the subject so state and its audit trail are committed or rolled back
// together.
func LogEvent(gdb *gorm.DB, input AuditEventInput) error {
	input.Kind = strings.TrimSpace(input.Kind)
	input.SubjectType = strings.TrimSpace(input.SubjectType)
	if input.Kind == "" {
		return fmt.Errorf("audit event kind is required")
	}
	if input.SubjectType == "" || input.SubjectID == 0 {
		return fmt.Errorf("audit event subject is required")
	}
	if input.Source == "" {
		return fmt.Errorf("audit event source is required")
	}
	if input.Payload == nil {
		input.Payload = map[string]any{}
	}
	payload, err := json.Marshal(input.Payload)
	if err != nil {
		return fmt.Errorf("marshal audit event payload: %w", err)
	}
	return gdb.Create(&AuditEvent{
		Kind:        input.Kind,
		SubjectType: input.SubjectType,
		SubjectID:   input.SubjectID,
		Actor:       input.Actor,
		Source:      input.Source,
		Payload:     string(payload),
	}).Error
}

// LogScanEvent appends a lifecycle event for scan. The payload deliberately
// captures fields needed for a timeline without duplicating the scan report or
// transcript, which can be large and may contain sensitive material.
func LogScanEvent(gdb *gorm.DB, kind string, scan *Scan) error {
	if scan == nil {
		return fmt.Errorf("audit event scan is required")
	}
	payload := map[string]any{
		"repository_id": scan.RepositoryID,
		"scan_kind":     scan.Kind,
		"status":        scan.Status,
		"skill_name":    scan.SkillName,
		"model":         scan.Model,
		"backend":       scan.Backend,
	}
	if scan.FindingID != nil {
		payload["finding_id"] = *scan.FindingID
	}
	if scan.DependentID != nil {
		payload["dependent_id"] = *scan.DependentID
	}
	if scan.StartedAt != nil {
		payload["started_at"] = scan.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	if scan.FinishedAt != nil {
		payload["finished_at"] = scan.FinishedAt.UTC().Format(time.RFC3339Nano)
	}
	if scan.StartedAt != nil && scan.FinishedAt != nil {
		payload["duration_ms"] = scan.FinishedAt.Sub(*scan.StartedAt).Milliseconds()
	}
	if kind != AuditEventScanStarted {
		payload["cost_usd"] = scan.CostUSD
		payload["turns"] = scan.Turns
		payload["input_tokens"] = scan.InputTokens
		payload["output_tokens"] = scan.OutputTokens
		payload["cache_read_tokens"] = scan.CacheReadTokens
		payload["cache_write_tokens"] = scan.CacheWriteTokens
		if scan.Error != "" {
			payload["error"] = scan.Error
		}
	}
	actor := scan.SkillName
	if actor == "" {
		actor = scan.Kind
	}
	return LogEvent(gdb, AuditEventInput{
		Kind:        kind,
		SubjectType: AuditSubjectScan,
		SubjectID:   scan.ID,
		Actor:       actor,
		Source:      SourceSystem,
		Payload:     payload,
	})
}

// ScanLifecycleEventKind returns the event associated with a persisted scan
// lifecycle status. Queued scans are intentionally omitted: this first audit
// surface records state transitions performed by the worker.
func ScanLifecycleEventKind(status ScanStatus) (string, bool) {
	switch status {
	case ScanDone:
		return AuditEventScanFinished, true
	case ScanFailed:
		return AuditEventScanFailed, true
	case ScanCancelled:
		return AuditEventScanCancelled, true
	case ScanPaused:
		return AuditEventScanPaused, true
	default:
		return "", false
	}
}
