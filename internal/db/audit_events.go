package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	AuditSubjectScan = "scan"

	AuditEventScanStarted   = "scan.started"
	AuditEventScanFinished  = "scan.finished"
	AuditEventScanFailed    = "scan.failed"
	AuditEventScanCancelled = "scan.cancelled"
	AuditEventScanPaused    = "scan.paused"
)

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
