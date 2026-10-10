package db

import "time"

// Receipts grant access to submission status and are excluded from finding exports.
type AkritesSubmission struct {
	ID           uint `gorm:"primaryKey"`
	FindingID    uint `gorm:"not null;uniqueIndex"`
	Endpoint     string
	Receipt      string
	Status       string
	StatusAt     *time.Time
	NextPollAt   *time.Time `gorm:"index"`
	PollAttempts int
	LastError    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
