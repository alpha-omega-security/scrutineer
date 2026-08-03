package db

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Chat message roles. A conversation alternates user prompts and the
// assistant's replies.
const (
	ChatRoleUser      = "user"
	ChatRoleAssistant = "assistant"
)

// Conversation is a persisted chat session about a repository or one of
// its findings, backed by an agent run with read-only access to the clone
// and a snapshot of the repository's findings. FindingID is set for a
// per-finding chat and nil for a repository-wide chat.
//
// SessionID/Backend mirror Scan: they let a follow-up turn resume the
// harness conversation with full history via `--resume` instead of
// restarting from turn 0. Backend is the harness that owns SessionID, so a
// turn only reuses the id while the running harness still matches.
type Conversation struct {
	ID           uint `gorm:"primarykey"`
	RepositoryID uint `gorm:"index;not null"`
	Repository   Repository
	// FindingID scopes the conversation to a single finding when set; nil
	// means a repository-wide chat. A finding-scoped conversation still
	// carries the finding's RepositoryID so repo-level cleanup reaches it.
	FindingID *uint `gorm:"index"`
	// Title is a short label derived from the first user message.
	Title string
	// Model is the model the turns run under, snapshotted at creation.
	Model string
	// Backend is the harness (agent CLI) that owns SessionID, e.g. "claude".
	Backend string
	// SessionID is the harness session the last turn belonged to, captured
	// from its event stream; the next turn resumes it. Empty until the
	// first turn completes.
	SessionID string

	Messages []ChatMessage `gorm:"constraint:OnDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// ChatMessage is one turn in a Conversation: a user prompt or the
// assistant's reply. Content holds the rendered text; for an assistant
// message it is the accumulated streamed response.
type ChatMessage struct {
	ID             uint   `gorm:"primarykey"`
	ConversationID uint   `gorm:"index;not null"`
	Role           string // user | assistant
	Content        string `gorm:"type:text"`

	CreatedAt time.Time
}

// ValidChatRole reports whether s is a role a ChatMessage may carry.
func ValidChatRole(s string) bool {
	return s == ChatRoleUser || s == ChatRoleAssistant
}

// chatTitleMaxLen caps the derived conversation title so a long first
// message doesn't bloat the sidebar; the full text lives in the message.
const chatTitleMaxLen = 80

// chatTitle derives a one-line title from the first user message.
func chatTitle(firstMessage string) string {
	first, _, _ := strings.Cut(firstMessage, "\n")
	t := strings.TrimSpace(first)
	// Cut on runes, not bytes: slicing mid-rune stores invalid UTF-8 that the
	// page then renders as a replacement character.
	if r := []rune(t); len(r) > chatTitleMaxLen {
		t = strings.TrimSpace(string(r[:chatTitleMaxLen])) + "..."
	}
	return t
}

// CreateConversation starts a conversation scoped to repoID, optionally to a
// single finding when findingID is non-nil. title is derived from firstMessage;
// the caller persists that message separately with AddChatMessage.
func CreateConversation(gdb *gorm.DB, repoID uint, findingID *uint, model, firstMessage string) (*Conversation, error) {
	if repoID == 0 {
		return nil, fmt.Errorf("conversation requires a repository")
	}
	c := &Conversation{
		RepositoryID: repoID,
		FindingID:    findingID,
		Title:        chatTitle(firstMessage),
		Model:        model,
	}
	if err := gdb.Create(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

// AddChatMessage appends a timestamped message to a conversation and bumps the
// conversation's UpdatedAt so recency ordering reflects the latest turn.
func AddChatMessage(gdb *gorm.DB, convID uint, role, content string) (*ChatMessage, error) {
	if !ValidChatRole(role) {
		return nil, fmt.Errorf("invalid chat role %q", role)
	}
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("chat message content is empty")
	}
	m := &ChatMessage{
		ConversationID: convID,
		Role:           role,
		Content:        content,
		CreatedAt:      time.Now(),
	}
	if err := gdb.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(m).Error; err != nil {
			return err
		}
		return tx.Model(&Conversation{}).Where("id = ?", convID).
			Update("updated_at", m.CreatedAt).Error
	}); err != nil {
		return nil, err
	}
	return m, nil
}

// SetConversationSession records the harness session the last turn ran under so
// the next turn can resume it. Backend pins which agent CLI the id belongs to.
func SetConversationSession(gdb *gorm.DB, convID uint, sessionID, backend string) error {
	return gdb.Model(&Conversation{}).Where("id = ?", convID).
		Updates(map[string]any{"session_id": sessionID, "backend": backend}).Error
}

// DeleteConversation drops a conversation and its messages. The messages go
// explicitly rather than through ON DELETE CASCADE: sqlite's foreign_keys
// pragma is per-connection and set on only one pooled connection, so the
// cascade may not fire on the connection serving this delete.
func DeleteConversation(gdb *gorm.DB, id uint) error {
	return gdb.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("conversation_id = ?", id).Delete(&ChatMessage{}).Error; err != nil {
			return err
		}
		return tx.Delete(&Conversation{}, id).Error
	})
}

// LoadConversation returns a conversation with its messages in chronological
// order and its repository preloaded.
func LoadConversation(gdb *gorm.DB, id uint) (*Conversation, error) {
	var c Conversation
	if err := gdb.Preload("Repository").
		Preload("Messages", func(tx *gorm.DB) *gorm.DB { return tx.Order("created_at, id") }).
		First(&c, id).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

// chatConversationCap bounds the chat panels on the repository and finding
// pages, which render the whole slice on every page load next to a dozen
// other collections. Mirrors the row caps those pages already apply.
const chatConversationCap = 50

// ConversationsFor lists the conversations attached to a repository or, when
// findingID is non-nil, to that single finding. A finding-scoped query keys on
// finding_id alone (repoID is ignored) so a legacy finding whose denormalized
// repository_id differs from its scan's still lists its chats. Newest activity
// first, capped at chatConversationCap.
func ConversationsFor(gdb *gorm.DB, repoID uint, findingID *uint) ([]Conversation, error) {
	var q *gorm.DB
	if findingID != nil {
		q = gdb.Where("finding_id = ?", *findingID)
	} else {
		q = gdb.Where("repository_id = ? AND finding_id IS NULL", repoID)
	}
	var out []Conversation
	if err := q.Order("updated_at DESC, id DESC").Limit(chatConversationCap).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}
