package db

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestChatTitle(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"hello", "hello"},
		{"  spaced  ", "spaced"},
		{"first line\nsecond line", "first line"},
		{strings.Repeat("a", 100), strings.Repeat("a", 80) + "..."},
		// Cutting on bytes would split the rune straddling the limit and
		// persist invalid UTF-8.
		{strings.Repeat("é", 100), strings.Repeat("é", 80) + "..."},
	}
	for _, tc := range cases {
		got := chatTitle(tc.in)
		if got != tc.want {
			t.Errorf("chatTitle(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("chatTitle(%q) produced invalid UTF-8: %q", tc.in, got)
		}
	}
}

func TestValidChatRole(t *testing.T) {
	for _, r := range []string{ChatRoleUser, ChatRoleAssistant} {
		if !ValidChatRole(r) {
			t.Errorf("ValidChatRole(%q) = false, want true", r)
		}
	}
	for _, r := range []string{"", "system", "User"} {
		if ValidChatRole(r) {
			t.Errorf("ValidChatRole(%q) = true, want false", r)
		}
	}
}

func TestCreateConversation(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	repoConv, err := CreateConversation(gdb, f.RepositoryID, nil, "claude-x", "Why is this repo laid out this way?")
	if err != nil {
		t.Fatalf("CreateConversation (repo): %v", err)
	}
	if repoConv.FindingID != nil {
		t.Errorf("repo-wide conversation should have nil FindingID, got %v", repoConv.FindingID)
	}
	if repoConv.Title != "Why is this repo laid out this way?" {
		t.Errorf("unexpected title %q", repoConv.Title)
	}
	if repoConv.Model != "claude-x" {
		t.Errorf("model not persisted: %q", repoConv.Model)
	}

	findConv, err := CreateConversation(gdb, f.RepositoryID, &f.ID, "claude-x", "Is this exploitable?")
	if err != nil {
		t.Fatalf("CreateConversation (finding): %v", err)
	}
	if findConv.FindingID == nil || *findConv.FindingID != f.ID {
		t.Errorf("finding-scoped conversation lost its FindingID: %v", findConv.FindingID)
	}
}

func TestCreateConversationRequiresRepo(t *testing.T) {
	gdb := newTestDB(t)
	if _, err := CreateConversation(gdb, 0, nil, "m", "hi"); err == nil {
		t.Fatal("expected error creating a conversation without a repository")
	}
}

func TestAddChatMessage(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	conv, err := CreateConversation(gdb, f.RepositoryID, nil, "m", "hello")
	if err != nil {
		t.Fatal(err)
	}
	created := conv.UpdatedAt

	if _, err := AddChatMessage(gdb, conv.ID, ChatRoleUser, "hello"); err != nil {
		t.Fatalf("AddChatMessage user: %v", err)
	}
	if _, err := AddChatMessage(gdb, conv.ID, ChatRoleAssistant, "hi there"); err != nil {
		t.Fatalf("AddChatMessage assistant: %v", err)
	}

	var reloaded Conversation
	if err := gdb.First(&reloaded, conv.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !reloaded.UpdatedAt.After(created) && !reloaded.UpdatedAt.Equal(created) {
		// UpdatedAt must have advanced to at least the last message time.
		t.Errorf("conversation UpdatedAt did not advance: %v -> %v", created, reloaded.UpdatedAt)
	}
}

func TestAddChatMessageRejectsBadInput(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	conv, err := CreateConversation(gdb, f.RepositoryID, nil, "m", "hello")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := AddChatMessage(gdb, conv.ID, "system", "x"); err == nil {
		t.Error("expected error for invalid role")
	}
	if _, err := AddChatMessage(gdb, conv.ID, ChatRoleUser, "   "); err == nil {
		t.Error("expected error for empty content")
	}
}

func TestSetConversationSession(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	conv, err := CreateConversation(gdb, f.RepositoryID, nil, "m", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetConversationSession(gdb, conv.ID, "sess-123", "claude"); err != nil {
		t.Fatalf("SetConversationSession: %v", err)
	}
	var reloaded Conversation
	if err := gdb.First(&reloaded, conv.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reloaded.SessionID != "sess-123" || reloaded.Backend != "claude" {
		t.Errorf("session/backend not persisted: %q / %q", reloaded.SessionID, reloaded.Backend)
	}
}

func TestLoadConversationOrdersMessages(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	conv, err := CreateConversation(gdb, f.RepositoryID, nil, "m", "first")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct{ role, body string }{
		{ChatRoleUser, "first"},
		{ChatRoleAssistant, "second"},
		{ChatRoleUser, "third"},
	} {
		if _, err := AddChatMessage(gdb, conv.ID, m.role, m.body); err != nil {
			t.Fatal(err)
		}
	}

	loaded, err := LoadConversation(gdb, conv.ID)
	if err != nil {
		t.Fatalf("LoadConversation: %v", err)
	}
	if loaded.Repository.ID != f.RepositoryID {
		t.Errorf("repository not preloaded: %+v", loaded.Repository)
	}
	want := []string{"first", "second", "third"}
	if len(loaded.Messages) != len(want) {
		t.Fatalf("got %d messages, want %d", len(loaded.Messages), len(want))
	}
	for i, m := range loaded.Messages {
		if m.Content != want[i] {
			t.Errorf("message %d = %q, want %q", i, m.Content, want[i])
		}
	}
}

func TestLoadConversationNotFound(t *testing.T) {
	gdb := newTestDB(t)
	if _, err := LoadConversation(gdb, 999); err == nil {
		t.Fatal("expected error loading a missing conversation")
	}
}

func TestConversationsForCapsRows(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	for i := range chatConversationCap + 5 {
		if _, err := CreateConversation(gdb, f.RepositoryID, nil, "m", fmt.Sprintf("chat %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	convs, err := ConversationsFor(gdb, f.RepositoryID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != chatConversationCap {
		t.Errorf("got %d conversations, want the list capped at %d", len(convs), chatConversationCap)
	}
}

func TestConversationsForScopes(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	if _, err := CreateConversation(gdb, f.RepositoryID, nil, "m", "repo chat A"); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateConversation(gdb, f.RepositoryID, &f.ID, "m", "finding chat"); err != nil {
		t.Fatal(err)
	}

	repoConvs, err := ConversationsFor(gdb, f.RepositoryID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(repoConvs) != 1 || repoConvs[0].Title != "repo chat A" {
		t.Errorf("repo-scoped list wrong: %+v", repoConvs)
	}

	findConvs, err := ConversationsFor(gdb, f.RepositoryID, &f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findConvs) != 1 || findConvs[0].Title != "finding chat" {
		t.Errorf("finding-scoped list wrong: %+v", findConvs)
	}
}
