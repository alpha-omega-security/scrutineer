package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/worker"
)

// chatTurnRunner runs one chat turn. *worker.ChatRunner satisfies it in
// production; tests substitute a stub so handler behaviour can be exercised
// without a real agent.
type chatTurnRunner interface {
	RunTurn(ctx context.Context, conv *db.Conversation, userMessage string, emit func(worker.Event)) (worker.ChatTurnResult, error)
}

// chatTurnTimeout bounds a single background chat turn so a stuck agent can't
// pin a workspace forever.
const chatTurnTimeout = 15 * time.Minute

// chatTurnSlots sizes the concurrent-chat-turn pool from the queue's own
// concurrency, so chat and scans compete for the host on the same terms. A
// server built without a queue still gets one slot, since a zero-capacity
// channel would block every turn forever.
func chatTurnSlots(q *queue.Queue) int {
	if q == nil || q.Concurrency() < 1 {
		return 1
	}
	return q.Concurrency()
}

// conversationCreateRepo starts a repo-wide chat from the repository page.
func (s *Server) conversationCreateRepo(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	s.startConversation(w, r, repo.ID, nil, fmt.Sprintf("/repositories/%d", repo.ID))
}

// conversationCreateFinding starts a finding-scoped chat from the finding page.
func (s *Server) conversationCreateFinding(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	backTo := fmt.Sprintf("/findings/%d", f.ID)
	repoID := f.RepositoryID
	if repoID == 0 {
		// Legacy rows may not have the denormalized repository_id; fall back to
		// the producing scan, mirroring findingShow.
		var scan db.Scan
		if err := s.DB.First(&scan, f.ScanID).Error; err != nil {
			s.Log.Error("chat: load finding scan", "finding", f.ID, "scan", f.ScanID, "err", err)
			setFlash(w, Flash{Category: errorKey, Title: "Chat unavailable", Description: "Could not resolve which repository this finding belongs to."})
			s.redirect(w, r, backTo)
			return
		}
		repoID = scan.RepositoryID
	}
	fid := f.ID
	s.startConversation(w, r, repoID, &fid, backTo)
}

// startConversation creates a conversation from the first message, persists that
// message, kicks off the opening turn, and sends the analyst to the chat page.
func (s *Server) startConversation(w http.ResponseWriter, r *http.Request, repoID uint, findingID *uint, backTo string) {
	if s.chatRunner == nil {
		setFlash(w, Flash{Category: errorKey, Title: "Chat unavailable", Description: "No agent runner is configured."})
		s.redirect(w, r, backTo)
		return
	}
	message := strings.TrimSpace(r.FormValue("message"))
	if message == "" {
		setFlash(w, Flash{Category: errorKey, Title: "Empty message", Description: "Type a message to start the conversation."})
		s.redirect(w, r, backTo)
		return
	}
	conv, err := db.CreateConversation(s.DB, repoID, findingID, s.DefaultModel(), message)
	if err != nil {
		s.Log.Error("chat: create conversation", "repo", repoID, "err", err)
		setFlash(w, Flash{Category: errorKey, Title: "Chat unavailable", Description: "The conversation could not be created."})
		s.redirect(w, r, backTo)
		return
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, message); err != nil {
		// The conversation row is already committed; drop it rather than leave
		// a titled, message-less chat in the panel.
		s.Log.Error("chat: persist first message", "conv", conv.ID, "err", err)
		s.DB.Delete(&db.Conversation{}, conv.ID)
		setFlash(w, Flash{Category: errorKey, Title: "Chat unavailable", Description: "The message could not be saved."})
		s.redirect(w, r, backTo)
		return
	}
	s.beginChatTurn(conv.ID)
	s.spawnTurn(conv.ID, message)
	s.redirect(w, r, fmt.Sprintf("/conversations/%d", conv.ID))
}

// conversationShow renders the full chat page.
func (s *Server) conversationShow(w http.ResponseWriter, r *http.Request) {
	conv, ok := s.loadConversation(w, r)
	if !ok {
		return
	}
	var findingID uint
	if conv.FindingID != nil {
		findingID = *conv.FindingID
	}
	s.render(w, r, "conversation_show.html", map[string]any{
		"Conv":      conv,
		"Active":    s.chatTurnActive(conv.ID),
		"BackHref":  conversationBackHref(conv),
		"FindingID": findingID,
	})
}

// conversationMessage appends the analyst's message and runs the next turn. It
// refuses while a turn is already in flight so the two can't interleave on the
// same session.
func (s *Server) conversationMessage(w http.ResponseWriter, r *http.Request) {
	conv, ok := loadByID[db.Conversation](s, w, r)
	if !ok {
		return
	}
	dest := fmt.Sprintf("/conversations/%d", conv.ID)
	message := strings.TrimSpace(r.FormValue("message"))
	if message == "" {
		setFlash(w, Flash{Category: errorKey, Title: "Empty message", Description: "Type a message to send."})
		s.redirect(w, r, dest)
		return
	}
	if s.chatRunner == nil {
		setFlash(w, Flash{Category: errorKey, Title: "Chat unavailable", Description: "No agent runner is configured."})
		s.redirect(w, r, dest)
		return
	}
	if !s.beginChatTurn(conv.ID) {
		setFlash(w, Flash{Category: errorKey, Title: "Still thinking", Description: "Wait for the current reply before sending another message."})
		s.redirect(w, r, dest)
		return
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, message); err != nil {
		s.endChatTurn(conv.ID)
		s.Log.Error("chat: persist message", "conv", conv.ID, "err", err)
		setFlash(w, Flash{Category: errorKey, Title: "Chat unavailable", Description: "The message could not be saved."})
		s.redirect(w, r, dest)
		return
	}
	s.spawnTurn(conv.ID, message)
	s.redirect(w, r, dest)
}

// runChatTurn executes one turn in the background: it streams activity to the
// conversation's SSE subscribers, persists the assistant reply and the session
// to resume next time, then signals completion so the page reloads the clean
// transcript.
func (s *Server) runChatTurn(convID uint, message string) {
	defer s.Broker.Publish(Event{Name: "chat-done", ConvID: convID})
	defer s.endChatTurn(convID)

	// A chat turn spawns the same agent (and container) a scan does, so it
	// takes a slot from a pool sized like the worker's rather than running
	// unbounded from an HTTP-triggered goroutine.
	s.chatSlots <- struct{}{}
	defer func() { <-s.chatSlots }()

	ctx, cancel := context.WithTimeout(context.Background(), chatTurnTimeout)
	defer cancel()

	conv, err := db.LoadConversation(s.DB, convID)
	if err != nil {
		s.Log.Error("chat: load conversation", "conv", convID, "err", err)
		return
	}
	emit := func(e worker.Event) {
		s.Broker.Publish(Event{Name: "chat-activity", Data: worker.FormatEvent(e), ConvID: convID})
	}
	res, err := s.chatRunner.RunTurn(ctx, conv, message, emit)
	// The session is recorded even when the turn failed: a resume that forked
	// a new session before dying must be carried forward, or the next turn
	// resumes the stale id and this turn's message never reaches the model. An
	// empty id means "nothing new to record", never "forget the session".
	if res.SessionID != "" {
		if serr := db.SetConversationSession(s.DB, convID, res.SessionID, res.Backend); serr != nil {
			s.Log.Error("chat: persist session", "conv", convID, "err", serr)
		}
	}
	reply := res.Response
	if err != nil {
		s.Log.Warn("chat turn failed", "conv", convID, "err", err)
		// A turn that hit the turn cap or the timeout has usually already
		// produced the answer; keep it and note the failure underneath rather
		// than replacing a good reply with the error alone.
		note := "The assistant could not complete this turn: " + err.Error()
		if strings.TrimSpace(reply) == "" {
			reply = note
		} else {
			reply += "\n\n_" + note + "_"
		}
	}
	if _, err := db.AddChatMessage(s.DB, convID, db.ChatRoleAssistant, reply); err != nil {
		s.Log.Error("chat: persist assistant message", "conv", convID, "err", err)
	}
}

// beginChatTurn marks a conversation busy, returning false if a turn is already
// running for it.
func (s *Server) beginChatTurn(convID uint) bool {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	if _, active := s.chatActive[convID]; active {
		return false
	}
	s.chatActive[convID] = struct{}{}
	return true
}

func (s *Server) endChatTurn(convID uint) {
	s.chatMu.Lock()
	delete(s.chatActive, convID)
	s.chatMu.Unlock()
}

func (s *Server) chatTurnActive(convID uint) bool {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	_, active := s.chatActive[convID]
	return active
}

func (s *Server) loadConversation(w http.ResponseWriter, r *http.Request) (*db.Conversation, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	conv, err := db.LoadConversation(s.DB, uint(id))
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	return conv, true
}

// conversationBackHref links a conversation back to the page it belongs to: the
// finding for a finding-scoped chat, the repository otherwise.
func conversationBackHref(conv *db.Conversation) string {
	if conv.FindingID != nil {
		return fmt.Sprintf("/findings/%d", *conv.FindingID)
	}
	return fmt.Sprintf("/repositories/%d", conv.RepositoryID)
}
