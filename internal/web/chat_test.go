package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// stubChatRunner is a chatTurnRunner double: it records the message it was
// handed and returns a canned result (or error).
type stubChatRunner struct {
	resp    string
	session string
	backend string
	err     error
	// partial is the answer a failing turn had already produced, which the
	// real runner hands back alongside its error.
	partial string
	gotMsg  string
}

func (r *stubChatRunner) RunTurn(_ context.Context, _ *db.Conversation, msg string, emit func(worker.Event)) (worker.ChatTurnResult, error) {
	r.gotMsg = msg
	emit(worker.Event{Kind: worker.KindText, Text: "working"})
	if r.err != nil {
		return worker.ChatTurnResult{Response: r.partial, SessionID: r.session, Backend: r.backend}, r.err
	}
	return worker.ChatTurnResult{Response: r.resp, SessionID: r.session, Backend: r.backend}, nil
}

// chatServer wires a test server with a synchronous turn runner so a POST that
// starts a turn completes before the request returns.
func chatServer(t *testing.T) (*Server, func(), *stubChatRunner) {
	t.Helper()
	s, done := newTestServer(t)
	stub := &stubChatRunner{resp: "The answer.", session: "sess-1", backend: "claude"}
	s.chatRunner = stub
	s.spawnTurn = func(convID uint, message string) { s.runChatTurn(convID, message) }
	return s, done, stub
}

func seedRepo(t *testing.T, s *Server) db.Repository {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/chat", Name: "chatrepo"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func getPage(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestConversationCreateRepo(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	repo := seedRepo(t, s)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/conversations", repo.ID),
		url.Values{"message": {"How does auth work?"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/conversations/") {
		t.Fatalf("Location = %q, want /conversations/N", loc)
	}

	var convs []db.Conversation
	s.DB.Find(&convs)
	if len(convs) != 1 {
		t.Fatalf("got %d conversations, want 1", len(convs))
	}
	if convs[0].FindingID != nil {
		t.Errorf("repo chat should have nil FindingID")
	}
	if stub.gotMsg != "How does auth work?" {
		t.Errorf("runner got message %q", stub.gotMsg)
	}

	loaded, _ := db.LoadConversation(s.DB, convs[0].ID)
	if len(loaded.Messages) != 2 {
		t.Fatalf("got %d messages, want user + assistant", len(loaded.Messages))
	}
	if loaded.Messages[0].Role != db.ChatRoleUser || loaded.Messages[1].Role != db.ChatRoleAssistant {
		t.Errorf("message roles = %q, %q", loaded.Messages[0].Role, loaded.Messages[1].Role)
	}
	if loaded.Messages[1].Content != "The answer." {
		t.Errorf("assistant content = %q", loaded.Messages[1].Content)
	}
	if loaded.SessionID != "sess-1" || loaded.Backend != "claude" {
		t.Errorf("session not persisted: %q / %q", loaded.SessionID, loaded.Backend)
	}
}

func TestConversationCreateEmptyMessage(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/conversations", repo.ID),
		url.Values{"message": {"   "}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 back to repo", w.Code)
	}
	var n int64
	s.DB.Model(&db.Conversation{}).Count(&n)
	if n != 0 {
		t.Errorf("empty message must not create a conversation, got %d", n)
	}
}

func TestConversationCreateChatUnavailable(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	s.chatRunner = nil
	repo := seedRepo(t, s)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/conversations", repo.ID),
		url.Values{"message": {"hi"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	var n int64
	s.DB.Model(&db.Conversation{}).Count(&n)
	if n != 0 {
		t.Errorf("no conversation should be created without a runner, got %d", n)
	}
}

func TestConversationCreateFinding(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	f := seedFindingForForm(t, s)

	w := postForm(t, s, fmt.Sprintf("/findings/%d/conversations", f.ID),
		url.Values{"message": {"is this exploitable?"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	var conv db.Conversation
	if err := s.DB.First(&conv).Error; err != nil {
		t.Fatal(err)
	}
	if conv.FindingID == nil || *conv.FindingID != f.ID {
		t.Errorf("finding chat lost its FindingID: %v", conv.FindingID)
	}
	if conv.RepositoryID != f.RepositoryID {
		t.Errorf("conversation repo = %d, want %d", conv.RepositoryID, f.RepositoryID)
	}
}

func TestStartConversationWithoutRepoRedirects(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	// A finding whose repository could not be resolved: the analyst gets the
	// page back with an error, not a bare database message on a dead-end page.
	r := httptest.NewRequest("POST", "/findings/1/conversations", strings.NewReader("message=hi"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = testHost
	w := httptest.NewRecorder()
	s.startConversation(w, r, 0, nil, "/findings/1")

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 back to the finding; body=%s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "conversation requires a repository") {
		t.Errorf("database error leaked to the page: %s", w.Body)
	}
	var n int64
	s.DB.Model(&db.Conversation{}).Count(&n)
	if n != 0 {
		t.Errorf("a conversation was created without a repository, got %d", n)
	}
}

func TestChatTurnsAreBounded(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)

	var mu sync.Mutex
	var inFlight, peak int
	release := make(chan struct{})
	s.chatRunner = &blockingChatRunner{start: func() {
		mu.Lock()
		inFlight++
		peak = max(peak, inFlight)
		mu.Unlock()
		<-release
		mu.Lock()
		inFlight--
		mu.Unlock()
	}}

	var wg sync.WaitGroup
	for range cap(s.chatSlots) + 2 {
		conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hi")
		if err != nil {
			t.Fatal(err)
		}
		s.beginChatTurn(conv.ID)
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runChatTurn(conv.ID, "hi")
		}()
	}
	// Let the queued turns pile up before letting any of them finish.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if peak > cap(s.chatSlots) {
		t.Errorf("%d turns ran at once, want at most %d", peak, cap(s.chatSlots))
	}
}

// blockingChatRunner holds each turn inside RunTurn so the caller can observe
// how many run concurrently.
type blockingChatRunner struct{ start func() }

func (r *blockingChatRunner) RunTurn(context.Context, *db.Conversation, string, func(worker.Event)) (worker.ChatTurnResult, error) {
	r.start()
	return worker.ChatTurnResult{Response: "done"}, nil
}

func TestConversationMessageAppends(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, "hello"); err != nil {
		t.Fatal(err)
	}
	stub.resp = "follow-up answer"

	w := postForm(t, s, fmt.Sprintf("/conversations/%d/messages", conv.ID),
		url.Values{"message": {"and what about crypto?"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	loaded, _ := db.LoadConversation(s.DB, conv.ID)
	if len(loaded.Messages) != 3 {
		t.Fatalf("got %d messages, want 3", len(loaded.Messages))
	}
	if loaded.Messages[2].Content != "follow-up answer" {
		t.Errorf("last message = %q, want the new assistant answer", loaded.Messages[2].Content)
	}
}

func TestConversationMessageConcurrentGuard(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hello")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an in-flight turn.
	s.beginChatTurn(conv.ID)

	w := postForm(t, s, fmt.Sprintf("/conversations/%d/messages", conv.ID),
		url.Values{"message": {"second message while busy"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (busy redirect)", w.Code)
	}
	var n int64
	s.DB.Model(&db.ChatMessage{}).Where("conversation_id = ?", conv.ID).Count(&n)
	if n != 0 {
		t.Errorf("no message should be appended while a turn is running, got %d", n)
	}
}

func TestConversationShowRenders(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "explain the layout")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, "explain the layout"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleAssistant, "It is a **modular** monolith."); err != nil {
		t.Fatal(err)
	}

	w := getPage(t, s, fmt.Sprintf("/conversations/%d", conv.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"explain the layout", "modular", "/conversations/" + fmt.Sprint(conv.ID) + "/messages"} {
		if !strings.Contains(body, want) {
			t.Errorf("conversation page missing %q", want)
		}
	}
}

func TestConversationShowNotFound(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	if w := getPage(t, s, "/conversations/9999"); w.Code != http.StatusNotFound {
		t.Errorf("missing conversation: status = %d, want 404", w.Code)
	}
}

func TestRunChatTurnErrorPersistsMessage(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hi")
	if err != nil {
		t.Fatal(err)
	}
	stub.err = fmt.Errorf("runner blew up")

	s.beginChatTurn(conv.ID)
	s.runChatTurn(conv.ID, "hi")

	if s.chatTurnActive(conv.ID) {
		t.Error("turn should be marked inactive after runChatTurn returns")
	}
	loaded, _ := db.LoadConversation(s.DB, conv.ID)
	if len(loaded.Messages) != 1 || loaded.Messages[0].Role != db.ChatRoleAssistant {
		t.Fatalf("expected one assistant error message, got %+v", loaded.Messages)
	}
	if !strings.Contains(loaded.Messages[0].Content, "runner blew up") {
		t.Errorf("error message not surfaced: %q", loaded.Messages[0].Content)
	}
}

func TestRunChatTurnKeepsSessionOnError(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hi")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationSession(s.DB, conv.ID, "sess-old", "claude"); err != nil {
		t.Fatal(err)
	}
	// A resume that forked a new session before failing: the next turn must
	// continue sess-new, or this turn's message never reaches the model.
	stub.session = "sess-new"
	stub.err = fmt.Errorf("claude exited: signal killed")

	s.beginChatTurn(conv.ID)
	s.runChatTurn(conv.ID, "hi")

	loaded, _ := db.LoadConversation(s.DB, conv.ID)
	if loaded.SessionID != "sess-new" {
		t.Errorf("session = %q, want the id the failed turn advanced to", loaded.SessionID)
	}
}

func TestRunChatTurnKeepsSessionWhenRunnerReportsNone(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hi")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationSession(s.DB, conv.ID, "sess-1", "claude"); err != nil {
		t.Fatal(err)
	}
	// A successful turn whose stream never re-announced the session must not
	// wipe the resume chain, which would silently drop the whole thread.
	stub.session = ""

	s.beginChatTurn(conv.ID)
	s.runChatTurn(conv.ID, "and then?")

	loaded, _ := db.LoadConversation(s.DB, conv.ID)
	if loaded.SessionID != "sess-1" {
		t.Errorf("session = %q, want the previous id preserved", loaded.SessionID)
	}
}

func TestEventsAnnouncesFinishedTurnOnConnect(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hi")
	if err != nil {
		t.Fatal(err)
	}
	// The turn finished between the page render and this connection, so its
	// chat-done reached nobody; the page would spin forever without this.
	w := getEvents(t, s, conv.ID)
	if !strings.Contains(w.Body.String(), "event: chat-done") {
		t.Errorf("no chat-done for an idle conversation:\n%s", w.Body)
	}
}

// getEvents opens the SSE endpoint for one conversation with an already
// cancelled context: the handler writes whatever it emits on connect, then
// its stream loop returns instead of blocking the test.
func getEvents(t *testing.T, s *Server, convID uint) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", fmt.Sprintf("/events?conv=%d", convID), nil)
	r.Host = testHost
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r.WithContext(ctx))
	return w
}

func TestEventsStaysSilentWhileTurnRuns(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hi")
	if err != nil {
		t.Fatal(err)
	}
	s.beginChatTurn(conv.ID)
	defer s.endChatTurn(conv.ID)

	if w := getEvents(t, s, conv.ID); strings.Contains(w.Body.String(), "chat-done") {
		t.Errorf("a running turn must not be announced as done:\n%s", w.Body)
	}
}

func TestRepoDeleteRemovesConversations(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, "hello"); err != nil {
		t.Fatal(err)
	}

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/delete", repo.ID), url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete status = %d, want 303; body=%s", w.Code, w.Body)
	}
	var convN, msgN int64
	s.DB.Model(&db.Conversation{}).Count(&convN)
	s.DB.Model(&db.ChatMessage{}).Count(&msgN)
	if convN != 0 || msgN != 0 {
		t.Errorf("after repo delete: %d conversations, %d messages, want 0/0", convN, msgN)
	}
}

func TestConversationDelete(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddChatMessage(s.DB, conv.ID, db.ChatRoleUser, "hello"); err != nil {
		t.Fatal(err)
	}

	w := postForm(t, s, fmt.Sprintf("/conversations/%d/delete", conv.ID), url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	if got, want := w.Header().Get("Location"), fmt.Sprintf("/repositories/%d", repo.ID); got != want {
		t.Errorf("redirected to %q, want %q", got, want)
	}
	var convN, msgN int64
	s.DB.Model(&db.Conversation{}).Count(&convN)
	s.DB.Model(&db.ChatMessage{}).Count(&msgN)
	if convN != 0 || msgN != 0 {
		t.Errorf("after delete: %d conversations, %d messages, want 0/0", convN, msgN)
	}
}

func TestConversationDeleteRefusedWhileTurnRuns(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hello")
	if err != nil {
		t.Fatal(err)
	}
	s.beginChatTurn(conv.ID)
	defer s.endChatTurn(conv.ID)

	w := postForm(t, s, fmt.Sprintf("/conversations/%d/delete", conv.ID), url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (busy redirect); body=%s", w.Code, w.Body)
	}
	if _, err := db.LoadConversation(s.DB, conv.ID); err != nil {
		t.Errorf("conversation must survive a delete refused mid-turn: %v", err)
	}
}

func TestConversationDeleteNotFound(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	if w := postForm(t, s, "/conversations/9999/delete", url.Values{}); w.Code != http.StatusNotFound {
		t.Errorf("missing conversation: status = %d, want 404", w.Code)
	}
}

func TestChatTurnSlotsHalvesQueueConcurrency(t *testing.T) {
	if got := chatTurnSlots(nil); got != 1 {
		t.Errorf("without a queue: %d slots, want 1", got)
	}
	s, done := newTestServer(t)
	defer done()
	for _, tc := range []struct{ concurrency, want int }{{1, 1}, {2, 1}, {4, 2}, {7, 3}} {
		s.Queue.Reconfigure(tc.concurrency)
		if got := chatTurnSlots(s.Queue); got != tc.want {
			t.Errorf("concurrency %d: %d slots, want %d", tc.concurrency, got, tc.want)
		}
	}
}

func TestBrokerConversationScope(t *testing.T) {
	b := NewBroker()
	c := b.Subscribe(0, 0, 1) // subscribe to conversation 1 only

	b.Publish(Event{Name: "chat-activity", Data: "for conv 1", ConvID: 1})
	select {
	case e := <-c.ch:
		if e.ConvID != 1 {
			t.Errorf("received event for conv %d", e.ConvID)
		}
	default:
		t.Fatal("expected the conv-1 event to be delivered")
	}

	b.Publish(Event{Name: "chat-activity", Data: "for conv 2", ConvID: 2})
	b.Publish(Event{Name: "scan-log", Data: "a scan", ScanID: 5})
	select {
	case e := <-c.ch:
		t.Errorf("conv-1 subscriber must not receive %+v", e)
	default:
	}
}

func TestRunChatTurnKeepsPartialAnswerOnFailure(t *testing.T) {
	s, done, stub := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	conv, err := db.CreateConversation(s.DB, repo.ID, nil, "m", "hi")
	if err != nil {
		t.Fatal(err)
	}
	// A turn that hit the turn cap after answering: replacing the answer with
	// the failure text loses work the analyst already paid for.
	stub.partial = "The check happens in auth.go."
	stub.err = fmt.Errorf("hit max turns")

	s.beginChatTurn(conv.ID)
	s.runChatTurn(conv.ID, "hi")

	loaded, _ := db.LoadConversation(s.DB, conv.ID)
	if len(loaded.Messages) != 1 {
		t.Fatalf("got %d messages, want one assistant reply", len(loaded.Messages))
	}
	body := loaded.Messages[0].Content
	if !strings.Contains(body, "The check happens in auth.go.") {
		t.Errorf("partial answer discarded: %q", body)
	}
	if !strings.Contains(body, "hit max turns") {
		t.Errorf("failure not surfaced next to the partial answer: %q", body)
	}
}

func TestStartConversationDropsOrphanOnMessageFailure(t *testing.T) {
	s, done, _ := chatServer(t)
	defer done()
	repo := seedRepo(t, s)
	// The conversation row commits before its first message; a failure there
	// must not leave a titled, message-less chat in the panel.
	if err := s.DB.Migrator().DropTable(&db.ChatMessage{}); err != nil {
		t.Fatal(err)
	}
	// newTestServer opens `file::memory:?cache=shared`, one database for the
	// whole process: leaving the table dropped would break any test that still
	// holds a connection to it.
	t.Cleanup(func() { _ = s.DB.AutoMigrate(&db.ChatMessage{}) })

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/conversations", repo.ID),
		url.Values{"message": {"How does auth work?"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 back to the repo; body=%s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "no such table") {
		t.Errorf("database error leaked to the page: %s", w.Body)
	}
	var n int64
	s.DB.Model(&db.Conversation{}).Count(&n)
	if n != 0 {
		t.Errorf("orphan conversation left behind: %d rows", n)
	}
}
