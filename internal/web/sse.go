package web

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Event is one SSE message. Name maps to the htmx sse-swap attribute;
// Data is the HTML fragment (or plain text) to swap in.
type Event struct {
	Name string // e.g. "scan-log", "scan-status"
	Data string
	// Scoping: which scan/repo this event is for. Clients subscribe by
	// scan or repo; the broker filters.
	ScanID uint
	RepoID uint
}

const sseBuf = 64

type client struct {
	ch     chan Event
	scanID uint // 0 = all scans
	repoID uint // 0 = all repos
}

// Broker fans SSE events from the worker to connected HTTP clients.
type Broker struct {
	mu      sync.RWMutex
	clients map[*client]struct{}
}

func NewBroker() *Broker {
	return &Broker{clients: make(map[*client]struct{})}
}

func (b *Broker) Subscribe(scanID, repoID uint) *client {
	c := &client{
		ch:     make(chan Event, sseBuf),
		scanID: scanID,
		repoID: repoID,
	}
	b.mu.Lock()
	b.clients[c] = struct{}{}
	b.mu.Unlock()
	return c
}

func (b *Broker) Unsubscribe(c *client) {
	b.mu.Lock()
	delete(b.clients, c)
	b.mu.Unlock()
}

// Publish sends an event to all matching clients. Non-blocking: slow
// clients get their channel drained.
func (b *Broker) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for c := range b.clients {
		if c.scanID != 0 && c.scanID != e.ScanID {
			continue
		}
		if c.repoID != 0 && c.repoID != e.RepoID {
			continue
		}
		select {
		case c.ch <- e:
		default:
			// Drop if client is backed up
		}
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	scanID, _ := strconv.ParseUint(r.URL.Query().Get("scan"), 10, 64)
	repoID, _ := strconv.ParseUint(r.URL.Query().Get("repo"), 10, 64)

	c := s.Broker.Subscribe(uint(scanID), uint(repoID))
	defer s.Broker.Unsubscribe(c)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-c.ch:
			writeSSEEvent(w, e.Name, e.Data)
			flusher.Flush()
		}
	}
}

// writeSSEEvent emits one SSE event per the spec. Embedded newlines in data
// are expressed as multiple `data:` lines so the browser's EventSource parser
// reconstructs the original text; a single `data: %s` pattern silently drops
// every line after the first newline.
func writeSSEEvent(w io.Writer, name, data string) {
	_, _ = io.WriteString(w, "event: ")
	_, _ = io.WriteString(w, name)
	_, _ = io.WriteString(w, "\n")
	for line := range strings.SplitSeq(data, "\n") {
		_, _ = io.WriteString(w, "data: ")
		_, _ = io.WriteString(w, line)
		_, _ = io.WriteString(w, "\n")
	}
	_, _ = io.WriteString(w, "\n")
}
