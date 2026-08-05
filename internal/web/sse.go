package web

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"scrutineer/internal/db"
)

// Event is one SSE message. Name maps to the htmx sse-swap attribute;
// Data is the HTML fragment (or plain text) to swap in.
type Event struct {
	Name string // e.g. "scan-log", "scan-status"
	Data string
	// Scoping: which scan/repo/conversation this event is for. Clients
	// subscribe by scan, repo, or conversation; the broker filters.
	ScanID uint
	RepoID uint
	ConvID uint
}

const sseBuf = 64

type client struct {
	ch     chan Event
	scanID uint // 0 = all scans
	repoID uint // 0 = all repos
	convID uint // 0 = all conversations
	// names restricts delivery to these event names; nil = every name. A list
	// page only reacts to scan-status, and without this filter it would be sent
	// every log line of every running scan and the whole chat activity stream.
	names map[string]bool
}

// Broker fans SSE events from the worker to connected HTTP clients.
type Broker struct {
	mu      sync.RWMutex
	clients map[*client]struct{}
}

func NewBroker() *Broker {
	return &Broker{clients: make(map[*client]struct{})}
}

func (b *Broker) Subscribe(scanID, repoID, convID uint, names ...string) *client {
	c := &client{
		ch:     make(chan Event, sseBuf),
		scanID: scanID,
		repoID: repoID,
		convID: convID,
	}
	if len(names) > 0 {
		c.names = make(map[string]bool, len(names))
		for _, n := range names {
			c.names[n] = true
		}
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
		if c.names != nil && !c.names[e.Name] {
			continue
		}
		if c.scanID != 0 && c.scanID != e.ScanID {
			continue
		}
		if c.repoID != 0 && c.repoID != e.RepoID {
			continue
		}
		if c.convID != 0 && c.convID != e.ConvID {
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
	convID, _ := strconv.ParseUint(r.URL.Query().Get("conv"), 10, 64)

	var names []string
	for name := range strings.SplitSeq(r.URL.Query().Get("events"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}

	c := s.Broker.Subscribe(uint(scanID), uint(repoID), uint(convID), names...)
	defer s.Broker.Unsubscribe(c)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	// Publish only reaches subscribers that already exist, so a chat turn
	// finishing between the page render and this connection would leave the
	// page spinning on a chat-done that is already gone. Re-check the live
	// state now that we are subscribed: the page reloads and picks up the
	// reply it missed.
	if convID != 0 && !s.chatTurnActive(uint(convID)) {
		writeSSEEvent(w, "chat-done", "")
		flusher.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-c.ch:
			var data string
			// A scan-status with no scan ID comes from a bulk action or an
			// enqueue, which name no row to swap: it carries no payload and
			// only tells the list pages to re-fetch their table.
			switch {
			case e.Name != "scan-status":
				data = html.EscapeString(e.Data)
			case e.ScanID != 0:
				data = s.renderScanStatus(e.ScanID)
			}
			writeSSEEvent(w, e.Name, data)
			flusher.Flush()
		}
	}
}

// publishScanRow announces a change to a scan that open pages already hold a
// row for, so the payload can swap that row in place (and toast it once the scan
// finished). Anything that has no single row to point at goes through
// publishScanList instead.
func (s *Server) publishScanRow(scan *db.Scan) {
	s.Broker.Publish(Event{Name: "scan-status", ScanID: scan.ID, RepoID: scan.RepositoryID})
}

// publishScanList tells the list pages that scan rows changed without naming
// one: a bulk action flips many rows at once, and an enqueue adds a row no open
// page has yet, so there is nothing for an OOB row swap to land on. repoID is 0
// for an instance-wide action, which still reaches the unscoped list
// subscribers and deliberately not the per-repository ones.
func (s *Server) publishScanList(repoID uint) {
	s.Broker.Publish(Event{Name: "scan-status", RepoID: repoID})
}

// renderScanStatus loads a scan and renders the OOB row (plus a toast once it
// finished) pushed to repo_show via the scan-status SSE event.
func (s *Server) renderScanStatus(scanID uint) string {
	var scan db.Scan
	if err := s.DB.Preload("Repository").First(&scan, scanID).Error; err != nil {
		return ""
	}
	var n int64
	s.DB.Model(&db.Finding{}).Where("scan_id = ?", scan.ID).Count(&n)
	scan.FindingsCount = int(n)

	data := map[string]any{"Scan": scan}
	// Only an outcome is worth a toast. A scan reaching `running` pushes a row
	// update like any other status, but announcing every start would spam the
	// toaster, and the category below would paint it as an error.
	if scan.Status.Terminal() {
		cat := successKey
		if scan.Status != db.ScanDone {
			cat = errorKey
		}
		data["Flash"] = Flash{
			Category:    cat,
			Title:       fmt.Sprintf("%s %s", scan.SkillName, scan.Status),
			Description: scan.Repository.Name,
			Href:        fmt.Sprintf("/scans/%d", scan.ID),
			Label:       "View",
		}
	}
	var buf strings.Builder
	if err := s.tmpl.ExecuteTemplate(&buf, "scan-status-sse", data); err != nil {
		s.Log.Error("render scan-status-sse", "scan", scanID, "err", err)
		return ""
	}
	return buf.String()
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
