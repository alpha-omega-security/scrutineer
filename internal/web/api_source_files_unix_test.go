//go:build !windows

package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestAPIStreamFindingRejectsFIFOSource(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	s.Worker.DataDir = t.TempDir()
	repo, scan := seedRunningScan(t, s)
	src := filepath.Join(s.Worker.DataDir, fmt.Sprintf("scan-%d", scan.ID), "src")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(src, "pipe.c")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/repositories/%d/findings", repo.ID),
		strings.NewReader(`{"title":"Unsafe parser","severity":"High","location":"pipe.c:1","trace":"User input reaches exec via handler.Run without quoting."}`))
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() {
		s.Handler().ServeHTTP(w, r)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		fd, err := syscall.Open(pipe, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			<-finished
			_ = syscall.Close(fd)
		}
		t.Fatal("streamed finding blocked on a FIFO")
	}
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var finding db.Finding
	if err := s.DB.Where("scan_id = ?", scan.ID).First(&finding).Error; err != nil {
		t.Fatal(err)
	}
	if finding.VID != "" || finding.Snippet != "" {
		t.Fatalf("FIFO produced source evidence: VID %q, snippet %q", finding.VID, finding.Snippet)
	}
}
