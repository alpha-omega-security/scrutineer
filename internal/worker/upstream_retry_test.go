package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveRemoteHeadRetriesTransientFailure(t *testing.T) {
	calls := 0
	retry := branchPickerRetry(fastRetry())
	retry.run = func(context.Context, string, []string, ...string) (string, error) {
		calls++
		if calls == 1 {
			return "fatal: unable to access remote: Connection reset by peer", errGitExit
		}
		return "deadbeef\tHEAD\n", nil
	}

	got, err := resolveRemoteHead(context.Background(), retry, "https://example.invalid/repo")
	if err != nil {
		t.Fatalf("resolveRemoteHead: %v", err)
	}
	if got != "deadbeef" || calls != 2 {
		t.Fatalf("HEAD = %q after %d calls, want deadbeef after 2", got, calls)
	}
}

func TestSyncUpstreamRetriesRemoteCloneAndFetch(t *testing.T) {
	for _, failOperation := range []string{"clone", "fetch"} {
		t.Run(failOperation, func(t *testing.T) {
			git := newUpstreamScript()
			git.failOperation = failOperation
			retry := fastRetry()
			retry.run = git.run
			worker := &Worker{DataDir: t.TempDir()}

			if err := worker.syncUpstream(context.Background(), retry, git.repoURL, git.upstreamURL); err != nil {
				t.Fatalf("syncUpstream: %v", err)
			}
			if failOperation == "clone" && (git.cloneCalls != 2 || !git.cloneResetObserved) {
				t.Fatalf("clone calls = %d, reset observed = %v; want 2 and true", git.cloneCalls, git.cloneResetObserved)
			}
			if failOperation == "fetch" && git.fetchCalls != 2 {
				t.Fatalf("fetch calls = %d, want 2", git.fetchCalls)
			}
			if git.pushCalls != 1 || git.remoteSHA != git.desiredSHA {
				t.Fatalf("push calls = %d, remote SHA = %q; want 1 and %q", git.pushCalls, git.remoteSHA, git.desiredSHA)
			}
		})
	}
}

func TestSyncUpstreamCancelledCloneCleansMirrorForNextInvocation(t *testing.T) {
	git := newUpstreamScript()
	git.failOperation = "clone-cancel"
	ctx, cancel := context.WithCancel(context.Background())
	git.cancel = cancel
	retry := fastRetry()
	retry.run = git.run
	worker := &Worker{DataDir: t.TempDir()}

	err := worker.syncUpstream(ctx, retry, git.repoURL, git.upstreamURL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("syncUpstream error = %v, want context.Canceled", err)
	}
	mirror := filepath.Join(RepoCacheRoot(worker.DataDir, git.repoURL), "upstream-sync.git")
	if _, err := os.Stat(mirror); !os.IsNotExist(err) {
		t.Fatalf("cancelled clone left mirror behind: %v", err)
	}

	fresh := newUpstreamScript()
	freshRetry := fastRetry()
	freshRetry.run = fresh.run
	if err := worker.syncUpstream(context.Background(), freshRetry, fresh.repoURL, fresh.upstreamURL); err != nil {
		t.Fatalf("fresh sync after cancellation: %v", err)
	}
	if fresh.cloneCalls != 1 || fresh.remoteSHA != fresh.desiredSHA {
		t.Fatalf("fresh sync cloned %d times and left SHA %q, want 1 clone and %q",
			fresh.cloneCalls, fresh.remoteSHA, fresh.desiredSHA)
	}
}

func TestSyncUpstreamReconcilesAmbiguousPush(t *testing.T) {
	for _, mode := range []string{"landed", "missed", "confirmation-error"} {
		t.Run(mode, func(t *testing.T) {
			git := newUpstreamScript()
			git.pushMode = mode
			retry := fastRetry()
			retry.run = git.run
			worker := &Worker{DataDir: t.TempDir()}

			if err := worker.syncUpstream(context.Background(), retry, git.repoURL, git.upstreamURL); err != nil {
				t.Fatalf("syncUpstream: %v", err)
			}
			wantPushes := 1
			if mode != "landed" {
				wantPushes = 2
			}
			if git.pushCalls != wantPushes {
				t.Fatalf("push calls = %d, want %d", git.pushCalls, wantPushes)
			}
			if git.confirmCalls != 1 {
				t.Fatalf("confirmation calls = %d, want 1", git.confirmCalls)
			}
			if git.remoteSHA != git.desiredSHA {
				t.Fatalf("remote SHA = %q, want %q", git.remoteSHA, git.desiredSHA)
			}
		})
	}
}

type upstreamScript struct {
	repoURL            string
	upstreamURL        string
	repoSHA            string
	upstreamSHA        string
	desiredSHA         string
	remoteSHA          string
	failOperation      string
	pushMode           string
	cloneCalls         int
	fetchCalls         int
	pushCalls          int
	confirmCalls       int
	cloneResetObserved bool
	cancel             context.CancelFunc
}

func newUpstreamScript() *upstreamScript {
	g := &upstreamScript{}
	g.defaults()
	return g
}

func (g *upstreamScript) defaults() {
	if g.repoURL == "" {
		g.repoURL = "https://example.invalid/staging"
	}
	if g.upstreamURL == "" {
		g.upstreamURL = "https://example.invalid/upstream"
	}
	if g.repoSHA == "" {
		g.repoSHA = "1111111111111111111111111111111111111111"
	}
	if g.upstreamSHA == "" {
		g.upstreamSHA = "2222222222222222222222222222222222222222"
	}
	if g.desiredSHA == "" {
		g.desiredSHA = g.upstreamSHA
	}
	if g.remoteSHA == "" {
		g.remoteSHA = g.repoSHA
	}
}

func (g *upstreamScript) run(_ context.Context, _ string, _ []string, args ...string) (string, error) {
	g.defaults()
	if len(args) == 0 {
		return "", errors.New("missing git command")
	}
	switch args[0] {
	case "ls-remote":
		return g.lsRemote(args)
	case "clone":
		return g.clone(args)
	case "symbolic-ref":
		return "main\n", nil
	case "fetch":
		return g.fetch()
	case "rev-parse":
		return g.desiredSHA + "\n", nil
	case "push":
		return g.push()
	}
	return "", errors.New("unexpected git command: " + strings.Join(args, " "))
}

// lsRemote answers the HEAD lookups and the reconciliation --refs query, which
// pushMode "confirmation-error" scripts to fail once.
func (g *upstreamScript) lsRemote(args []string) (string, error) {
	if len(args) > 1 && args[1] == "--refs" {
		g.confirmCalls++
		if g.pushMode == "confirmation-error" && g.confirmCalls == 1 {
			return "fatal: unable to access remote: Connection reset by peer", errGitExit
		}
		return g.remoteSHA + "\t" + args[len(args)-1] + "\n", nil
	}
	switch args[len(args)-2] {
	case g.repoURL:
		return g.remoteSHA + "\tHEAD\n", nil
	case g.upstreamURL:
		return g.upstreamSHA + "\tHEAD\n", nil
	}
	return "", errors.New("unexpected git command: " + strings.Join(args, " "))
}

// clone leaves a partial destination and fails once when failOperation is
// "clone", so the retry can prove it cleared the target first.
func (g *upstreamScript) clone(args []string) (string, error) {
	g.cloneCalls++
	dst := args[len(args)-1]
	partial := filepath.Join(dst, "partial")
	if (g.failOperation == "clone" || g.failOperation == "clone-cancel") && g.cloneCalls == 1 {
		if err := os.MkdirAll(dst, dirPerm); err != nil {
			return "", err
		}
		if err := os.WriteFile(partial, []byte("partial clone"), 0o644); err != nil {
			return "", err
		}
		if g.cancel != nil {
			g.cancel()
		}
		return "fatal: the remote end hung up unexpectedly", errGitExit
	}
	if _, err := os.Stat(partial); os.IsNotExist(err) {
		g.cloneResetObserved = true
	}
	return "", os.MkdirAll(dst, dirPerm)
}

// fetch fails once when failOperation is "fetch".
func (g *upstreamScript) fetch() (string, error) {
	g.fetchCalls++
	if g.failOperation == "fetch" && g.fetchCalls == 1 {
		return "fatal: unable to access remote: Connection reset by peer", errGitExit
	}
	return "", nil
}

// push fails its first attempt whenever pushMode is set, recording the
// destination SHA up front only when the ambiguous failure "landed".
func (g *upstreamScript) push() (string, error) {
	g.pushCalls++
	if g.pushCalls == 1 && g.pushMode != "" {
		if g.pushMode == "landed" {
			g.remoteSHA = g.desiredSHA
		}
		return "fatal: the remote end hung up unexpectedly", errGitExit
	}
	g.remoteSHA = g.desiredSHA
	return "", nil
}
