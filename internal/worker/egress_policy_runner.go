package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"scrutineer/internal/egressgrant"
)

// applyEgressPolicy applies the operator's egress grants for sj's skill to a
// copy of the runner. A skill without a policy gets the runner back untouched.
// Grants need --hardened: without the per-scan --internal network a scan could
// clear its proxy variables and ignore the port gate, so the scan is refused
// rather than run with grants nothing enforces. The returned cleanup must run
// after the scan and emits any denials the host proxy recorded.
func (d ContainerRunner) applyEgressPolicy(sj SkillJob, emit func(Event)) (ContainerRunner, func(), error) {
	noop := func() {}
	grants := d.EgressPolicies[sj.Name]
	if len(grants) == 0 {
		return d, noop, nil
	}
	if !d.Hardened {
		return d, noop, fmt.Errorf("egress policy for skill %q requires --hardened; refusing to run with unenforced grants", sj.Name)
	}
	emit(Event{Kind: KindEgress, Text: fmt.Sprintf("egress-policy: skill=%s grants=%s", sj.Name, egressgrant.Format(grants))})
	if d.usesEgressSidecar() {
		d.Egress.Grants = slices.Clone(grants)
		return d, noop, nil
	}
	if d.ProviderProxy.ContainerHost == "" {
		return d, noop, fmt.Errorf("egress policy for skill %q cannot start a scoped proxy because the container host endpoint is unavailable", sj.Name)
	}
	rec := &lineBuffer{}
	token := NewProxyToken()
	port, closeProxy, err := StartScopedEgressProxy(&EgressProxy{
		Allow:     d.ProviderProxy.Allow,
		Token:     token,
		APIPort:   d.ProviderProxy.APIPort,
		APIHosts:  d.ProviderProxy.APIHosts,
		HostPorts: d.Egress.HostPorts,
		Log:       slog.New(&recordingHandler{inner: forwardHandler(d.ProviderProxy.Log), rec: newWarnHandler(rec)}),
	}, grants...)
	if err != nil {
		return d, noop, fmt.Errorf("start egress policy proxy for skill %q: %w", sj.Name, err)
	}
	d.ProxyURL = ProxyURLForHost(token, d.ProviderProxy.ContainerHost, port)
	return d, func() {
		closeProxy()
		for _, line := range rec.lines() {
			emit(Event{Kind: KindEgress, Text: "egress-proxy: " + line})
		}
	}, nil
}

// lineBuffer is a mutex-guarded sink for the text lines the proxy goroutines
// log. Only the scan goroutine reads it, after the proxy has closed.
type lineBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lineBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lineBuffer) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for line := range strings.SplitSeq(strings.TrimSpace(l.buf.String()), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// forwardHandler returns the handler denials are also forwarded to, or a
// discarding one when the operator logger is unset.
func forwardHandler(log *slog.Logger) slog.Handler {
	if log == nil {
		return slog.NewTextHandler(io.Discard, nil)
	}
	return log.Handler()
}

func newWarnHandler(w *lineBuffer) slog.Handler {
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelWarn})
}

// recordingHandler forwards every record to the operator's logger (when one is
// configured) and also keeps WARN and above so the scan record can show what
// the per-skill proxy denied.
type recordingHandler struct {
	inner slog.Handler
	rec   slog.Handler
}

func (h *recordingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelWarn || h.inner.Enabled(ctx, level)
}

func (h *recordingHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.inner.Enabled(ctx, r.Level) {
		_ = h.inner.Handle(ctx, r.Clone())
	}
	if r.Level >= slog.LevelWarn {
		return h.rec.Handle(ctx, r)
	}
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &recordingHandler{inner: h.inner.WithAttrs(attrs), rec: h.rec.WithAttrs(attrs)}
}

func (h *recordingHandler) WithGroup(name string) slog.Handler {
	return &recordingHandler{inner: h.inner.WithGroup(name), rec: h.rec.WithGroup(name)}
}
