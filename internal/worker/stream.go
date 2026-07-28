package worker

import "github.com/alpha-omega-security/harness"

// The event vocabulary and stream parsing live in
// github.com/alpha-omega-security/harness. These aliases keep every existing
// unqualified reference in this package (and every worker.Event / worker.Kind*
// reference elsewhere in scrutineer) working without a package-rename churn.

type (
	Event         = harness.Event
	Usage         = harness.Usage
	RateLimitInfo = harness.RateLimitInfo
)

const (
	KindThinking  = harness.KindThinking
	KindText      = harness.KindText
	KindTool      = harness.KindTool
	KindResult    = harness.KindResult
	KindError     = harness.KindError
	KindSession   = harness.KindSession
	KindRateLimit = harness.KindRateLimit

	// KindEgress is scrutineer's own commentary, not the agent's: the egress
	// sidecar's log lines, forwarded after the harness has already exited.
	// Distinct from KindText so a consumer reading the agent's last words
	// (the chat runner) cannot mistake them for the model speaking.
	KindEgress = "egress"
)

func FormatEvent(e Event) string { return harness.FormatEvent(e) }
