package worker

import "strings"

// ClaudeAccountPausePrefix is the stable leading sentence shared by every
// account-pause message: the scan that hit the wall (ClaudeAccountError) and the
// scans paused behind it (accountPauseReason). The scans page matches on it
// (web.scanListStats) to surface them together in the account banner, so these
// strings and that query share this prefix. Keep the heading in
// web/templates/jobs.html in sync.
const ClaudeAccountPausePrefix = "Claude account access paused."

// ClaudeAccountError is returned when claude-code reports an account-level
// problem -- a usage/plan limit, or access being disabled or revoked -- rather
// than a per-scan failure. The worker pauses the scan and the rest of the queue
// instead of failing each one, because retrying cannot succeed until the
// account recovers: a usage limit resets, an admin re-enables access, or the
// operator switches to an Anthropic API key. The claude message is carried in
// Detail so the operator sees the real reason instead of a bare container exit
// status.
type ClaudeAccountError struct {
	Detail string
}

func (e *ClaudeAccountError) Error() string {
	const base = ClaudeAccountPausePrefix + " This scan and the queued batch were held; " +
		"resume once the account recovers."
	if e.Detail == "" {
		return base
	}
	return base + " Claude reported: " + e.Detail
}

// claudeAccountErrorText returns s when it looks like an account-level message
// from claude-code -- a usage/plan/rate limit, or access being disabled or
// revoked -- and "" otherwise. The caller only consults it when the run already
// failed (non-zero exit), so a stray "rate limit" in normal scan output never
// pauses a healthy scan. The access phrases are deliberately specific (verbatim
// fragments of Claude Code's auth-denied message) so a repository's own content
// cannot trip them.
func claudeAccountErrorText(s string) string {
	text := strings.TrimSpace(s)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	for _, phrase := range []string{
		// usage / plan / rate limits (transient: resume after the limit resets)
		"usage limit",
		"session limit",
		"plan limit",
		"rate limit",
		"rate_limit",
		"too many requests",
		"quota exceeded",
		"credit balance",
		"429",
		// access disabled or revoked (account-level: retrying cannot help)
		"disabled claude subscription access",
		"use an anthropic api key instead",
		"ask your admin to enable access",
	} {
		if strings.Contains(lower, phrase) {
			return text
		}
	}
	return ""
}
