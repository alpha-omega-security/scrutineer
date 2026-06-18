package worker

import "strings"

// ClaudePlanLimitError is returned when claude-code reports an account or plan
// limit rather than a skill failure. The worker pauses the scan (and the rest
// of the queue) instead of failing it, so the operator resumes the batch once
// the limit resets rather than retrying each scan.
type ClaudePlanLimitError struct {
	Detail string
}

func (e *ClaudePlanLimitError) Error() string {
	if e.Detail == "" {
		return "Claude plan limit reached. Queued scans were paused; resume after your limit resets."
	}
	return "Claude plan limit reached. Queued scans were paused; resume after your limit resets. " + e.Detail
}

func claudePlanLimitText(s string) string {
	text := strings.TrimSpace(s)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	for _, phrase := range []string{
		"usage limit",
		"session limit",
		"plan limit",
		"rate limit",
		"rate_limit",
		"too many requests",
		"quota exceeded",
		"credit balance",
		"429",
	} {
		if strings.Contains(lower, phrase) {
			return text
		}
	}
	return ""
}
