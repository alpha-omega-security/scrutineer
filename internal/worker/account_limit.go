package worker

import (
	"strings"
	"time"
)

// AccountPausePrefix is the stable leading sentence shared by every
// account-pause message: the scan that hit the wall (AccountError) and the
// scans paused behind it (accountPauseReason). The scans page matches on it
// (web.scanListStats) to surface them together in the account banner, so these
// strings and that query share this prefix. Keep the heading in
// web/templates/jobs.html in sync.
const AccountPausePrefix = "Model API account paused."

// legacyAccountPausePrefix is the pre-rename value of AccountPausePrefix.
// migrateLegacyState rewrites it to the current value in scans.error at
// startup so the LIKE queries in worker.go and web/scans.go stay
// single-pattern. Remove once no deployment can have pre-rename paused
// rows (one release after this change ships).
const legacyAccountPausePrefix = "Claude account access paused."

// AccountError is returned for account-level failures from the active
// harness's model provider. The worker pauses the batch instead of
// failing every scan; Detail preserves the provider's text.
type AccountError struct {
	Detail string
	// ResetAt is the reported recovery time for transient limits. Nil means
	// manual resume.
	ResetAt *time.Time
}

func (e *AccountError) Error() string {
	const base = AccountPausePrefix + " This scan and queued scans were paused; " +
		"resume once the account recovers."
	if e.Detail == "" {
		return base
	}
	return base + " Provider reported: " + e.Detail
}

// transientLimitPhrases mark limits that can auto-resume after reset.
var transientLimitPhrases = []string{
	"usage limit",
	"session limit",
	"plan limit",
	"rate limit",
	"rate_limit",
	"too many requests",
	"quota exceeded",
	"credit balance",
	"429",
}

// accessRevokedPhrases mark account problems that need operator action, not a
// timed resume. Keep these close to Claude Code's auth-denied wording.
var accessRevokedPhrases = []string{
	"disabled claude subscription access",
	"use an anthropic api key instead",
	"ask your admin to enable access",
}

// matchAccountPhrase returns the trimmed s when its lowercase form contains
// any phrase from any of the given lists, and "" otherwise. It is the shared
// core of every Harness.AccountErrorText: the caller only consults it after
// the harness exited non-zero, so a stray phrase in normal scan output never
// triggers.
func matchAccountPhrase(s string, lists ...[]string) string {
	text := strings.TrimSpace(s)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	for _, list := range lists {
		for _, phrase := range list {
			if strings.Contains(lower, phrase) {
				return text
			}
		}
	}
	return ""
}

// claudeAccountErrorText returns s when it looks like an account-level message
// from claude-code -- a usage/plan/rate limit, or access being disabled or
// revoked -- and "" otherwise.
func claudeAccountErrorText(s string) string {
	return matchAccountPhrase(s, transientLimitPhrases, accessRevokedPhrases)
}

// accountErrorAccessRevoked reports whether s mentions account access being
// disabled or revoked -- a permanent problem that must never drive an automatic
// resume, regardless of any transient wording elsewhere in the run.
func accountErrorAccessRevoked(s string) bool {
	lower := strings.ToLower(s)
	for _, phrase := range accessRevokedPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// accountErrorResumable returns false for access/admin errors even when the
// message also mentions a limit.
func accountErrorResumable(s string) bool {
	if accountErrorAccessRevoked(s) {
		return false
	}
	lower := strings.ToLower(s)
	for _, phrase := range transientLimitPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// preferAccountErrText picks which account-error message a run should keep as it
// streams lines: the first account-error line seen, except that a later
// access-revoked line overrides an earlier transient one. This keeps a
// permanently revoked account from being auto-resumed just because a transient
// line was printed first. candidate is claudeAccountErrorText(line) ("" for a
// non-account line), so this can be folded over every emitted line.
func preferAccountErrText(current, candidate string) string {
	switch {
	case candidate == "":
		return current
	case current == "":
		return candidate
	case accountErrorAccessRevoked(candidate) && !accountErrorAccessRevoked(current):
		return candidate
	default:
		return current
	}
}

func preferRateLimitReset(current, candidate *RateLimitInfo) *RateLimitInfo {
	if candidate == nil || !candidate.Rejected() || candidate.ResetTime() == nil {
		return current
	}
	if current == nil {
		return candidate
	}
	curReset := current.ResetTime()
	candReset := candidate.ResetTime()
	if curReset == nil || candReset.After(*curReset) {
		return candidate
	}
	return current
}

// resumableReset returns a captured reset only for transient account limits.
func resumableReset(errText string, rl *RateLimitInfo) *time.Time {
	if !accountErrorResumable(errText) || rl == nil || !rl.Rejected() {
		return nil
	}
	return rl.ResetTime()
}
