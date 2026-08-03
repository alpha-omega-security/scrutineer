package worker

import (
	"time"

	"github.com/alpha-omega-security/harness"
)

// AccountPausePrefix is the stable leading sentence shared by every
// account-pause scan.Error value. The web layer's paused-scans query and
// the auto-resume sweep both match `error LIKE AccountPausePrefix+'%'`, so
// this string is a stored-data contract, not just display text.
const AccountPausePrefix = "Model API account paused."

// legacyAccountPausePrefix is the pre-rename value of AccountPausePrefix.
// The startup migration at worker.go rewrites it on paused rows so a
// pre-upgrade pause still matches the current LIKE query.
const legacyAccountPausePrefix = "Claude account access paused."

// AccountError is scrutineer's own error type: its Error() text is stored in
// scan.Error and matched by SQL LIKE, so it cannot be aliased to
// harness.AccountError (whose Error() format differs). The phrase
// classification lives in the harness module.
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

func preferAccountErrText(current, candidate string) string {
	return harness.PreferAccountErrorText(current, candidate)
}

func preferRateLimitReset(current, candidate *RateLimitInfo) *RateLimitInfo {
	return harness.PreferRateLimitReset(current, candidate)
}

func resumableReset(errText string, rl *RateLimitInfo) *time.Time {
	return harness.ResumableReset(errText, rl)
}

func accountErrorResumable(s string) bool { return harness.AccountErrorResumable(s) }
