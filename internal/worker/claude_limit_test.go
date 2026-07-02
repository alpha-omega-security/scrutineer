package worker

import "testing"

func TestAccountErrorResumable(t *testing.T) {
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"usage limit", "Claude usage limit reached", true},
		{"429", "error 429 too many requests", true},
		{"credit balance", "your credit balance is too low", true},
		{"access disabled", "This organization has disabled Claude subscription access", false},
		{"use api key", "Please use an Anthropic API key instead", false},
		{"admin enable", "ask your admin to enable access for your account", false},
		{"limit wording but access-revoked wins", "rate limit; use an Anthropic API key instead", false},
		{"unrelated", "some other failure", false},
	}
	for _, tc := range cases {
		if got := accountErrorResumable(tc.text); got != tc.want {
			t.Errorf("%s: accountErrorResumable(%q) = %v, want %v", tc.name, tc.text, got, tc.want)
		}
	}
}

func TestPreferAccountErrText(t *testing.T) {
	transient := "Claude usage limit reached"
	access := "ask your admin to enable access"

	// First account-error line is kept when nothing overrides it.
	if got := preferAccountErrText("", transient); got != transient {
		t.Errorf("first line = %q, want %q", got, transient)
	}
	// Non-account lines (candidate "") never change the capture.
	if got := preferAccountErrText(transient, ""); got != transient {
		t.Errorf("empty candidate changed capture to %q", got)
	}
	// A later access-revoked line overrides an earlier transient one.
	if got := preferAccountErrText(transient, access); got != access {
		t.Errorf("access line did not override transient: %q", got)
	}
	// The reverse does not: once access-revoked, a later transient line loses.
	if got := preferAccountErrText(access, transient); got != access {
		t.Errorf("transient line overrode access: %q", got)
	}
	// Fold over a run that prints transient then access: not resumable.
	got := ""
	for _, line := range []string{"working", transient, "more output", access} {
		got = preferAccountErrText(got, claudeAccountErrorText(line))
	}
	if accountErrorResumable(got) {
		t.Errorf("run ending access-revoked classified resumable via %q", got)
	}
}

func TestResumableReset(t *testing.T) {
	rl := &RateLimitInfo{Type: "five_hour", ResetsAt: 1782990000}
	// Transient limit -> the captured reset flows through.
	if got := resumableReset("usage limit reached", rl); got == nil || got.Unix() != 1782990000 {
		t.Errorf("transient reset = %v, want captured reset", got)
	}
	// Permanent access error -> nil even with a captured event (no auto-resume).
	if got := resumableReset("ask your admin to enable access", rl); got != nil {
		t.Errorf("access-revoked reset = %v, want nil", got)
	}
	// No captured event -> nil.
	if got := resumableReset("usage limit reached", nil); got != nil {
		t.Errorf("nil rate-limit reset = %v, want nil", got)
	}
}
