package verification

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const MaxFeedbackBytes = 4000

// NormalizeFeedback bounds operator input before it is persisted or staged.
func NormalizeFeedback(raw string) (string, error) {
	if len(raw) > MaxFeedbackBytes || !utf8.ValidString(raw) {
		return "", fmt.Errorf("verification feedback must be valid UTF-8 and at most %d bytes", MaxFeedbackBytes)
	}
	return strings.TrimSpace(raw), nil
}
