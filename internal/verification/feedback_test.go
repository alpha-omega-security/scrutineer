package verification

import (
	"strings"
	"testing"
)

func TestNormalizeFeedback(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		invalid           bool
	}{
		{name: "absent"},
		{name: "blank", input: " \n\t"},
		{name: "trim", input: " check the real parser \n", want: "check the real parser"},
		{name: "boundary", input: strings.Repeat("x", MaxFeedbackBytes), want: strings.Repeat("x", MaxFeedbackBytes)},
		{name: "too long", input: strings.Repeat("x", MaxFeedbackBytes+1), invalid: true},
		{name: "multibyte limit", input: strings.Repeat("\u00e9", MaxFeedbackBytes/2+1), invalid: true},
		{name: "invalid utf8", input: string([]byte{0xff}), invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeFeedback(tc.input)
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatalf("feedback=%q err=%v", got, err)
			}
		})
	}
}
