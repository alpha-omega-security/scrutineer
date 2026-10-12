package web

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// disclosureRequest encodes a payload exactly as it is sent, for the
// submission record.
func disclosureRequest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

// disclosureResendError reports whether a finding already sent on channel
// needs the analyst to confirm sending again. More than one submission per
// channel is allowed, but only deliberately.
func disclosureResendError(r *http.Request, sentBefore bool, recipient string) error {
	if !sentBefore || r.FormValue("resend") == "yes" {
		return nil
	}
	return fmt.Errorf("this finding was already submitted to %s; confirm sending another submission", recipient)
}
