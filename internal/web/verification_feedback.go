package web

import (
	"fmt"
	"net/http"

	"scrutineer/internal/verification"
)

const verificationFormMaxBytes = 32 << 10

func parseVerificationFeedback(w http.ResponseWriter, r *http.Request) bool {
	// Allow URL-encoding overhead while still bounding the entire form body.
	r.Body = http.MaxBytesReader(w, r.Body, verificationFormMaxBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid verification form (maximum 32 KiB)", http.StatusBadRequest)
		return false
	}
	feedback, err := verification.NormalizeFeedback(r.PostForm.Get("feedback"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	r.PostForm.Set("feedback", feedback)
	return true
}

func normalizeVerificationOpts(opts *ScanOpts, skill string) error {
	feedback, err := verification.NormalizeFeedback(opts.VerificationFeedback)
	if err != nil {
		return err
	}
	if feedback != "" && (skill != verifySkillName || opts.FindingID == nil) {
		return fmt.Errorf("verification feedback requires a finding-scoped verify scan")
	}
	opts.VerificationFeedback = feedback
	return nil
}
