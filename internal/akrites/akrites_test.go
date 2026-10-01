package akrites

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func validReport() Report {
	return Report{PURL: "pkg:npm/example-lib@1.0.0", Software: "example-lib", Ecosystem: "npm", RawFormat: "markdown", Raw: "Reviewed vulnerability report"}
}

func TestClientSubmitAndPoll(t *testing.T) {
	for _, header := range []string{"", "Authorization"} {
		t.Run(header, func(t *testing.T) {
			var posts, gets int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "POST /v1/reports":
					posts++
					checkReportRequest(t, r, header)
					w.WriteHeader(http.StatusAccepted)
					_, _ = fmt.Fprint(w, `{"receipt":"SUB-example"}`)
				case "GET /v1/submissions/SUB-example":
					gets++
					if r.Header.Get("Authorization") != "" || r.Header.Get("TAP-SUBMISSION-TOKEN") != "" {
						t.Error("token sent with status GET")
					}
					_, _ = fmt.Fprint(w, `{"receipt":"SUB-example","status":"processing","at":"2026-10-01T12:00:00Z"}`)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()
			client := Client{Config: Config{BaseURL: server.URL, SubmissionToken: "private-token", AuthHeader: header}, HTTPClient: server.Client()}
			receipt, err := client.Submit(context.Background(), validReport())
			if err != nil || receipt != "SUB-example" {
				t.Fatalf("receipt = %q, err = %v", receipt, err)
			}
			status, err := client.Poll(context.Background(), receipt)
			if err != nil || status.Status != "processing" || status.At.IsZero() {
				t.Fatalf("status = %+v, err = %v", status, err)
			}
			if posts != 1 || gets != 1 {
				t.Fatalf("requests: posts=%d gets=%d", posts, gets)
			}
		})
	}
}

func checkReportRequest(t *testing.T, r *http.Request, header string) {
	t.Helper()
	h, token := "TAP-SUBMISSION-TOKEN", "private-token"
	if header == "Authorization" {
		h, token = header, "Bearer "+token
	}
	if r.Header.Get(h) != token || r.Header.Get("Content-Type") != "application/json" {
		t.Error("missing authentication or JSON content type")
	}
	var report Report
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil || report.Software != "example-lib" {
		t.Errorf("report = %+v, err = %v", report, err)
	}
}

func TestClientSubmissionErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		code      int
		body      string
		ambiguous bool
		delay     time.Duration
	}{
		{"validation", 400, `{"error":"report.software: private report text"}`, false, 0},
		{"auth", 403, "<html>private-token</html>", false, 0},
		{"rate limit", 429, "", false, time.Hour},
		{"unavailable", 503, "", false, 0},
		{"server error", 500, "", true, 0},
		{"missing receipt", 202, `{}`, true, 0},
		{"unsafe receipt", 202, `{"receipt":"../../elsewhere"}`, true, 0},
		{"truncated JSON", 202, `{"receipt":`, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(tc.code)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			client := Client{Config: Config{BaseURL: server.URL, SubmissionToken: "private-token"}, HTTPClient: server.Client()}
			_, err := client.Submit(context.Background(), validReport())
			var response *ResponseError
			if !errors.As(err, &response) || response.Ambiguous != tc.ambiguous || response.RetryAfter != tc.delay {
				t.Fatalf("response = %#v, err = %v", response, err)
			}
			if requests != 1 || strings.Contains(err.Error(), "private") {
				t.Fatalf("requests = %d, err = %v", requests, err)
			}
		})
	}
}

func TestClientRejectsRedirectAndUntrustedTLS(t *testing.T) {
	var redirected int
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++ }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := Client{Config: Config{BaseURL: server.URL, SubmissionToken: "secret"}, HTTPClient: server.Client()}
	if _, err := client.Submit(context.Background(), validReport()); err == nil {
		t.Fatal("accepted redirect")
	}
	if redirected != 0 {
		t.Fatal("followed redirect")
	}
	client.HTTPClient = nil
	if _, err := client.Submit(context.Background(), validReport()); err == nil {
		t.Fatal("accepted untrusted TLS certificate")
	}
}

func TestReportValidation(t *testing.T) {
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Software = "" },
		func(r *Report) { r.PURL = "" },
		func(r *Report) { r.PURL = "https://example.com" },
		func(r *Report) { r.Software = strings.Repeat("é", 129) },
		func(r *Report) { r.CodePath = "file\npath" },
		func(r *Report) { r.Raw = string([]byte{0xff}) },
		func(r *Report) { r.Raw = strings.Repeat("<", MaxBodySize/2) },
		func(r *Report) { r.Versions = make([]string, 65) },
		func(r *Report) { r.Versions = []string{strings.Repeat("a", 65)} },
		func(r *Report) { r.PackageRepoURL = "file:///private" },
		func(r *Report) { r.Notify = "invalid" },
		func(r *Report) { r.DiscoveryMethod = "invalid" },
	} {
		report := validReport()
		mutate(&report)
		if _, err := report.JSON(); err == nil {
			t.Errorf("accepted invalid report: %.100v", report)
		}
	}
	for _, ecosystem := range []string{"Linux", "OSS-Fuzz", "Android", "GitHub Actions", "Hardware"} {
		report := validReport()
		report.PURL, report.Ecosystem = "", ecosystem
		if _, err := report.JSON(); err != nil {
			t.Errorf("%s: %v", ecosystem, err)
		}
	}
}

func TestPollRejectsInvalidResponses(t *testing.T) {
	for _, body := range []string{
		`{"receipt":"SUB-other","status":"done","at":"2026-10-01T12:00:00Z"}`,
		`{"receipt":"SUB-example","status":"unknown","at":"2026-10-01T12:00:00Z"}`,
		`{"receipt":"SUB-example","status":"done"}`, `{}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, body) }))
		client := Client{Config: Config{BaseURL: server.URL}, HTTPClient: server.Client()}
		if _, err := client.Poll(context.Background(), "SUB-example"); err == nil {
			t.Errorf("accepted %s", body)
		}
		server.Close()
	}
}

func TestRetryAfter(t *testing.T) {
	if got := retryAfter("120"); got != 2*time.Minute {
		t.Fatalf("delay = %v", got)
	}
	future := time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
	if got := retryAfter(future); got < 59*time.Minute || got > time.Hour {
		t.Fatalf("date delay = %v", got)
	}
	if got := retryAfter("nonsense"); got != 0 {
		t.Fatalf("invalid delay = %v", got)
	}
}
