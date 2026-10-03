package akrites

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// intakeReport mirrors the wire fields of model.Report in akrites-pipeline
// (core/model/report.go). Intake decodes with DisallowUnknownFields, so a field
// Scrutineer sends that is missing here fails every submission.
type intakeReport struct {
	Software       string   `json:"software"`
	Ecosystem      string   `json:"ecosystem,omitempty"`
	Versions       []string `json:"versions,omitempty"`
	CodePath       string   `json:"code_path,omitempty"`
	Purl           string   `json:"purl,omitempty"`
	AffectedSymbol *struct {
		File     string `json:"file,omitempty"`
		Function string `json:"function,omitempty"`
		Line     int    `json:"line,omitempty"`
	} `json:"affected_symbol,omitempty"`
	References         []string       `json:"references,omitempty"`
	UpstreamIDs        []string       `json:"upstream_ids,omitempty"`
	IntroducedCommit   string         `json:"introduced_commit,omitempty"`
	FixedCommit        string         `json:"fixed_commit,omitempty"`
	DiscoveryMethod    string         `json:"discovery_method,omitempty"`
	DiscoveryTooling   string         `json:"discovery_tooling,omitempty"`
	PackageRepoURL     string         `json:"package_repo_url,omitempty"`
	Exploit            string         `json:"exploit,omitempty"`
	ExploitContentType string         `json:"exploit_content_type,omitempty"`
	Raw                string         `json:"raw,omitempty"`
	RawContentType     string         `json:"raw_content_type,omitempty"`
	Email              string         `json:"email,omitempty"`
	Notify             string         `json:"notify,omitempty"`
	Enrichment         map[string]any `json:"enrichment,omitempty"`
}

func jsonNames(v any) []string {
	var names []string
	typ := reflect.TypeOf(v)
	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}

func TestReportFieldsAreIntakeFields(t *testing.T) {
	intake := jsonNames(intakeReport{})
	for _, name := range jsonNames(Report{}) {
		if !slices.Contains(intake, name) {
			t.Errorf("intake does not accept field %q", name)
		}
	}
}

func validReport() Report {
	return Report{PURL: "pkg:npm/example-lib@1.0.0", Software: "example-lib", Ecosystem: "npm", RawContentType: "text/markdown", Raw: "Reviewed vulnerability report"}
}

func TestClientSubmitAndPoll(t *testing.T) {
	for _, header := range []string{"", "TAP-SUBMISSION-TOKEN"} {
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
	h, token := "Authorization", "Bearer private-token"
	if header == "TAP-SUBMISSION-TOKEN" {
		h, token = header, "private-token"
	}
	if r.Header.Get(h) != token || r.Header.Get("Content-Type") != "application/json" {
		t.Error("missing authentication or JSON content type")
	}
	var report intakeReport
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil || report.Software != "example-lib" || report.RawContentType != "text/markdown" {
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
		message   string
	}{
		{"validation", 400, `{"type":"tag:akrites.dev,2026-07:problem/validation","title":"Report failed validation","status":400,"errors":[` +
			`{"code":"unknown_ecosystem","field":"ecosystem","reason":"private report text"},` +
			`{"code":"purl_ecosystem_mismatch","field":"purl","also_field":"ecosystem","reason":"private"},` +
			`{"code":"private code","field":"private<field>","reason":"private"}]}`,
			false, 0, "HTTP 400): ecosystem (unknown_ecosystem), purl and ecosystem (purl_ecosystem_mismatch)"},
		{"too large", 413, `{"type":"tag:akrites.dev,2026-07:problem/validation","status":413,"errors":[{"code":"field_too_large","field":"raw","reason":"private"}]}`,
			false, 0, "HTTP 413): raw (field_too_large)"},
		{"malformed", 400, `{"type":"tag:akrites.dev,2026-07:problem/malformed-json","title":"Malformed JSON","status":400}`, false, 0, "could not parse"},
		{"untyped problem", 400, `{"type":"about:blank","status":400,"detail":"private","errors":[{"code":"missing_field","field":"software"}]}`, false, 0, "rejected the report (HTTP 400)"},
		{"auth", 401, `{"type":"about:blank","title":"Unauthorized","status":401,"detail":"submission token not recognized"}`, false, 0, "HTTP 401"},
		{"firewall", 403, "<html>private-token</html>", false, 0, "firewall"},
		{"rate limit", 429, "", false, time.Hour, ""},
		{"unavailable", 503, "", false, 0, ""},
		{"server error", 500, "", true, 0, ""},
		{"missing receipt", 202, `{}`, true, 0, ""},
		{"unsafe receipt", 202, `{"receipt":"../../elsewhere"}`, true, 0, ""},
		{"truncated JSON", 202, `{"receipt":`, true, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if tc.code >= 400 && strings.HasPrefix(tc.body, "{") {
					w.Header().Set("Content-Type", "application/problem+json")
				}
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
			if requests != 1 || strings.Contains(err.Error(), "private") || !strings.Contains(err.Error(), tc.message) {
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
	versions := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("0.%d.0", i)
		}
		return out
	}
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Software = "" },
		func(r *Report) { r.PURL, r.Ecosystem = "", "" },
		func(r *Report) { r.PURL = "https://example.com" },
		func(r *Report) { r.Software = strings.Repeat("é", 129) },
		func(r *Report) { r.CodePath = "file\npath" },
		func(r *Report) { r.Raw = string([]byte{0xff}) },
		func(r *Report) { r.Raw = strings.Repeat("a", MaxPayloadSize+1) },
		func(r *Report) {
			r.Raw, r.Exploit, r.ExploitContentType = strings.Repeat(`"`, MaxPayloadSize), strings.Repeat(`"`, MaxPayloadSize), "text/plain"
		},
		func(r *Report) { r.RawContentType = "" },
		func(r *Report) { r.RawContentType = "text/plain; charset=utf-8" },
		func(r *Report) { r.Exploit = "Crafted input" },
		func(r *Report) { r.ExploitContentType = "text/plain" },
		func(r *Report) { r.Versions = versions(65) },
		func(r *Report) { r.Versions = versions(64) },
		func(r *Report) { r.Versions = []string{strings.Repeat("a", 65)} },
		func(r *Report) { r.PackageRepoURL = "file:///private" },
		func(r *Report) { r.Notify = "invalid" },
		func(r *Report) { r.Notify = "final" },
		func(r *Report) { r.DiscoveryMethod = "invalid" },
	} {
		report := validReport()
		mutate(&report)
		if _, err := report.JSON(); err == nil {
			t.Errorf("accepted invalid report: %.100v", report)
		}
	}
	for name, mutate := range map[string]func(*Report){
		"ecosystem without purl": func(r *Report) { r.PURL = "" },
		"unescaped HTML":         func(r *Report) { r.Raw = strings.Repeat("<", MaxPayloadSize) },
		"exploit":                func(r *Report) { r.Exploit, r.ExploitContentType = "Crafted input", "text/plain" },
		"purl version listed":    func(r *Report) { r.Versions = append(versions(63), "1.0.0") },
		"notify with email":      func(r *Report) { r.Notify, r.Email = "final", "reporter@example.com" },
	} {
		report := validReport()
		mutate(&report)
		if _, err := report.JSON(); err != nil {
			t.Errorf("%s: %v", name, err)
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
