package vince

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func validReport() Report {
	return Report{
		ContactName:              "Alice",
		ContactOrganization:      "Example Security",
		ContactEmail:             "alice@example.com",
		ContactPhone:             "+44 20 7946 0958",
		ShareRelease:             AnswerNo,
		CreditRelease:            AnswerYes,
		CoordinationStatus:       []string{"3", "4"},
		CommunicationAttempt:     AnswerYes,
		VendorName:               "Acme",
		MultipleVendors:          AnswerNo,
		ProductName:              "widget",
		ProductVersion:           "< 2.0",
		ICSImpact:                AnswerNo,
		AIMLSystem:               AnswerNo,
		VulnerabilityDescription: "A vulnerability.",
		VulnerabilityExploit:     "Send crafted input.",
		VulnerabilityImpact:      "Code execution.",
		VulnerabilityDiscovery:   "AI-assisted analysis followed by analyst review.",
		VulnerabilityPublic:      AnswerNo,
		VulnerabilityExploited:   AnswerNo,
		VulnerabilityDisclose:    AnswerYes,
		CISACoordination:         AnswerNo,
	}
}

func TestClientSubmitMultipart(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assertVINCERequest(t, r)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"vrf_id": "VRF#26-07-ABCDE"})
	}))
	defer server.Close()

	client := Client{
		Config: Config{BaseURL: server.URL, APIKey: "test-key"},
	}
	got, err := client.Submit(context.Background(), validReport(), &Attachment{
		Name: "bundle.tar.gz", ContentType: "application/gzip", Data: []byte("bundle bytes"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "VRF#26-07-ABCDE" {
		t.Errorf("VRF ID = %q", got)
	}
	if requests.Load() != 1 {
		t.Errorf("requests = %d, want 1", requests.Load())
	}
}

type multipartSubmission struct {
	fields         map[string][]string
	attachment     []byte
	attachmentName string
	attachmentType string
}

func assertVINCERequest(t *testing.T, r *http.Request) {
	t.Helper()
	if r.URL.Path != "/vince/comm/api/vulreport/" {
		t.Errorf("path = %q", r.URL.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Token test-key" {
		t.Errorf("Authorization = %q", got)
	}
	submission := readMultipartSubmission(t, r)
	for _, name := range []string{
		"contact_name", "contact_org", "contact_email", "reporter_pgp", "contact_phone",
		"share_release", "credit_release", "coord_status", "comm_attempt",
		"why_no_attempt", "please_explain", "vendor_name", "multiplevendors",
		"other_vendors", "first_contact", "vendor_communication", "product_name",
		"product_version", "ics_impact", "ai_ml_system", "vul_description",
		"vul_exploit", "vul_impact", "vul_discovery", "vul_public",
		"public_references", "vul_exploited", "exploit_references",
		"vul_disclose", "disclosure_plans", "tracking", "comments", "cisa_please",
	} {
		if _, ok := submission.fields[name]; !ok {
			t.Errorf("multipart field %q missing", name)
		}
	}
	if got := submission.fields["coord_status"]; len(got) != 2 || got[0] != "3" || got[1] != "4" {
		t.Errorf("coord_status = %#v", got)
	}
	if got := submission.fields["share_release"]; len(got) != 1 || got[0] != "False" {
		t.Errorf("share_release = %#v", got)
	}
	if submission.attachmentName != "bundle.tar.gz" || submission.attachmentType != "application/gzip" ||
		string(submission.attachment) != "bundle bytes" {
		t.Errorf(
			"attachment name=%q type=%q body=%q",
			submission.attachmentName,
			submission.attachmentType,
			submission.attachment,
		)
	}
}

func readMultipartSubmission(t *testing.T, r *http.Request) multipartSubmission {
	t.Helper()
	reader, err := r.MultipartReader()
	if err != nil {
		t.Fatal(err)
	}
	submission := multipartSubmission{fields: map[string][]string{}}
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return submission
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		if part.FormName() == "user_file" {
			submission.attachment = raw
			submission.attachmentName = part.FileName()
			submission.attachmentType = part.Header.Get("Content-Type")
			continue
		}
		submission.fields[part.FormName()] = append(submission.fields[part.FormName()], string(raw))
	}
}

func TestClientSubmitResponseHandling(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantKind  ErrorKind
		wantField string
		wantVRFID string
	}{
		{"created", 201, `{"vrf_id":"VRF#1"}`, "", "", "VRF#1"},
		{"created without id", 201, `{}`, ErrorAmbiguous, "", ""},
		{"field errors", 400, `{"errors":{"product_name":["Too long."]}}`, ErrorValidation, "product_name", ""},
		{"unauthorized", 401, `{}`, ErrorAuth, "", ""},
		{"forbidden", 403, `{}`, ErrorAuth, "", ""},
		{"rate limited", 429, `{}`, ErrorRateLimit, "", ""},
		{"server error", 500, `{}`, ErrorAmbiguous, "", ""},
		{"other response", 404, `{}`, ErrorResponse, "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client := Client{Config: Config{BaseURL: server.URL, APIKey: "key"}}
			got, err := client.Submit(context.Background(), validReport(), nil)
			if test.wantKind == "" {
				if err != nil {
					t.Fatal(err)
				}
				if got != test.wantVRFID {
					t.Errorf("VRF ID = %q, want %q", got, test.wantVRFID)
				}
			} else {
				submitErr, ok := AsSubmitError(err)
				if !ok {
					t.Fatalf("error = %T %v, want SubmitError", err, err)
				}
				if submitErr.Kind != test.wantKind {
					t.Errorf("kind = %q, want %q", submitErr.Kind, test.wantKind)
				}
				if test.wantField != "" && len(submitErr.FieldErrors[test.wantField]) == 0 {
					t.Errorf("field errors = %#v", submitErr.FieldErrors)
				}
			}
			if requests.Load() != 1 {
				t.Errorf("requests = %d, want exactly 1", requests.Load())
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestClientSubmitTransportErrorDoesNotRetry(t *testing.T) {
	var requests atomic.Int32
	client := Client{
		Config: Config{BaseURL: "https://vince.example", APIKey: "key"},
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return nil, errors.New("timeout")
		})},
	}
	_, err := client.Submit(context.Background(), validReport(), nil)
	submitErr, ok := AsSubmitError(err)
	if !ok || submitErr.Kind != ErrorAmbiguous {
		t.Fatalf("error = %#v, want ambiguous SubmitError", err)
	}
	if requests.Load() != 1 {
		t.Errorf("requests = %d, want exactly 1", requests.Load())
	}
}

func TestClientSubmitDoesNotFollowRedirects(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/vince/comm/api/vulreport/" {
			http.Redirect(w, r, "/second-request", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"vrf_id":"VRF#redirected"}`)
	}))
	defer server.Close()

	client := Client{Config: Config{BaseURL: server.URL, APIKey: "key"}}
	_, err := client.Submit(context.Background(), validReport(), nil)
	submitErr, ok := AsSubmitError(err)
	if !ok || submitErr.Kind != ErrorResponse || submitErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("error = %#v, want redirect response error", err)
	}
	if requests.Load() != 1 {
		t.Errorf("requests = %d, want exactly 1", requests.Load())
	}
}

func TestReportValidationRequiresResolvedChoicesAndHonorsLengths(t *testing.T) {
	report := validReport()
	report.ShareRelease = AnswerUnknown
	report.ProductName = strings.Repeat("x", 201)
	report.ContactPhone = "555 ext 9"
	err := report.Validate()
	var validation ValidationErrors
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T %v, want ValidationErrors", err, err)
	}
	for _, field := range []string{"share_release", "product_name", "contact_phone"} {
		if len(validation[field]) == 0 {
			t.Errorf("missing %s error in %#v", field, validation)
		}
	}
}

func TestReportValidationUsesVINCEStorageLimits(t *testing.T) {
	report := validReport()
	report.ContactPhone = strings.Repeat("1", 20)
	report.ExploitReferences = strings.Repeat("x", 1000)
	if err := report.Validate(); err != nil {
		t.Fatalf("values at VINCE storage limits: %v", err)
	}

	report.ContactPhone += "1"
	report.ExploitReferences += "x"
	err := report.Validate()
	var validation ValidationErrors
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T %v, want ValidationErrors", err, err)
	}
	for _, field := range []string{"contact_phone", "exploit_references"} {
		if len(validation[field]) == 0 {
			t.Errorf("missing %s error in %#v", field, validation)
		}
	}
}

func TestClientSubmitAttachmentSizeBoundary(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if err := r.ParseMultipartForm(MaxAttachmentSize + 1024); err != nil {
			t.Errorf("ParseMultipartForm: %v", err)
		}
		file, _, err := r.FormFile("user_file")
		if err != nil {
			t.Errorf("FormFile: %v", err)
		} else {
			defer func() {
				_ = file.Close()
			}()
			n, _ := io.Copy(io.Discard, file)
			if n != MaxAttachmentSize {
				t.Errorf("attachment bytes = %d, want %d", n, MaxAttachmentSize)
			}
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"vrf_id":"VRF#boundary"}`)
	}))
	defer server.Close()
	client := Client{Config: Config{BaseURL: server.URL, APIKey: "key"}}

	if _, err := client.Submit(context.Background(), validReport(), &Attachment{
		Name: "exact.bin", Data: make([]byte, MaxAttachmentSize),
	}); err != nil {
		t.Fatalf("exact boundary: %v", err)
	}
	if _, err := client.Submit(context.Background(), validReport(), &Attachment{
		Name: "too-large.bin", Data: make([]byte, MaxAttachmentSize+1),
	}); err == nil {
		t.Fatal("expected oversized attachment error")
	}
	if requests.Load() != 1 {
		t.Errorf("requests = %d, want 1 (oversized body must not be sent)", requests.Load())
	}
}

func TestConfigURLs(t *testing.T) {
	cfg := Config{}
	if got, _ := cfg.Endpoint(); got != DefaultBaseURL+"/vince/comm/api/vulreport/" {
		t.Errorf("default endpoint = %q", got)
	}
	cfg.BaseURL = "https://vince.example/root/"
	if got, _ := cfg.ReportsURL(); got != "https://vince.example/root/vince/comm/reports/" {
		t.Errorf("reports URL = %q", got)
	}
	cfg.BaseURL = "http://vince.example"
	if _, err := cfg.Endpoint(); err == nil {
		t.Error("non-loopback HTTP base URL accepted")
	}
}
