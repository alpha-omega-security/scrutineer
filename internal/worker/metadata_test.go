package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchEcosystemsSetsUserAgent(t *testing.T) {
	var gotUA, gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotURL = r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"full_name":"a/b","owner":"a","description":"d","default_branch":"main","language":"Go","stargazers_count":42,"license":"mit","html_url":"https://h","pushed_at":"2026-01-02T03:04:05Z"}`))
	}))
	defer srv.Close()

	old := ecosystemsLookup
	ecosystemsLookup = srv.URL
	defer func() { ecosystemsLookup = old }()

	er, _, err := fetchEcosystems(context.Background(), "https://github.com/a/b", func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotUA, "scrutineer") || !strings.Contains(gotUA, "@") {
		t.Errorf("user agent = %q", gotUA)
	}
	if gotURL != "https://github.com/a/b" {
		t.Errorf("url param = %q", gotURL)
	}
	if er.Description != "d" || er.DefaultBranch != "main" || er.Language != "Go" {
		t.Errorf("decode: %+v", er)
	}
	if er.Stars != 42 || er.License != "mit" || er.Owner != "a" || er.HTMLURL != "https://h" {
		t.Errorf("decode extras: %+v", er)
	}
	if er.PushedAt == nil || er.PushedAt.Year() != 2026 {
		t.Errorf("pushed_at: %v", er.PushedAt)
	}
}
