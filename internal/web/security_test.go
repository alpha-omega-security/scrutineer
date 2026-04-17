package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testHost = "127.0.0.1:8080"

func TestSecurityHeadersRejectsBadHost(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(inner)

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "evil.example:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("bad host: got %d, want 403", w.Code)
	}
}

func TestSecurityHeadersAllowsLocalhost(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(inner)

	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("host %q: got %d, want 200", host, w.Code)
		}
	}
}

func TestSecurityHeadersRejectsCrossSitePost(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(inner)

	r := httptest.NewRequest("POST", "/repositories", nil)
	r.Host = testHost
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: got %d, want 403", w.Code)
	}
}

func TestSecurityHeadersAllowsSameOriginPost(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(inner)

	r := httptest.NewRequest("POST", "/repositories", nil)
	r.Host = testHost
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("same-origin POST: got %d, want 200", w.Code)
	}
}
