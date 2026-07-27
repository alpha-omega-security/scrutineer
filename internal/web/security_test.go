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
	h := securityHeaders(false, inner)

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
	h := securityHeaders(false, inner)

	for _, host := range []string{
		"127.0.0.1:8080", "localhost:8080", "[::1]:8080",
		"127.0.0.1", "localhost", "[::1]",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("host %q: got %d, want 200", host, w.Code)
		}
	}
}

func TestSecurityHeadersAllowRemoteBypassesHostCheck(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(true, inner)

	// With the toggle on, a non-localhost Host is served instead of rejected.
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "scrutineer.example:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("allowRemote: got %d, want 200", w.Code)
	}

	// The CSRF check is independent of the host toggle and still fires.
	r = httptest.NewRequest("POST", "/repositories", nil)
	r.Host = "scrutineer.example:8080"
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("allowRemote cross-site POST: got %d, want 403", w.Code)
	}
}

func TestSecurityHeadersRejectsCrossSitePost(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(false, inner)

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
	h := securityHeaders(false, inner)

	r := httptest.NewRequest("POST", "/repositories", nil)
	r.Host = testHost
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("same-origin POST: got %d, want 200", w.Code)
	}
}
