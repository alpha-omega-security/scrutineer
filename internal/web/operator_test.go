package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestRequireOperatorGatesUI(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	for _, tc := range []struct {
		name   string
		cookie string
		auth   string
		want   int
	}{
		{"no credential", "", "", http.StatusUnauthorized},
		{"wrong cookie", "wrong", "", http.StatusUnauthorized},
		{"wrong bearer", "", "Bearer wrong", http.StatusUnauthorized},
		{"wrong bearer beside a valid cookie", testOperatorToken, "Bearer wrong", http.StatusUnauthorized},
		{"cookie", testOperatorToken, "", http.StatusOK},
		{"bearer", "", "Bearer " + testOperatorToken, http.StatusOK},
	} {
		r := httptest.NewRequest("GET", "/repositories", nil)
		r.Host = testHost
		if tc.cookie != "" {
			r.AddCookie(&http.Cookie{Name: testOperatorCookie, Value: tc.cookie})
		}
		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}
		if w := serve(s, r); w.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, w.Code, tc.want)
		}
	}
}

func TestRequireOperatorKeepsHostCheck(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r := httptest.NewRequest("GET", "/repositories", nil)
	r.Host = "evil.example:8080"
	r.Header.Set("Authorization", "Bearer "+testOperatorToken)
	if w := serve(s, r); w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
}

func TestRequireOperatorFailsClosedWithoutToken(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.OperatorToken = ""

	r := httptest.NewRequest("GET", "/repositories", nil)
	r.Host = testHost
	r.AddCookie(&http.Cookie{Name: testOperatorCookie, Value: ""})
	if w := serve(s, r); w.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", w.Code)
	}
	r = httptest.NewRequest("GET", "/login?token=", nil)
	r.Host = testHost
	if w := serve(s, r); w.Code != http.StatusUnauthorized {
		t.Errorf("login: status %d, want 401", w.Code)
	}
}

func TestLoginSetsOperatorCookie(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r := httptest.NewRequest("GET", "/login?token="+testOperatorToken, nil)
	r.Host = testHost
	w := serve(s, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("status %d Location %q, want 303 to /", w.Code, w.Header().Get("Location"))
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != testOperatorCookie || c.Value != testOperatorToken || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie = %+v, want HttpOnly SameSite=Strict operator cookie", c)
	}

	r = httptest.NewRequest("GET", "/repositories", nil)
	r.Host = testHost
	r.AddCookie(c)
	if w := serve(s, r); w.Code != http.StatusOK {
		t.Errorf("with login cookie: status %d, want 200", w.Code)
	}
}

func TestLoginRejectsWrongToken(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	for _, target := range []string{"/login", "/login?token=wrong"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = testHost
		w := serve(s, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", target, w.Code)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Errorf("%s: set a cookie on a rejected login", target)
		}
	}

	r := httptest.NewRequest("GET", "/login?token="+testOperatorToken, nil)
	r.Host = "evil.example:8080"
	if w := serve(s, r); w.Code != http.StatusForbidden {
		t.Errorf("non-loopback Host: status %d, want 403", w.Code)
	}
}

func TestOperatorExemptRoutes(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r := httptest.NewRequest("GET", "/static/app.js", nil)
	r.Host = testHost
	if w := serve(s, r); w.Code != http.StatusOK {
		t.Errorf("static: status %d, want 200", w.Code)
	}

	// Without a federation salt claim-check answers 404, not the 401 the
	// operator gate would.
	r = httptest.NewRequest("POST", "/claim-check", nil)
	r.Host = testHost
	if w := serve(s, r); w.Code != http.StatusNotFound {
		t.Errorf("claim-check: status %d, want 404", w.Code)
	}
}

func TestOperatorCookieNameIsPerToken(t *testing.T) {
	a, b := operatorCookieName("token-a"), operatorCookieName("token-b")
	if a == b {
		t.Errorf("two tokens share cookie name %q; instances on one host would sign each other out", a)
	}
	if a != operatorCookieName("token-a") {
		t.Error("cookie name changed between calls; a restart would sign the browser out")
	}
	if c := (&http.Cookie{Name: a, Value: "v"}).String(); c == "" {
		t.Errorf("%q is not a valid cookie name", a)
	}
}

func TestLoginDoesNotSignOutOtherInstance(t *testing.T) {
	a, doneA := newTestServer(t)
	defer doneA()
	b, doneB := newTestServer(t)
	defer doneB()
	b.OperatorToken = "other-instance-token"

	login := func(s *Server, token string) *http.Cookie {
		r := httptest.NewRequest("GET", "/login?token="+token, nil)
		r.Host = testHost
		return serve(s, r).Result().Cookies()[0]
	}
	// A browser holds one cookie per name on 127.0.0.1 whatever the port,
	// so B's cookie must not replace A's.
	jar := map[string]*http.Cookie{}
	for _, c := range []*http.Cookie{login(a, testOperatorToken), login(b, b.OperatorToken)} {
		jar[c.Name] = c
	}

	r := httptest.NewRequest("GET", "/repositories", nil)
	r.Host = testHost
	for _, c := range jar {
		r.AddCookie(c)
	}
	if w := serve(a, r); w.Code != http.StatusOK {
		t.Errorf("instance A after signing into B: status %d, want 200", w.Code)
	}
}

func TestUnauthorizedNamesTokenFile(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.OperatorTokenFile = "/srv/scrutineer/data/operator-token"

	r := httptest.NewRequest("GET", "/repositories", nil)
	r.Host = testHost
	w := serve(s, r)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), s.OperatorTokenFile) {
		t.Errorf("status %d body %q, want 401 naming %s", w.Code, w.Body.String(), s.OperatorTokenFile)
	}
}
