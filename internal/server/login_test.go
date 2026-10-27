package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mostlygeek/llama-swap/internal/config"
)

// formLoginConfig returns a config with form login enabled for key.
func formLoginConfig(keys ...string) config.Config {
	return config.Config{
		RequiredAPIKeys: keys,
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{Mode: config.AuthModeForm, SessionTTL: 3600},
		},
	}
}

// browserRequest builds a request carrying the Sec-Fetch-* headers a browser
// sends. An empty value leaves that header out.
func browserRequest(method, target, site, mode, dest string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for name, value := range map[string]string{"Sec-Fetch-Site": site, "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest} {
		if value != "" {
			r.Header.Set(name, value)
		}
	}
	return r
}

// sessionCookieFor returns a session cookie for key that expires at expiry.
func sessionCookieFor(key string, expiry time.Time) *http.Cookie {
	exp := expiry.Unix()
	return &http.Cookie{
		Name:  sessionCookieName(key),
		Value: strconv.FormatInt(exp, 10) + "." + sessionSignature(key, exp),
	}
}

func TestServer_AuthMiddleware_BasicModeUnchanged(t *testing.T) {
	cfg := config.Config{
		RequiredAPIKeys: []string{"secret"},
		Security:        config.SecurityConfig{Auth: config.AuthConfig{Mode: config.AuthModeBasic}},
	}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	// A page load without credentials still gets the Basic challenge, and a
	// session cookie means nothing.
	r := browserRequest(http.MethodGet, "/ui/", "none", "navigate", "document")
	r.AddCookie(sessionCookieFor("secret", time.Now().Add(time.Hour)))
	w := httptest.NewRecorder()
	CreateAuthMiddleware(cfg)(final).ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header in basic mode")
	}
}

func TestServer_AuthMiddleware_FormMode(t *testing.T) {
	cfg := formLoginConfig("secret")
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	valid := sessionCookieFor("secret", time.Now().Add(time.Hour))

	tests := []struct {
		name      string
		req       func() *http.Request
		wantCode  int
		challenge bool // whether WWW-Authenticate is expected
	}{
		{
			name: "bearer key",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
				r.Header.Set("Authorization", "Bearer secret")
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "basic auth still accepted",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
				r.SetBasicAuth("anyone", "secret")
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie on same-origin fetch",
			req: func() *http.Request {
				r := browserRequest(http.MethodPost, "/api/models/unload", "same-origin", "cors", "empty")
				r.AddCookie(valid)
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie on typed-in page load",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/ui/", "none", "navigate", "document")
				r.AddCookie(valid)
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie on page load linked from another port",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/ui/", "same-site", "navigate", "document")
				r.AddCookie(valid)
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie ignored on cross-site fetch",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/unload", "same-site", "no-cors", "image")
				r.AddCookie(valid)
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "cookie ignored on cross-site POST",
			req: func() *http.Request {
				r := browserRequest(http.MethodPost, "/api/models/unload", "cross-site", "no-cors", "empty")
				r.AddCookie(valid)
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "cookie ignored when framed by another site",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/ui/", "cross-site", "navigate", "iframe")
				r.AddCookie(valid)
				return r
			},
			wantCode: http.StatusSeeOther,
		},
		{
			name: "cookie from an old browser with a matching Origin",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/models/unload", nil)
				r.Header.Set("Origin", "http://example.com")
				r.AddCookie(valid)
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie from an old browser with a foreign Origin",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/models/unload", nil)
				r.Header.Set("Origin", "http://evil.example")
				r.AddCookie(valid)
				return r
			},
			wantCode:  http.StatusUnauthorized,
			challenge: true,
		},
		{
			name: "expired cookie",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty")
				r.AddCookie(sessionCookieFor("secret", time.Now().Add(-time.Second)))
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "tampered expiry",
			req: func() *http.Request {
				c := sessionCookieFor("secret", time.Now().Add(-time.Second))
				_, sig, _ := strings.Cut(c.Value, ".")
				c.Value = strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + "." + sig
				r := browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty")
				r.AddCookie(c)
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "cookie for a key no longer configured",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty")
				r.AddCookie(sessionCookieFor("removed", time.Now().Add(time.Hour)))
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "browser page load without credentials",
			req: func() *http.Request {
				return browserRequest(http.MethodGet, "/ui/", "none", "navigate", "document")
			},
			wantCode: http.StatusSeeOther,
		},
		{
			name: "browser fetch without credentials",
			req: func() *http.Request {
				return browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty")
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "API client without credentials",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			},
			wantCode:  http.StatusUnauthorized,
			challenge: true,
		},
	}

	mw := CreateAuthMiddleware(cfg)(final)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, tt.req())
			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if got := w.Header().Get("WWW-Authenticate") != ""; got != tt.challenge {
				t.Errorf("WWW-Authenticate present = %v, want %v", got, tt.challenge)
			}
		})
	}
}

// TestServer_AuthMiddleware_StripsSessionCookie pins that the session cookie
// never reaches what the middleware wraps (upstreams, peers), while cookies
// belonging to an upstream's own UI pass through.
func TestServer_AuthMiddleware_StripsSessionCookie(t *testing.T) {
	var forwarded string
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	})

	r := browserRequest(http.MethodGet, "/upstream/m1/", "same-origin", "cors", "empty")
	r.AddCookie(&http.Cookie{Name: "comfy", Value: "1"})
	r.AddCookie(sessionCookieFor("secret", time.Now().Add(time.Hour)))
	r.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	w := httptest.NewRecorder()
	CreateAuthMiddleware(formLoginConfig("secret"))(final).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if forwarded != "comfy=1; theme=dark" {
		t.Errorf("forwarded Cookie = %q, want the session cookie removed and the rest kept", forwarded)
	}
}

func TestServer_SessionCookieName(t *testing.T) {
	a, b := sessionCookieName("key-a"), sessionCookieName("key-b")
	if !strings.HasPrefix(a, sessionCookiePrefix) {
		t.Errorf("name %q lacks prefix %q", a, sessionCookiePrefix)
	}
	if a == b {
		t.Errorf("keys share cookie name %q; instances on one host would overwrite each other's login", a)
	}
	if a != sessionCookieName("key-a") {
		t.Error("cookie name is not stable for a key; instances sharing a key would not share the login")
	}
	if strings.Contains(a, "key-a") {
		t.Errorf("cookie name %q contains the key", a)
	}
}

func TestServer_LoginRedirect(t *testing.T) {
	tests := map[string]string{
		"/ui/":                   "../ui/login?next=%2Fui%2F",
		"/logs":                  "ui/login?next=%2Flogs",
		"/upstream/m1/":          "../../ui/login?next=%2Fupstream%2Fm1%2F",
		"/upstream/m1/x?a=1&b=2": "../../ui/login?next=%2Fupstream%2Fm1%2Fx%3Fa%3D1%26b%3D2",
		"/upstream/a%2Fb/":       "../../ui/login?next=%2Fupstream%2Fa%252Fb%2F",
	}
	for target, want := range tests {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if got := loginRedirect(r); got != want {
			t.Errorf("loginRedirect(%q) = %q, want %q", target, got, want)
		}

		// Whatever prefix a reverse proxy adds, the redirect resolves to the
		// login page under that same prefix.
		base, _ := url.Parse("https://host.example/prefix" + target)
		ref, _ := url.Parse(want)
		if got := base.ResolveReference(ref).Path; got != "/prefix/ui/login" {
			t.Errorf("%q resolves to %q, want /prefix/ui/login", target, got)
		}
	}
}

func TestServer_LoginReturnPath(t *testing.T) {
	tests := map[string]string{
		"":                     "./",
		"/ui/":                 "../ui/",
		"/ui/#/models":         "../ui/#/models",
		"/upstream/m1/?x=1":    "../upstream/m1/?x=1",
		"https://evil.example": "./",
		"//evil.example/":      "./",
		"/\\evil.example":      "./",
		"/\t/evil.example":     "./",
		"ui/":                  "./",
		"javascript:alert(1)":  "./",
	}
	for next, want := range tests {
		got := loginReturnPath(next)
		if got != want {
			t.Errorf("loginReturnPath(%q) = %q, want %q", next, got, want)
		}

		// Never leaves the login page's host.
		base, _ := url.Parse("https://host.example/prefix/ui/login")
		ref, _ := url.Parse(got)
		if resolved := base.ResolveReference(ref); resolved.Host != "host.example" {
			t.Errorf("loginReturnPath(%q) resolves to host %q", next, resolved.Host)
		}
	}
}

// TestServer_Login_Flow walks the login page, a failed and a successful login,
// use of the session, and logout through the full router.
func TestServer_Login_Flow(t *testing.T) {
	s := newTestServerWithConfig(formLoginConfig("secret", "other"), newStubRouter(nil, ""), newStubRouter(nil, ""))

	// The page is served without credentials and carries the hints password
	// managers look for.
	w := httptest.NewRecorder()
	s.ServeHTTP(w, browserRequest(http.MethodGet, "/ui/login?next=%2Fui%2F", "none", "navigate", "document"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /ui/login: status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`autocomplete="current-password"`, `value="/ui/"`, `action="login"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %s", want)
		}
	}

	post := func(form url.Values, site string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", site)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}

	w = post(url.Values{"username": {"me"}, "password": {"wrong"}, "next": {"/ui/"}}, "same-origin")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: status = %d, want 401", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("wrong key: a cookie was set")
	}
	if !strings.Contains(w.Body.String(), "not valid") {
		t.Error("wrong key: page does not say the key was rejected")
	}

	w = post(url.Values{"password": {"secret"}, "next": {"/ui/"}}, "cross-site")
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site login: status = %d, want 403", w.Code)
	}

	w = post(url.Values{"username": {"me"}, "password": {"other"}, "next": {"/ui/#/models"}}, "same-origin")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "../ui/#/models" {
		t.Errorf("login: Location = %q, want ../ui/#/models", loc)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login: %d cookies set, want 1", len(cookies))
	}
	session := cookies[0]
	if session.Name != sessionCookieName("other") || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Secure || session.Path != "/" || session.MaxAge != 3600 {
		t.Errorf("login: unexpected cookie %+v", session)
	}

	// The session authenticates the UI's own requests.
	r := browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty")
	r.AddCookie(session)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/version with session: status = %d, want 200", w.Code)
	}

	// Revisiting the login page while logged in goes straight on.
	r = browserRequest(http.MethodGet, "/ui/login?next=%2Fui%2F", "none", "navigate", "document")
	r.AddCookie(session)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "../ui/" {
		t.Errorf("GET /ui/login with session: status = %d, Location = %q, want 303 ../ui/", w.Code, w.Header().Get("Location"))
	}

	// Logout expires the cookie and returns to the login page.
	r = browserRequest(http.MethodPost, "/ui/logout", "same-origin", "cors", "empty")
	r.AddCookie(session)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "login" {
		t.Errorf("logout: status = %d, Location = %q, want 303 login", w.Code, w.Header().Get("Location"))
	}
	cleared := w.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != session.Name || cleared[0].MaxAge >= 0 {
		t.Errorf("logout: cookies = %+v, want %s expired", cleared, session.Name)
	}
}

// TestServer_Login_SecureBehindTLSProxy pins that the cookie is marked Secure
// when a reverse proxy terminated TLS, and only then.
func TestServer_Login_SecureBehindTLSProxy(t *testing.T) {
	s := newTestServerWithConfig(formLoginConfig("secret"), newStubRouter(nil, ""), newStubRouter(nil, ""))

	r := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader("password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure {
		t.Errorf("cookies = %+v, want one Secure cookie", cookies)
	}
}

// TestServer_Login_OnlyInFormMode pins that basic mode registers no login
// routes, so a deployment that never opts in serves what it always did.
func TestServer_Login_OnlyInFormMode(t *testing.T) {
	cfg := config.Config{RequiredAPIKeys: []string{"secret"}}
	s := newTestServerWithConfig(cfg, newStubRouter(nil, ""), newStubRouter(nil, ""))

	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ui/login", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("GET /ui/login: status = %d, want 401 from the protected /ui/ route", w.Code)
	}

	r := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader("password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if len(w.Result().Cookies()) != 0 {
		t.Error("POST /ui/login set a cookie in basic mode")
	}
}
