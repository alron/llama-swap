package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mostlygeek/llama-swap/internal/config"
	"github.com/mostlygeek/llama-swap/internal/swaputil"
)

// formLoginConfig returns a config with form login enabled for keys, signing
// sessions with the per-process secret, lasting an hour unused.
func formLoginConfig(keys ...string) config.Config {
	ttl := 3600
	return config.Config{
		RequiredAPIKeys: keys,
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{Mode: config.AuthModeForm, SessionTTL: &ttl},
		},
	}
}

// withSecret returns cfg signing sessions with secret.
func withSecret(cfg config.Config, secret string) config.Config {
	cfg.Security.Auth.SessionSecret = secret
	return cfg
}

// browserRequest builds a request carrying the Sec-Fetch-* headers a browser
// sends over HTTPS or to localhost. An empty value leaves that header out.
func browserRequest(method, target, site, mode, dest string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for name, value := range map[string]string{"Sec-Fetch-Site": site, "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest} {
		if value != "" {
			r.Header.Set(name, value)
		}
	}
	return r
}

// plainHTTPRequest builds a request as a browser sends it over plain HTTP to
// an address other than localhost: no Sec-Fetch-* at all, so only Accept,
// Origin and Referer say where it came from. An empty value leaves that
// header out. httptest requests arrive for Host example.com.
func plainHTTPRequest(method, target, accept, origin, referer string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for name, value := range map[string]string{"Accept": accept, "Origin": origin, "Referer": referer} {
		if value != "" {
			r.Header.Set(name, value)
		}
	}
	return r
}

// sessionCookieFor returns a cookie sa would issue for key, expiring at expiry.
func sessionCookieFor(sa *sessionAuth, key string, expiry time.Time) *http.Cookie {
	return sessionCookieSince(sa, key, time.Now(), expiry)
}

// sessionCookieSince is sessionCookieFor for a login made at login.
func sessionCookieSince(sa *sessionAuth, key string, login, expiry time.Time) *http.Cookie {
	c := sa.cookie(httptest.NewRequest(http.MethodGet, "/", nil), session{key: key, login: login, expiry: expiry})
	return &http.Cookie{Name: c.Name, Value: c.Value}
}

type authCase struct {
	name      string
	req       func() *http.Request
	wantCode  int
	challenge bool // whether WWW-Authenticate is expected
}

func runAuthCases(t *testing.T, cfg config.Config, tests []authCase) {
	t.Helper()
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
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

func TestServer_AuthMiddleware_BasicModeUnchanged(t *testing.T) {
	cfg := config.Config{
		RequiredAPIKeys: []string{"secret"},
		Security:        config.SecurityConfig{Auth: config.AuthConfig{Mode: config.AuthModeBasic}},
	}
	sa := newSessionAuth(formLoginConfig("secret"))

	// A page load without credentials still gets the Basic challenge, and a
	// session cookie means nothing.
	runAuthCases(t, cfg, []authCase{{
		name: "page load with a session cookie",
		req: func() *http.Request {
			r := browserRequest(http.MethodGet, "/ui/", "none", "navigate", "document")
			r.AddCookie(sessionCookieFor(sa, "secret", time.Now().Add(time.Hour)))
			return r
		},
		wantCode:  http.StatusUnauthorized,
		challenge: true,
	}, {
		name: "browser with Basic auth",
		req: func() *http.Request {
			r := browserRequest(http.MethodGet, "/ui/", "none", "navigate", "document")
			r.SetBasicAuth("anyone", "secret")
			return r
		},
		wantCode: http.StatusOK,
	}})
}

// TestServer_AuthMiddleware_FormMode covers browsers that send Fetch
// Metadata, which they do over HTTPS and to localhost.
func TestServer_AuthMiddleware_FormMode(t *testing.T) {
	cfg := formLoginConfig("secret")
	sa := newSessionAuth(cfg)
	valid := sessionCookieFor(sa, "secret", time.Now().Add(time.Hour))
	withCookie := func(r *http.Request, c *http.Cookie) *http.Request {
		r.AddCookie(c)
		return r
	}

	runAuthCases(t, cfg, []authCase{
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
			// Possibly cached from the native dialog; logging out must work.
			name: "basic auth from a browser page load is ignored",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/ui/", "none", "navigate", "document")
				r.SetBasicAuth("anyone", "secret")
				return r
			},
			wantCode: http.StatusSeeOther,
		},
		{
			name: "basic auth on a browser fetch is ignored",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty")
				r.SetBasicAuth("anyone", "secret")
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			// A client that sent a key needs to hear the key is wrong, not to
			// be sent to a login page. Another llama-swap proxying a page load
			// here with a wrong peer key would otherwise loop.
			name: "wrong Bearer key on a browser page load",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/upstream/m1/", "none", "navigate", "document")
				r.Header.Set("Authorization", "Bearer wrong")
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "wrong x-api-key on a page load proxied by a peer",
			req: func() *http.Request {
				r := plainHTTPRequest(http.MethodGet, "/upstream/m1/", "text/html", "", "")
				r.Header.Set("x-api-key", "wrong")
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "bearer from a browser still accepted",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/v1/models", "cross-site", "cors", "empty")
				r.Header.Set("Authorization", "Bearer secret")
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie on same-origin fetch",
			req: func() *http.Request {
				return withCookie(browserRequest(http.MethodPost, "/api/models/unload", "same-origin", "cors", "empty"), valid)
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie on typed-in page load",
			req: func() *http.Request {
				return withCookie(browserRequest(http.MethodGet, "/ui/", "none", "navigate", "document"), valid)
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie on page load linked from another port",
			req: func() *http.Request {
				return withCookie(browserRequest(http.MethodGet, "/ui/", "same-site", "navigate", "document"), valid)
			},
			wantCode: http.StatusOK,
		},
		{
			name: "cookie refused on an image request from another port",
			req: func() *http.Request {
				return withCookie(browserRequest(http.MethodGet, "/upstream/m1/", "same-site", "no-cors", "image"), valid)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "cookie refused on cross-site POST",
			req: func() *http.Request {
				return withCookie(browserRequest(http.MethodPost, "/api/models/unload", "cross-site", "no-cors", "empty"), valid)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "cookie refused when framed by another site",
			req: func() *http.Request {
				return withCookie(browserRequest(http.MethodGet, "/ui/", "cross-site", "navigate", "iframe"), valid)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "expired cookie",
			req: func() *http.Request {
				return withCookie(browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty"),
					sessionCookieFor(sa, "secret", time.Now().Add(-time.Second)))
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "tampered expiry",
			req: func() *http.Request {
				c := sessionCookieFor(sa, "secret", time.Now().Add(-time.Second))
				parts := strings.Split(c.Value, ".")
				parts[1] = strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
				c.Value = strings.Join(parts, ".")
				return withCookie(browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty"), c)
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			// The cap is measured from login, so moving it must invalidate
			// the cookie rather than buy a longer lifetime.
			name: "tampered login time",
			req: func() *http.Request {
				c := sessionCookieFor(sa, "secret", time.Now().Add(time.Hour))
				parts := strings.Split(c.Value, ".")
				parts[0] = strconv.FormatInt(time.Now().Add(24*time.Hour).Unix(), 10)
				c.Value = strings.Join(parts, ".")
				return withCookie(browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty"), c)
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "cookie for a key no longer configured",
			req: func() *http.Request {
				other := newSessionAuth(formLoginConfig("removed"))
				return withCookie(browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty"),
					sessionCookieFor(other, "removed", time.Now().Add(time.Hour)))
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
	})
}

// TestServer_AuthMiddleware_PlainHTTP covers browsers reaching llama-swap
// over plain HTTP at a LAN address, where they send no Sec-Fetch-* headers.
func TestServer_AuthMiddleware_PlainHTTP(t *testing.T) {
	cfg := formLoginConfig("secret")
	sa := newSessionAuth(cfg)
	valid := sessionCookieFor(sa, "secret", time.Now().Add(time.Hour))
	withCookie := func(r *http.Request) *http.Request {
		r.AddCookie(valid)
		return r
	}
	const self, otherPort = "http://example.com", "http://example.com:9000"

	runAuthCases(t, cfg, []authCase{
		{
			name: "UI fetch",
			req: func() *http.Request {
				return withCookie(plainHTTPRequest(http.MethodGet, "/api/version", "*/*", "", self+"/ui/"))
			},
			wantCode: http.StatusOK,
		},
		{
			name: "UI event stream",
			req: func() *http.Request {
				return withCookie(plainHTTPRequest(http.MethodGet, "/api/events", "text/event-stream", "", self+"/ui/"))
			},
			wantCode: http.StatusOK,
		},
		{
			name: "UI POST",
			req: func() *http.Request {
				return withCookie(plainHTTPRequest(http.MethodPost, "/api/models/unload", "*/*", self, self+"/ui/"))
			},
			wantCode: http.StatusOK,
		},
		{
			name:     "typed-in page load",
			req:      func() *http.Request { return withCookie(plainHTTPRequest(http.MethodGet, "/ui/", "text/html", "", "")) },
			wantCode: http.StatusOK,
		},
		{
			name: "page load linked from another port",
			req: func() *http.Request {
				return withCookie(plainHTTPRequest(http.MethodGet, "/ui/", "text/html", "", otherPort+"/"))
			},
			wantCode: http.StatusOK,
		},
		{
			name: "image request from another port",
			req: func() *http.Request {
				return withCookie(plainHTTPRequest(http.MethodGet, "/upstream/m1/", "image/*", "", otherPort+"/"))
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "image request with the referrer stripped",
			req: func() *http.Request {
				return withCookie(plainHTTPRequest(http.MethodGet, "/upstream/m1/", "image/*", "", ""))
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "POST from another port",
			req: func() *http.Request {
				return withCookie(plainHTTPRequest(http.MethodPost, "/api/models/unload", "*/*", otherPort, otherPort+"/"))
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "POST from an opaque origin",
			req: func() *http.Request {
				return withCookie(plainHTTPRequest(http.MethodPost, "/api/models/unload", "*/*", "null", self+"/ui/"))
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "behind a proxy that rewrites Host",
			req: func() *http.Request {
				r := withCookie(plainHTTPRequest(http.MethodPost, "/api/models/unload", "*/*", self, self+"/ui/"))
				r.Host = "127.0.0.1:8080"
				r.Header.Set("X-Forwarded-Host", "example.com")
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "X-Forwarded-Host does not admit another origin",
			req: func() *http.Request {
				r := withCookie(plainHTTPRequest(http.MethodPost, "/api/models/unload", "*/*", otherPort, ""))
				r.Header.Set("X-Forwarded-Host", "example.com")
				return r
			},
			wantCode: http.StatusForbidden,
		},
		{
			// The browser deletes the cookie when it expires, so the UI's
			// next request carries none. It must get a bare 401, not the
			// Basic challenge that would bring back the native dialog.
			name:     "UI fetch after the session expired",
			req:      func() *http.Request { return plainHTTPRequest(http.MethodGet, "/api/version", "*/*", "", self+"/ui/") },
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "UI event stream after the session expired",
			req: func() *http.Request {
				return plainHTTPRequest(http.MethodGet, "/api/events", "text/event-stream", "", self+"/ui/")
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "page load without credentials",
			req:      func() *http.Request { return plainHTTPRequest(http.MethodGet, "/ui/", "text/html", "", "") },
			wantCode: http.StatusSeeOther,
		},
		{
			name: "page load with cached Basic auth",
			req: func() *http.Request {
				r := plainHTTPRequest(http.MethodGet, "/ui/", "text/html", "", "")
				r.SetBasicAuth("anyone", "secret")
				return r
			},
			wantCode: http.StatusSeeOther,
		},
	})
}

// TestServer_AuthMiddleware_StripsSessionCookie pins that the session cookie
// never reaches what the middleware wraps (upstreams, peers) in either mode,
// while cookies belonging to an upstream's own UI pass through.
func TestServer_AuthMiddleware_StripsSessionCookie(t *testing.T) {
	sa := newSessionAuth(formLoginConfig("secret"))
	basic := config.Config{RequiredAPIKeys: []string{"secret"}}

	for name, cfg := range map[string]config.Config{"form": formLoginConfig("secret"), "basic": basic} {
		t.Run(name, func(t *testing.T) {
			var forwarded string
			final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = r.Header.Get("Cookie")
				w.WriteHeader(http.StatusOK)
			})

			r := browserRequest(http.MethodGet, "/upstream/m1/", "same-origin", "cors", "empty")
			r.Header.Set("Authorization", "Bearer secret")
			r.AddCookie(&http.Cookie{Name: "comfy", Value: "1"})
			r.AddCookie(sessionCookieFor(sa, "secret", time.Now().Add(time.Hour)))
			r.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
			w := httptest.NewRecorder()
			CreateAuthMiddleware(cfg)(final).ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if forwarded != "comfy=1; theme=dark" {
				t.Errorf("forwarded Cookie = %q, want the session cookie removed and the rest kept", forwarded)
			}
		})
	}
}

func TestServer_SessionCookieName(t *testing.T) {
	secretA := strings.Repeat("a", config.MinSessionSecretLength)
	secretB := strings.Repeat("b", config.MinSessionSecretLength)
	sa := newSessionAuth(withSecret(formLoginConfig("key-a", "key-b"), secretA))

	a, b := sa.cookieName("key-a"), sa.cookieName("key-b")
	if !strings.HasPrefix(a, sessionCookiePrefix) {
		t.Errorf("name %q lacks prefix %q", a, sessionCookiePrefix)
	}
	if a == b {
		t.Errorf("keys share cookie name %q", a)
	}
	if strings.Contains(a, "key-a") {
		t.Errorf("cookie name %q contains the key", a)
	}

	// Another instance on the same host, with its own secret, uses its own
	// cookie, so logging in to one never overwrites the other's login.
	other := newSessionAuth(withSecret(formLoginConfig("key-a"), secretB))
	if other.cookieName("key-a") == a {
		t.Error("instances with different secrets share a cookie name")
	}
	if other.validCookie(sessionCookieFor(sa, "key-a", time.Now().Add(time.Hour))) {
		t.Error("a session from one secret is valid under another")
	}

	// Instances configured with the same secret and key share a login.
	shared := newSessionAuth(withSecret(formLoginConfig("key-a"), secretA))
	if !shared.validCookie(sessionCookieFor(sa, "key-a", time.Now().Add(time.Hour))) {
		t.Error("instances sharing a secret do not share the login")
	}

	// Without a configured secret, Servers built by a config reload share the
	// process secret, so a reload keeps browsers logged in.
	before := newSessionAuth(formLoginConfig("key-a"))
	after := newSessionAuth(formLoginConfig("key-a"))
	if !after.validCookie(sessionCookieFor(before, "key-a", time.Now().Add(time.Hour))) {
		t.Error("a session does not survive a config reload")
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

// postLogin submits the login form to s. headers are set on the request.
func postLogin(s *Server, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// TestServer_Login_Flow walks the login page, a failed and a successful login,
// use of the session, and logout through the full router.
func TestServer_Login_Flow(t *testing.T) {
	s := newTestServerWithConfig(formLoginConfig("secret", "other"), newStubRouter(nil, ""), newStubRouter(nil, ""))
	sameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}

	// The page is served without credentials, carries the hint password
	// managers look for, and may not be framed or post elsewhere.
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
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("Content-Security-Policy = %q", csp)
	}

	w = postLogin(s, url.Values{"password": {"wrong"}, "next": {"/ui/"}}, sameOrigin)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: status = %d, want 401", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("wrong key: a cookie was set")
	}
	if !strings.Contains(w.Body.String(), "not valid") {
		t.Error("wrong key: page does not say the key was rejected")
	}

	w = postLogin(s, url.Values{"password": {"secret"}, "next": {"/ui/"}}, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site login: status = %d, want 403", w.Code)
	}

	w = postLogin(s, url.Values{"password": {"other"}, "next": {"/ui/#/models"}}, sameOrigin)
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
	sa := newSessionAuth(formLoginConfig("secret", "other"))
	if session.Name != sa.cookieName("other") || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Secure || session.Path != "/" || session.MaxAge != 3600 {
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

	// Logout expires this instance's cookie and returns to the login page,
	// leaving another instance's cookie on the same host alone.
	foreign := &http.Cookie{Name: sessionCookiePrefix + "deadbeef", Value: "1.x"}
	r = browserRequest(http.MethodPost, "/ui/logout", "same-origin", "cors", "empty")
	r.AddCookie(session)
	r.AddCookie(foreign)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "login" {
		t.Errorf("logout: status = %d, Location = %q, want 303 login", w.Code, w.Header().Get("Location"))
	}
	cleared := w.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != session.Name || cleared[0].MaxAge >= 0 {
		t.Errorf("logout: cookies = %+v, want only %s expired", cleared, session.Name)
	}
}

// TestServer_Login_PlainHTTP pins the login form's origin check for browsers
// that send no Sec-Fetch-* headers, which is every browser on plain HTTP to a
// LAN address.
func TestServer_Login_PlainHTTP(t *testing.T) {
	s := newTestServerWithConfig(formLoginConfig("secret"), newStubRouter(nil, ""), newStubRouter(nil, ""))
	form := url.Values{"password": {"secret"}, "next": {"/ui/"}}

	tests := []struct {
		name    string
		headers map[string]string
		host    string
		want    int
	}{
		{"posted from the login page", map[string]string{"Origin": "http://example.com", "Referer": "http://example.com/ui/login"}, "", http.StatusSeeOther},
		{"posted from another port", map[string]string{"Origin": "http://example.com:9000"}, "", http.StatusForbidden},
		{"no Origin or Referer", nil, "", http.StatusForbidden},
		{"behind a proxy that rewrites Host", map[string]string{"Origin": "http://example.com", "X-Forwarded-Host": "example.com"}, "127.0.0.1:8080", http.StatusSeeOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for name, value := range tt.headers {
				r.Header.Set(name, value)
			}
			if tt.host != "" {
				r.Host = tt.host
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// TestServer_Login_SecureBehindTLSProxy pins that the cookie is marked Secure
// when a reverse proxy terminated TLS, and only then.
func TestServer_Login_SecureBehindTLSProxy(t *testing.T) {
	s := newTestServerWithConfig(formLoginConfig("secret"), newStubRouter(nil, ""), newStubRouter(nil, ""))

	w := postLogin(s, url.Values{"password": {"secret"}}, map[string]string{"Sec-Fetch-Site": "same-origin", "X-Forwarded-Proto": "https"})
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

	w = postLogin(s, url.Values{"password": {"secret"}}, nil)
	if len(w.Result().Cookies()) != 0 {
		t.Error("POST /ui/login set a cookie in basic mode")
	}
}

// TestServer_Unload_IgnoresSessionCookie pins that GET /unload, which acts on
// a plain GET any page can make a browser send, takes API keys in a header
// only, and that in form mode a browser is neither shown the Basic dialog nor
// sent to the login page, which would only send it back here in a loop.
func TestServer_Unload_IgnoresSessionCookie(t *testing.T) {
	cfg := formLoginConfig("secret")
	s := newTestServerWithConfig(cfg, newStubRouter(nil, ""), newStubRouter(nil, ""))
	session := sessionCookieFor(newSessionAuth(cfg), "secret", time.Now().Add(time.Hour))

	tests := []struct {
		name      string
		req       func() *http.Request
		wantCode  int
		challenge bool
	}{
		{
			name: "browser page load with a session",
			req: func() *http.Request {
				r := browserRequest(http.MethodGet, "/unload", "same-origin", "navigate", "document")
				r.AddCookie(session)
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "browser with Basic auth",
			req: func() *http.Request {
				r := plainHTTPRequest(http.MethodGet, "/unload", "text/html", "", "")
				r.SetBasicAuth("anyone", "secret")
				return r
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "API client with Bearer",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/unload", nil)
				r.Header.Set("Authorization", "Bearer secret")
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name: "API client with Basic auth",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/unload", nil)
				r.SetBasicAuth("anyone", "secret")
				return r
			},
			wantCode: http.StatusOK,
		},
		{
			name:      "API client without a key",
			req:       func() *http.Request { return httptest.NewRequest(http.MethodGet, "/unload", nil) },
			wantCode:  http.StatusUnauthorized,
			challenge: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, tt.req())
			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if got := w.Header().Get("WWW-Authenticate") != ""; got != tt.challenge {
				t.Errorf("WWW-Authenticate present = %v, want %v", got, tt.challenge)
			}
		})
	}
}

// TestServer_AuthMiddleware_LoginRequiredHeader pins that only llama-swap's
// own "log in" answer to a browser carries the marker the UI acts on, so a
// 401 passed through from an upstream or peer never sends it to the login page.
func TestServer_AuthMiddleware_LoginRequiredHeader(t *testing.T) {
	cfg := formLoginConfig("secret")
	sa := newSessionAuth(cfg)
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mw := CreateAuthMiddleware(cfg)(final)

	refused := plainHTTPRequest(http.MethodGet, "/upstream/m1/", "image/*", "", "http://example.com:9000/")
	refused.AddCookie(sessionCookieFor(sa, "secret", time.Now().Add(time.Hour)))

	tests := map[string]struct {
		req  *http.Request
		want string
	}{
		"browser fetch without a session":     {plainHTTPRequest(http.MethodGet, "/api/version", "*/*", "", "http://example.com/ui/"), "required"},
		"browser page load without a session": {plainHTTPRequest(http.MethodGet, "/ui/", "text/html", "", ""), "required"},
		"browser with a wrong Bearer key": {func() *http.Request {
			r := plainHTTPRequest(http.MethodGet, "/ui/", "text/html", "", "")
			r.Header.Set("Authorization", "Bearer wrong")
			return r
		}(), ""},
		"API client without a key": {httptest.NewRequest(http.MethodGet, "/v1/models", nil), ""},
		"valid session refused":    {refused, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, tt.req)
			if got := w.Header().Get(swaputil.LoginRequiredHeader); got != tt.want {
				t.Errorf("%s = %q, want %q (status %d)", swaputil.LoginRequiredHeader, got, tt.want, w.Code)
			}
		})
	}
}

// TestServer_AuthMiddleware_SessionEndsRequests pins that a request
// authenticated only by the session cookie ends when the session does, so
// the UI's event stream cannot keep a logged-out UI looking alive.
func TestServer_AuthMiddleware_SessionEndsRequests(t *testing.T) {
	cfg := formLoginConfig("secret")
	sa := newSessionAuth(cfg)
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)

	var deadline time.Time
	var hasDeadline bool
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, hasDeadline = r.Context().Deadline()
	})
	mw := CreateAuthMiddleware(cfg)(final)

	r := browserRequest(http.MethodGet, "/api/events", "same-origin", "cors", "empty")
	r.AddCookie(sessionCookieFor(sa, "secret", expiry))
	mw.ServeHTTP(httptest.NewRecorder(), r)
	if !hasDeadline || !deadline.Equal(expiry) {
		t.Errorf("cookie request deadline = %v (set %v), want %v", deadline, hasDeadline, expiry)
	}

	r = httptest.NewRequest(http.MethodGet, "/api/events", nil)
	r.Header.Set("Authorization", "Bearer secret")
	mw.ServeHTTP(httptest.NewRecorder(), r)
	if hasDeadline {
		t.Errorf("API key request got a deadline of %v", deadline)
	}
}

// TestServer_APIEvents_EndsWithSession runs the real event stream with a
// session about to expire and checks the stream closes on its own.
func TestServer_APIEvents_EndsWithSession(t *testing.T) {
	cfg := formLoginConfig("secret")
	s := newTestServerWithConfig(cfg, newStubRouter(nil, ""), newStubRouter(nil, ""))

	r := browserRequest(http.MethodGet, "/api/events", "same-origin", "cors", "empty")
	r.AddCookie(sessionCookieFor(newSessionAuth(cfg), "secret", time.Now().Add(2*time.Second)))
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		s.ServeHTTP(w, r)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("event stream still open after the session expired")
	}
	if !strings.Contains(w.Body.String(), `"type":"modelStatus"`) {
		t.Errorf("stream never started; body=%q", w.Body.String())
	}
}

// TestServer_AuthMiddleware_RenewsSession pins renewal on activity: a page
// load or a request that changes something extends the session to a full ttl
// from now, however recently it was last renewed, never past the lifetime cap
// measured from login, and a script's GET, such as a page polling for status,
// never extends it.
func TestServer_AuthMiddleware_RenewsSession(t *testing.T) {
	const ttl = 3600
	now := time.Unix(1_800_000_000, 0)
	at := func(offset int) time.Time { return now.Add(time.Duration(offset) * time.Second) }
	withCap := func(seconds int) config.Config {
		cfg := formLoginConfig("secret")
		cfg.Security.Auth.SessionMaxLifetime = &seconds
		return cfg
	}

	chat := func() *http.Request {
		return browserRequest(http.MethodPost, "/v1/chat/completions", "same-origin", "cors", "empty")
	}
	pageLoad := func() *http.Request { return plainHTTPRequest(http.MethodGet, "/upstream/m1/", "text/html", "", "") }
	poll := func() *http.Request {
		return plainHTTPRequest(http.MethodGet, "/upstream/m1/props", "*/*", "", "http://example.com/upstream/m1/")
	}
	stream := func() *http.Request {
		return browserRequest(http.MethodGet, "/api/events", "same-origin", "cors", "empty")
	}
	const month = 30 * 24 * 3600

	tests := []struct {
		name       string
		cfg        config.Config
		req        func() *http.Request
		login      time.Time
		expiry     time.Time
		wantExpiry time.Time // zero means no new cookie
	}{
		{"chat past halfway", withCap(month), chat, at(-1000), at(1000), at(ttl)},
		{"page load past halfway", withCap(month), pageLoad, at(-1000), at(1000), at(ttl)},
		{"chat soon after the last renewal", withCap(month), chat, at(-600), at(3000), at(ttl)},
		{"chat in the same second as a renewal", withCap(month), chat, at(-600), at(ttl), time.Time{}},
		{"renewal trimmed to the cap", withCap(7200), chat, at(-7000), at(100), at(200)},
		{"already at the cap", withCap(7200), chat, at(-7150), at(50), time.Time{}},
		{"no cap", withCap(0), chat, at(-100 * 24 * 3600), at(10), at(ttl)},
		{"page polling for status", withCap(0), poll, at(-1000), at(1000), time.Time{}},
		{"event stream", withCap(0), stream, at(-1000), at(1000), time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := newSessionAuth(tt.cfg)
			sa.now = func() time.Time { return now }

			var deadline time.Time
			final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				deadline, _ = r.Context().Deadline()
			})
			r := tt.req()
			r.AddCookie(sessionCookieSince(sa, "secret", tt.login, tt.expiry))
			w := httptest.NewRecorder()
			createAuthMiddleware(tt.cfg.RequiredAPIKeys, sa, sessionAccepted)(final).ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			cookies := w.Result().Cookies()
			if tt.wantExpiry.IsZero() {
				if len(cookies) != 0 {
					t.Errorf("session renewed: %v", cookies)
				}
				if !deadline.Equal(tt.expiry) {
					t.Errorf("deadline = %v, want the unchanged expiry %v", deadline, tt.expiry)
				}
				return
			}
			if len(cookies) != 1 {
				t.Fatalf("cookies = %v, want one renewed session", cookies)
			}
			renewed, ok := sa.parse(cookies[0])
			if !ok {
				t.Fatalf("renewed cookie %v does not parse", cookies[0])
			}
			if !renewed.expiry.Equal(tt.wantExpiry) || !renewed.login.Equal(tt.login) {
				t.Errorf("renewed to login %v expiry %v, want login %v expiry %v", renewed.login, renewed.expiry, tt.login, tt.wantExpiry)
			}
			if !deadline.Equal(tt.wantExpiry) {
				t.Errorf("deadline = %v, want the renewed expiry %v", deadline, tt.wantExpiry)
			}
		})
	}
}

// TestServer_SessionRenewal_Routes runs the real router: an action in the UI
// renews a session past halfway, while a background GET and the event stream
// do not, so an idle open tab still expires.
func TestServer_SessionRenewal_Routes(t *testing.T) {
	cfg := formLoginConfig("secret")
	s := newTestServerWithConfig(cfg, newStubRouter(nil, ""), newStubRouter(nil, ""))
	cookie := sessionCookieFor(newSessionAuth(cfg), "secret", time.Now().Add(time.Minute))

	renewed := func(r *http.Request) []string {
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Header().Values("Set-Cookie")
	}

	if got := renewed(browserRequest(http.MethodPost, "/api/models/unload", "same-origin", "cors", "empty")); len(got) != 1 {
		t.Errorf("POST /api/models/unload: Set-Cookie = %v, want the session renewed", got)
	}
	if got := renewed(browserRequest(http.MethodGet, "/api/version", "same-origin", "cors", "empty")); len(got) != 0 {
		t.Errorf("GET /api/version renewed the session: %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := browserRequest(http.MethodGet, "/api/events", "same-origin", "cors", "empty").WithContext(ctx)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.ServeHTTP(w, r)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if got := w.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("GET /api/events renewed the session: %v", got)
	}
}

// TestServer_AuthMiddleware_MarksBrowsersForChallengeStripping pins that only
// browser requests under form login are marked to lose an upstream's or
// peer's WWW-Authenticate, so API clients and basic mode still see it.
func TestServer_AuthMiddleware_MarksBrowsersForChallengeStripping(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		browser bool
		want    bool
	}{
		{"form mode, browser", formLoginConfig("secret"), true, true},
		{"form mode, API client", formLoginConfig("secret"), false, false},
		{"basic mode, browser", config.Config{RequiredAPIKeys: []string{"secret"}}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stripped bool
			final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := &http.Response{Header: http.Header{"Www-Authenticate": {"Basic"}}, Request: r}
				swaputil.StripAuthChallenge(resp)
				stripped = resp.Header.Get("WWW-Authenticate") == ""
			})
			r := httptest.NewRequest(http.MethodGet, "/upstream/m1/", nil)
			if tt.browser {
				r.Header.Set("Referer", "http://example.com/ui/")
			}
			r.Header.Set("Authorization", "Bearer secret")
			CreateAuthMiddleware(tt.cfg)(final).ServeHTTP(httptest.NewRecorder(), r)
			if stripped != tt.want {
				t.Errorf("challenge stripped = %v, want %v", stripped, tt.want)
			}
		})
	}
}

// TestServer_SessionCapAppliesToExistingCookies pins that the lifetime cap is
// applied as configured now, so lowering sessionMaxLifetime ends sessions it
// no longer allows instead of waiting for their next renewal.
func TestServer_SessionCapAppliesToExistingCookies(t *testing.T) {
	now := time.Now()
	issuedUnder := newSessionAuth(formLoginConfig("secret"))
	cookie := sessionCookieSince(issuedUnder, "secret", now.Add(-2*time.Hour), now.Add(time.Hour))

	for _, tc := range []struct {
		capSeconds int
		valid      bool
	}{{0, true}, {3 * 3600, true}, {3600, false}} {
		cfg := formLoginConfig("secret")
		cfg.Security.Auth.SessionMaxLifetime = &tc.capSeconds
		s, ok := newSessionAuth(cfg).parse(cookie)
		if ok != tc.valid {
			t.Errorf("cap %ds: valid = %v, want %v", tc.capSeconds, ok, tc.valid)
		}
		if ok && tc.capSeconds > 0 && s.expiry.After(s.login.Add(time.Duration(tc.capSeconds)*time.Second)) {
			t.Errorf("cap %ds: expiry %v is past the cap", tc.capSeconds, s.expiry)
		}
	}
}

// TestServer_SessionTTLZeroIsMaximum pins that the server honors
// sessionTTL: 0 as the longest session, in the cookie it hands the browser.
func TestServer_SessionTTLZeroIsMaximum(t *testing.T) {
	cfg := formLoginConfig("secret")
	zero, noCap := 0, 0
	cfg.Security.Auth.SessionTTL = &zero
	cfg.Security.Auth.SessionMaxLifetime = &noCap
	sa := newSessionAuth(cfg)

	c := sa.cookie(httptest.NewRequest(http.MethodPost, "/ui/login", nil), sa.start("secret"))
	if c.MaxAge != config.MaxSessionTTL {
		t.Errorf("cookie Max-Age = %d, want %d", c.MaxAge, config.MaxSessionTTL)
	}
}
