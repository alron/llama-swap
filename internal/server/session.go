package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mostlygeek/llama-swap/internal/config"
)

// sessionCookiePrefix starts the name of every form login cookie. The rest of
// the name is a fingerprint of the API key the cookie was issued for.
//
// Browsers scope cookies by host but not by port or path, so llama-swap
// instances on one host share a cookie jar. Naming the cookie after its key
// lets instances that share a key share the login, while instances with
// different keys keep separate cookies instead of overwriting each other's.
const sessionCookiePrefix = "llama_swap_session_"

// sessionAuth issues and checks the cookies behind security.auth.mode: form.
//
// Nothing is stored server side. A cookie carries its own expiry and an HMAC
// of that expiry keyed with the API key used to log in, so sessions survive
// config reloads and restarts, and removing a key from apiKeys ends every
// session issued for it. The flip side is that a single session cannot be
// revoked; logging out only clears the browser's copy.
type sessionAuth struct {
	keys []string
	// byCookie maps each key's cookie name back to the key.
	byCookie map[string]string
	ttl      time.Duration
	now      func() time.Time
}

// newSessionAuth returns nil unless the config enables form login, so callers
// can treat a nil value as basic mode.
func newSessionAuth(cfg config.Config) *sessionAuth {
	if !cfg.FormLoginEnabled() {
		return nil
	}
	sa := &sessionAuth{
		keys:     cfg.RequiredAPIKeys,
		byCookie: make(map[string]string, len(cfg.RequiredAPIKeys)),
		ttl:      time.Duration(cfg.Security.Auth.SessionTTL) * time.Second,
		now:      time.Now,
	}
	if sa.ttl <= 0 {
		sa.ttl = config.DefaultSessionTTL * time.Second
	}
	for _, key := range cfg.RequiredAPIKeys {
		sa.byCookie[sessionCookieName(key)] = key
	}
	return sa
}

// sessionCookieName returns the cookie name for sessions issued for key. The
// fingerprint is a truncated hash, which reveals nothing about the key that
// the cookie's own HMAC does not already.
func sessionCookieName(key string) string {
	sum := sha256.Sum256([]byte("llama-swap session cookie\x00" + key))
	return sessionCookiePrefix + hex.EncodeToString(sum[:4])
}

// sessionSignature is the HMAC binding an expiry to key.
func sessionSignature(key string, expiry int64) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("llama-swap session\x00" + strconv.FormatInt(expiry, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// newCookie returns a session cookie for key, valid for the configured TTL.
func (sa *sessionAuth) newCookie(r *http.Request, key string) *http.Cookie {
	expiry := sa.now().Add(sa.ttl).Unix()
	return &http.Cookie{
		Name:     sessionCookieName(key),
		Value:    strconv.FormatInt(expiry, 10) + "." + sessionSignature(key, expiry),
		Path:     "/",
		MaxAge:   int(sa.ttl / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   requestIsHTTPS(r),
	}
}

// validCookie reports whether a cookie carries an unexpired session for one
// of the configured keys.
func (sa *sessionAuth) validCookie(c *http.Cookie) bool {
	key, ok := sa.byCookie[c.Name]
	if !ok {
		return false
	}
	expiryText, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	expiry, err := strconv.ParseInt(expiryText, 10, 64)
	if err != nil || sa.now().Unix() >= expiry {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(sessionSignature(key, expiry)))
}

// authenticated reports whether r carries a valid session cookie in a context
// where llama-swap honors it; see sessionRequestAllowed.
func (sa *sessionAuth) authenticated(r *http.Request) bool {
	if !sessionRequestAllowed(r) {
		return false
	}
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, sessionCookiePrefix) && sa.validCookie(c) {
			return true
		}
	}
	return false
}

// sessionRequestAllowed reports whether r may authenticate with the session
// cookie, which is the cross-site request forgery defence for form login.
//
// Browsers attach cookies to requests other pages trigger, and SameSite does
// not separate ports: a page on another port of the same host counts as same
// site. So the cookie is only honored for requests the UI itself makes
// (same-origin) or the user started (none), plus top-level page loads, so a
// link from a dashboard on another site or port still opens the UI. Header
// credentials are unaffected; a page cannot make a browser attach those.
func sessionRequestAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
		// A browser too old to send Sec-Fetch-Site (before 2023) still sends
		// Origin on cross-origin requests that can change state.
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host
	default:
		return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
			r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
			r.Header.Get("Sec-Fetch-Dest") == "document"
	}
}

// isPageLoad reports whether r is the browser loading a page rather than a
// script fetching data.
func isPageLoad(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	// Browsers without Sec-Fetch-* still ask for HTML when loading a page.
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// isBrowserRequest reports whether r came from a browser. Every browser has
// sent Sec-Fetch-Mode since 2023; API clients such as curl and the OpenAI
// SDKs send none of the Sec-Fetch-* headers.
func isBrowserRequest(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Mode") != "" || isPageLoad(r)
}

// requestIsHTTPS reports whether the browser reached llama-swap over HTTPS,
// either directly or through a TLS-terminating reverse proxy. It decides the
// cookie's Secure flag: always setting it would make browsers drop the cookie
// on plain-HTTP LAN setups, so login would silently never stick.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// stripSessionCookies removes llama-swap's session cookies from a request's
// Cookie header and keeps any others, which may belong to an upstream's own
// web UI. The session cookie is llama-swap's credential; upstreams and peers
// never need it.
func stripSessionCookies(h http.Header) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	stripped := false
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, sessionCookiePrefix) {
				stripped = true
				continue
			}
			if part != "" {
				kept = append(kept, part)
			}
		}
	}
	if !stripped {
		return
	}
	if len(kept) == 0 {
		h.Del("Cookie")
		return
	}
	h.Set("Cookie", strings.Join(kept, "; "))
}

// loginRedirect returns the URL of the login page relative to r, with r's own
// path as the page to return to afterwards.
//
// It is relative for the same reason as redirectRelative: a reverse proxy
// that strips a path prefix would lose the prefix from an absolute Location.
// Climbing one level per directory in r's path reaches the server root from
// wherever the browser is.
func loginRedirect(r *http.Request) string {
	p := r.URL.EscapedPath()
	next := p
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	up := strings.Repeat("../", max(strings.Count(p, "/")-1, 0))
	return up + "ui/login?next=" + url.QueryEscape(next)
}

// loginReturnPath turns the login form's next value, a path on this server,
// into a URL relative to the login page at <prefix>/ui/login. Anything that
// is not a plain server path falls back to the UI, so the parameter cannot be
// used to send the browser to another site.
func loginReturnPath(next string) string {
	const ui = "./"
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n\t") {
		return ui
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ui
	}
	return "../" + strings.TrimPrefix(next, "/")
}
