package server

import (
	"crypto/hmac"
	"crypto/rand"
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
// the name is derived from the session secret and the API key the cookie was
// issued for.
//
// Browsers scope cookies by host but not by port or path, so llama-swap
// instances on one host share a cookie jar. Instances with different secrets
// or keys get differently named cookies, so logging in to one never
// overwrites another's login.
//
// The flip side: with the default per-process secret each restart changes
// the name, and the old cookie stays in the browser, unused, until it
// expires. Clearing it would mean clearing cookies this instance cannot tell
// apart from another instance's live login on the same host.
const sessionCookiePrefix = "llama_swap_session_"

// processSessionSecret signs sessions when security.auth.sessionSecret is not
// set. It lives as long as the process: a config reload builds a new Server
// but keeps this, so a reload keeps browsers logged in and a restart logs
// them out.
var processSessionSecret = func() []byte {
	secret := make([]byte, 32)
	rand.Read(secret)
	return secret
}()

// sessionAuth issues and checks the cookies behind security.auth.mode: form.
//
// Nothing is stored server side. A cookie carries when the browser logged in,
// when the session ends, and an HMAC of both keyed from the session secret
// and the API key used to log in. Without the secret a leaked cookie cannot
// be used to test guesses of the key. Removing the key from apiKeys or
// changing the secret ends the sessions issued with it; a single session
// cannot be revoked, and logging out only clears the browser's copy.
//
// A session in use is renewed (see renew), so ttl is really an idle timeout
// and maxLifetime caps how long one login can last in total.
type sessionAuth struct {
	secret []byte
	keys   []string
	// byCookie maps each key's cookie name back to the key.
	byCookie map[string]string
	ttl      time.Duration
	// maxLifetime is measured from login; 0 means no cap.
	maxLifetime time.Duration
	now         func() time.Time
}

// newSessionAuth returns nil unless the config enables form login, so callers
// can treat a nil value as basic mode.
func newSessionAuth(cfg config.Config) *sessionAuth {
	if !cfg.FormLoginEnabled() {
		return nil
	}
	auth := cfg.Security.Auth
	sa := &sessionAuth{
		secret:      processSessionSecret,
		keys:        cfg.RequiredAPIKeys,
		byCookie:    make(map[string]string, len(cfg.RequiredAPIKeys)),
		ttl:         time.Duration(auth.EffectiveSessionTTL()) * time.Second,
		maxLifetime: config.DefaultSessionMaxLifetime * time.Second,
		now:         time.Now,
	}
	if auth.SessionSecret != "" {
		sa.secret = []byte(auth.SessionSecret)
	}
	if auth.SessionMaxLifetime != nil {
		sa.maxLifetime = time.Duration(*auth.SessionMaxLifetime) * time.Second
	}
	for _, key := range cfg.RequiredAPIKeys {
		sa.byCookie[sa.cookieName(key)] = key
	}
	return sa
}

// derive returns a value bound to the session secret, key and purpose, so the
// cookie name and the signing key reveal nothing about each other or the key.
func (sa *sessionAuth) derive(purpose, key string) []byte {
	mac := hmac.New(sha256.New, sa.secret)
	mac.Write([]byte("llama-swap session " + purpose + "\x00" + key))
	return mac.Sum(nil)
}

// cookieName returns the cookie name for sessions issued for key.
func (sa *sessionAuth) cookieName(key string) string {
	return sessionCookiePrefix + hex.EncodeToString(sa.derive("cookie name", key)[:4])
}

// session is a login read from, or written to, a session cookie.
type session struct {
	key string
	// login is when the browser logged in. Renewal never moves it, so the
	// lifetime cap is measured from here.
	login  time.Time
	expiry time.Time
}

// payload is the signed part of a session cookie: login and expiry in Unix
// seconds.
func (s session) payload() string {
	return strconv.FormatInt(s.login.Unix(), 10) + "." + strconv.FormatInt(s.expiry.Unix(), 10)
}

// signature is the HMAC binding a session's payload to its key.
func (sa *sessionAuth) signature(s session) string {
	mac := hmac.New(sha256.New, sa.derive("signing key", s.key))
	mac.Write([]byte(s.payload()))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// start returns a new session for key, beginning now.
func (sa *sessionAuth) start(key string) session {
	now := sa.now()
	return session{key: key, login: now, expiry: sa.expiryFrom(now, now)}
}

// expiryFrom returns when a session that began at login ends if last used at
// now: one ttl later, but no later than the lifetime cap.
func (sa *sessionAuth) expiryFrom(login, now time.Time) time.Time {
	expiry := now.Add(sa.ttl)
	if sa.maxLifetime > 0 {
		if limit := login.Add(sa.maxLifetime); expiry.After(limit) {
			expiry = limit
		}
	}
	// The cookie stores whole seconds; match it so a session compares
	// equal to itself after a round trip.
	return time.Unix(expiry.Unix(), 0)
}

// renew extends s to a full ttl from now, so a browser stays logged in for
// ttl after the last thing its user did. It is only called for activity (see
// isActivity), which is rare enough that setting a cookie each time costs
// nothing. The cap stops a session, stolen or not, from being kept alive
// forever. It reports whether s changed.
func (sa *sessionAuth) renew(s session) (session, bool) {
	expiry := sa.expiryFrom(s.login, sa.now())
	if !expiry.After(s.expiry) {
		return s, false
	}
	s.expiry = expiry
	return s, true
}

// cookie returns the cookie carrying s.
func (sa *sessionAuth) cookie(r *http.Request, s session) *http.Cookie {
	return &http.Cookie{
		Name:     sa.cookieName(s.key),
		Value:    s.payload() + "." + sa.signature(s),
		Path:     "/",
		MaxAge:   max(int(s.expiry.Unix()-sa.now().Unix()), 1),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   requestIsHTTPS(r),
	}
}

// parse returns the session in c, and whether c carries an unexpired session
// for one of the configured keys at all.
func (sa *sessionAuth) parse(c *http.Cookie) (session, bool) {
	key, ok := sa.byCookie[c.Name]
	if !ok {
		return session{}, false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return session{}, false
	}
	login, err1 := strconv.ParseInt(parts[0], 10, 64)
	expiry, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || sa.now().Unix() >= expiry {
		return session{}, false
	}
	s := session{key: key, login: time.Unix(login, 0), expiry: time.Unix(expiry, 0)}
	if !hmac.Equal([]byte(parts[2]), []byte(sa.signature(s))) {
		return session{}, false
	}
	// Apply the cap as configured now rather than as it was when the cookie
	// was issued, so lowering sessionMaxLifetime takes effect at once.
	if sa.maxLifetime > 0 {
		if limit := s.login.Add(sa.maxLifetime); limit.Before(s.expiry) {
			s.expiry = limit
		}
	}
	if !sa.now().Before(s.expiry) {
		return session{}, false
	}
	return s, true
}

// validCookie reports whether c carries an unexpired session for one of the
// configured keys.
func (sa *sessionAuth) validCookie(c *http.Cookie) bool {
	_, ok := sa.parse(c)
	return ok
}

// sessionState is what a request's session cookie amounts to.
type sessionState int

const (
	// sessionNone means no valid session cookie.
	sessionNone sessionState = iota
	// sessionValid means a valid session cookie on a request it may
	// authenticate.
	sessionValid
	// sessionRefused means a valid session cookie on a request that did not
	// come from this llama-swap's own pages, such as one a page on another
	// site or port made the browser send.
	sessionRefused
)

// check reports what r's session cookie amounts to, see
// sessionRequestAllowed, and the session itself when it is valid.
func (sa *sessionAuth) check(r *http.Request) (sessionState, session) {
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, sessionCookiePrefix) {
			continue
		}
		if s, ok := sa.parse(c); ok {
			if sessionRequestAllowed(r) {
				return sessionValid, s
			}
			return sessionRefused, s
		}
	}
	return sessionNone, session{}
}

// sessionRequestAllowed reports whether r may authenticate with the session
// cookie, which is the cross-site request forgery defence for form login.
//
// Browsers attach cookies to requests other pages trigger, and SameSite does
// not separate ports: a page on another port of the same host counts as same
// site. So the cookie only counts on requests made by this llama-swap's own
// pages, plus top-level page loads, so a link from a dashboard on another
// site or port still opens the UI. Header credentials are unaffected; a page
// cannot make a browser attach those.
func sessionRequestAllowed(r *http.Request) bool {
	return sameOriginRequest(r) || isTopLevelPageLoad(r)
}

// sameOriginRequest reports whether r came from a page this llama-swap served,
// or was started by the user, such as by typing the address.
//
// Browsers only send Sec-Fetch-Site to HTTPS and localhost addresses. Over
// plain HTTP to any other address the page that made the request is read
// from Origin, or from Referer when the browser leaves Origin out, as it does
// on same-origin GETs. A request carrying neither is refused, because a page
// can strip both from the requests it makes (referrerpolicy="no-referrer").
func sameOriginRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
		source := r.Header.Get("Origin")
		if source == "" {
			source = r.Header.Get("Referer")
		}
		u, err := url.Parse(source)
		return err == nil && u.Host != "" && isOwnHost(r, u.Host)
	default:
		return false
	}
}

// isOwnHost reports whether host, taken from Origin or Referer, names this
// llama-swap as the browser reached it. Behind a reverse proxy that rewrites
// Host, the browser's host arrives in X-Forwarded-Host. Trusting that header
// is safe here: a page cannot set it on the requests it makes a browser send.
func isOwnHost(r *http.Request, host string) bool {
	if strings.EqualFold(host, r.Host) {
		return true
	}
	forwarded, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Host"), ",")
	forwarded = strings.TrimSpace(forwarded)
	return forwarded != "" && strings.EqualFold(host, forwarded)
}

// isTopLevelPageLoad reports whether r is the browser loading a page in its
// own tab. Without Fetch Metadata, over plain HTTP, a page loading in a frame
// looks the same and is let through here too. Framing is still refused: the
// auth middleware sends frame-ancestors 'self' and X-Frame-Options:
// SAMEORIGIN on every response to a browser, which browsers enforce over
// plain HTTP as well, so another site's frame never displays the page.
func isTopLevelPageLoad(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Mode") != "" {
		return isPageLoad(r) && r.Header.Get("Sec-Fetch-Dest") == "document"
	}
	return isPageLoad(r)
}

// isActivity reports whether r is the person at the browser doing something,
// which renews their session: loading a page, or a request that changes
// something, such as sending a chat or unloading a model. A script's GET is
// not, whether it polls for status or holds open an event stream, so a tab
// left open on a page that polls, like llama-server's own UI, still logs out.
func isActivity(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return isPageLoad(r)
	default:
		return true
	}
}

// isPageLoad reports whether r is the browser loading a page, in a tab or a
// frame, rather than a script fetching data.
func isPageLoad(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	// Without Fetch Metadata a page load still asks for HTML.
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// isBrowserRequest reports whether r came from a browser. API clients such as
// curl and the OpenAI SDKs send no Sec-Fetch-*, Origin or Referer and no
// session cookie. The UI's own requests over plain HTTP carry no Sec-Fetch-*
// either, but do carry a Referer.
func isBrowserRequest(r *http.Request) bool {
	h := r.Header
	if h.Get("Sec-Fetch-Mode") != "" || h.Get("Origin") != "" || h.Get("Referer") != "" || isPageLoad(r) {
		return true
	}
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, sessionCookiePrefix) {
			return true
		}
	}
	return false
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
