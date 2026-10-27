package server

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/mostlygeek/llama-swap/internal/chain"
	"github.com/mostlygeek/llama-swap/internal/config"
	"github.com/mostlygeek/llama-swap/internal/swaputil"
)

// CreateAuthMiddleware returns middleware that validates API keys when the
// config declares any. It accepts the key via Authorization: Bearer,
// Authorization: Basic (password field), or x-api-key. When no keys are
// configured the middleware is a pass-through.
//
// With security.auth.mode: form, browsers log in through the login page
// instead: the session cookie it sets is accepted, a browser without one is
// sent to that page (or gets a bare 401 for a script's request), and Basic
// auth never shows up in a browser. API clients keep every way of sending a
// key, Basic included, and still get the challenge.
func CreateAuthMiddleware(cfg config.Config) chain.Middleware {
	return createAuthMiddleware(cfg.RequiredAPIKeys, newSessionAuth(cfg), sessionRenews)
}

// sessionUse is how a route treats the form login session.
type sessionUse int

const (
	// sessionRenews accepts the session cookie, and a request counts as the
	// browser being in use, which renews the session.
	sessionRenews sessionUse = iota
	// sessionWatches accepts the session cookie without renewing it. Streams
	// that only watch, such as the UI's event stream, use it so an idle open
	// tab still logs out.
	sessionWatches
	// sessionIgnored accepts API keys only, for routes a page on another
	// site could trigger with a plain GET (GET /unload).
	sessionIgnored
)

// createAuthMiddleware is CreateAuthMiddleware with the session check passed
// in, so routes can share one and choose how they treat it. A nil sessions
// means basic mode.
//
// A request authenticated only by the cookie ends when the session does, so
// a long-lived one such as the event stream cannot outlast it. The UI notices
// the stream close and goes to the login page.
func createAuthMiddleware(keys []string, sessions *sessionAuth, use sessionUse) chain.Middleware {
	return func(next http.Handler) http.Handler {
		if len(keys) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			form := sessions != nil
			browser := form && isBrowserRequest(r)

			provided := swaputil.ExtractAPIKey(r)
			if browser {
				// A browser re-sends Basic credentials it cached from the
				// native dialog, perhaps from before form mode was enabled,
				// which would keep it logged in after logging out. In form
				// mode a browser logs in through the form; Bearer and
				// x-api-key are always sent on purpose, so they still count.
				provided = deliberateAPIKey(r)
			}
			_, valid := matchAPIKey(keys, provided)
			if browser {
				r = r.WithContext(swaputil.WithoutAuthChallenge(r.Context()))
			}

			state, sess := sessionNone, session{}
			if form && use != sessionIgnored {
				state, sess = sessions.check(r)
			}
			// Strip in every mode: a cookie left over from form mode is no
			// use to an upstream or peer.
			stripSessionCookies(r.Header)

			switch {
			case valid:
				next.ServeHTTP(w, r)
			case state == sessionValid:
				if renewed, ok := sessions.renew(sess); ok && use == sessionRenews {
					sess = renewed
					http.SetCookie(w, sessions.cookie(r, sess))
				}
				ctx, cancel := context.WithDeadline(r.Context(), sess.expiry)
				defer cancel()
				next.ServeHTTP(w, r.WithContext(ctx))
			case state == sessionRefused:
				// 403, not 401: the browser is logged in, and a 401 would send
				// the UI back to the login page in a loop.
				swaputil.SendResponse(w, r, http.StatusForbidden, "forbidden: the request did not come from this llama-swap's own pages")
			case browser && deliberateAPIKey(r) != "":
				// A request that sent a key is a client, not a user who needs
				// the login page. That includes another llama-swap proxying a
				// browser's page load here with a wrong peer key, where a
				// redirect would loop through its own login page.
				swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: invalid API key")
			case browser && use == sessionIgnored:
				// The login page would only send the browser back here, where
				// the session does not count, in a loop.
				swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: this endpoint takes an API key in the Authorization or x-api-key header")
			case browser:
				// No WWW-Authenticate here: it would bring back the browser's
				// native dialog that form mode replaces.
				// Marks this as llama-swap's own "log in" answer, so the UI
				// can tell it from a 401 an upstream or peer passes through,
				// and a llama-swap proxying here as a peer can tell it apart.
				w.Header().Set(swaputil.LoginRequiredHeader, "required")
				if isPageLoad(r) {
					redirectRelative(w, loginRedirect(r), http.StatusSeeOther)
					return
				}
				swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: log in or provide an API key")
			default:
				w.Header().Set("WWW-Authenticate", `Basic realm="llama-swap"`)
				swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: invalid or missing API key")
			}
		})
	}
}

// deliberateAPIKey is swaputil.ExtractAPIKey without Basic auth: the key from
// Authorization: Bearer, or else from x-api-key.
func deliberateAPIKey(r *http.Request) string {
	if scheme, credentials, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "bearer") {
		return credentials
	}
	return r.Header.Get("x-api-key")
}

// matchAPIKey returns the configured key equal to provided, comparing in
// constant time so response timing does not reveal how much of a guess was
// right.
func matchAPIKey(keys []string, provided string) (string, bool) {
	if provided == "" {
		return "", false
	}
	for _, key := range keys {
		if subtle.ConstantTimeCompare([]byte(provided), []byte(key)) == 1 {
			return key, true
		}
	}
	return "", false
}

// CreateRequestContextMiddleware returns middleware that extracts model and
// auth info from the request into the context. Requests where no model can be
// identified are rejected with a 404, and bodies over the size cap with a 413.
//
// JSON and multipart bodies without a Content-Length are first read here, so
// this is where their size cap is usually hit.
func CreateRequestContextMiddleware(cfg config.Config) chain.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = markInflightStart(r)
			data, err := swaputil.FetchContext(r, cfg)
			if err != nil {
				if bodyErr := bodyTooLargeFrom(err); bodyErr != nil {
					swaputil.SendResponse(w, r, bodyErr.status, bodyErr.message)
					return
				}
				swaputil.SendError(w, r, swaputil.ErrNoModelInContext)
				return
			}
			_ = data
			next.ServeHTTP(w, r)
		})
	}
}
