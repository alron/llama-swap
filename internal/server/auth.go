package server

import (
	"crypto/subtle"
	"net/http"

	"github.com/mostlygeek/llama-swap/internal/chain"
	"github.com/mostlygeek/llama-swap/internal/config"
	"github.com/mostlygeek/llama-swap/internal/swaputil"
)

// CreateAuthMiddleware returns middleware that validates API keys when the
// config declares any. It accepts the key via Authorization: Bearer,
// Authorization: Basic (password field), or x-api-key. When no keys are
// configured the middleware is a pass-through.
//
// With security.auth.mode: form it also accepts the session cookie set by the
// login page, and a browser without credentials is sent to that page (or gets
// a bare 401 for a script's request) instead of a Basic challenge. API
// clients still get the challenge, so their behaviour does not depend on the
// mode.
func CreateAuthMiddleware(cfg config.Config) chain.Middleware {
	keys := cfg.RequiredAPIKeys
	sessions := newSessionAuth(cfg)
	return func(next http.Handler) http.Handler {
		if len(keys) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, valid := matchAPIKey(keys, swaputil.ExtractAPIKey(r))
			if sessions != nil {
				valid = valid || sessions.authenticated(r)
				stripSessionCookies(r.Header)
			}

			if !valid {
				if sessions != nil && isBrowserRequest(r) {
					// No WWW-Authenticate here: it would bring back the
					// browser's native dialog that form mode replaces.
					if isPageLoad(r) {
						redirectRelative(w, loginRedirect(r), http.StatusSeeOther)
						return
					}
					swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: log in or provide an API key")
					return
				}
				w.Header().Set("WWW-Authenticate", `Basic realm="llama-swap"`)
				swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: invalid or missing API key")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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
