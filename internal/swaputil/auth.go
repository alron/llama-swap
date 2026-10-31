package swaputil

import (
	"context"
	"net/http"
)

// LoginRequiredHeader marks llama-swap's own "log in" answers to a browser
// under security.auth.mode: form: the 401 a script's request gets and the
// redirect a page load gets. The UI goes to the login page when it sees it,
// and the peer proxy uses it to recognize a peer asking for a login.
const LoginRequiredHeader = "X-Llama-Swap-Login"

type formLoginBrowserKey struct{}

// WithFormLoginBrowser marks ctx as a browser request under form login, so
// proxied responses to it are filtered; see FilterFormLoginResponse.
func WithFormLoginBrowser(ctx context.Context) context.Context {
	return context.WithValue(ctx, formLoginBrowserKey{}, true)
}

// FilterFormLoginResponse removes from an upstream's or peer's response what
// form login replaces, when the request was marked by WithFormLoginBrowser:
//
//   - WWW-Authenticate, which a browser answers with its native Basic dialog.
//     An upstream's challenge is not one the browser's user could answer.
//   - X-Frame-Options, because llama-swap sets its own on every response to
//     a browser under form login, and two conflicting values would leave the
//     browser to pick one.
//
// Call it from httputil.ReverseProxy.ModifyResponse.
func FilterFormLoginResponse(resp *http.Response) {
	if resp.Request != nil && resp.Request.Context().Value(formLoginBrowserKey{}) != nil {
		resp.Header.Del("WWW-Authenticate")
		resp.Header.Del("X-Frame-Options")
	}
}
