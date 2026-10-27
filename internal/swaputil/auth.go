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

type noAuthChallengeKey struct{}

// WithoutAuthChallenge marks ctx as a browser request under form login, so
// proxied responses to it lose WWW-Authenticate; see StripAuthChallenge.
func WithoutAuthChallenge(ctx context.Context) context.Context {
	return context.WithValue(ctx, noAuthChallengeKey{}, true)
}

// StripAuthChallenge deletes WWW-Authenticate from resp when its request was
// marked by WithoutAuthChallenge. A browser answers that header with its
// native Basic dialog, which form login replaces, and an upstream's or
// peer's challenge is not one the browser's user could answer anyway. Call
// it from httputil.ReverseProxy.ModifyResponse.
func StripAuthChallenge(resp *http.Response) {
	if resp.Request != nil && resp.Request.Context().Value(noAuthChallengeKey{}) != nil {
		resp.Header.Del("WWW-Authenticate")
	}
}
