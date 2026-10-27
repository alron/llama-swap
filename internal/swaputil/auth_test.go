package swaputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStripAuthChallenge(t *testing.T) {
	challenged := func(r *http.Request) *http.Response {
		return &http.Response{Header: http.Header{"Www-Authenticate": {`Basic realm="peer"`}}, Request: r}
	}

	browser := httptest.NewRequest(http.MethodGet, "/", nil)
	browser = browser.WithContext(WithoutAuthChallenge(browser.Context()))
	resp := challenged(browser)
	StripAuthChallenge(resp)
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("marked request: WWW-Authenticate = %q, want it removed", got)
	}

	resp = challenged(httptest.NewRequest(http.MethodGet, "/", nil))
	StripAuthChallenge(resp)
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("unmarked request: WWW-Authenticate removed; API clients must keep it")
	}

	resp = challenged(nil)
	StripAuthChallenge(resp)
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("response without a request: WWW-Authenticate removed")
	}
}
