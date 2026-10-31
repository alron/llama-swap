package swaputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFilterFormLoginResponse(t *testing.T) {
	upstream := func(r *http.Request) *http.Response {
		return &http.Response{Header: http.Header{
			"Www-Authenticate": {`Basic realm="peer"`},
			"X-Frame-Options":  {"ALLOW-FROM http://example.com"},
			"Content-Type":     {"text/html"},
		}, Request: r}
	}

	browser := httptest.NewRequest(http.MethodGet, "/", nil)
	browser = browser.WithContext(WithFormLoginBrowser(browser.Context()))
	resp := upstream(browser)
	FilterFormLoginResponse(resp)
	for _, name := range []string{"WWW-Authenticate", "X-Frame-Options"} {
		if got := resp.Header.Get(name); got != "" {
			t.Errorf("marked request: %s = %q, want it removed", name, got)
		}
	}
	if resp.Header.Get("Content-Type") == "" {
		t.Error("marked request: unrelated header removed")
	}

	resp = upstream(httptest.NewRequest(http.MethodGet, "/", nil))
	FilterFormLoginResponse(resp)
	if resp.Header.Get("WWW-Authenticate") == "" || resp.Header.Get("X-Frame-Options") == "" {
		t.Error("unmarked request: headers removed; API clients and basic mode must get them as sent")
	}

	resp = upstream(nil)
	FilterFormLoginResponse(resp)
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("response without a request: headers removed")
	}
}
