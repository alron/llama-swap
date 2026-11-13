package process

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mostlygeek/llama-swap/internal/config"
	"github.com/mostlygeek/llama-swap/internal/hint"
)

// TestProcessCommand_ProxyApiKey pins that proxyApiKey reaches the upstream on
// every request llama-swap makes to it: the health check, upstream detection
// and proxied client requests, whose own key is replaced. The fake upstream is
// a vLLM started with --api-key that is strict on every path, so a request
// missing the key anywhere fails the test.
func TestProcessCommand_ProxyApiKey(t *testing.T) {
	skipIfNoSimpleResponder(t)

	const key = "upstream-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key || len(r.Header.Values("x-api-key")) != 1 || r.Header.Get("x-api-key") != key {
			http.Error(w, "invalid api key", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"object":"list","data":[{"id":%q,"object":"model","owned_by":"vllm","max_model_len":8192}]}`, t.Name())
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[]}`))
		}
	}))
	t.Cleanup(upstream.Close)

	cmd, _ := simpleResponderCmd(t, "-silent")
	p := newProcessCommand(t, config.ModelConfig{
		Cmd:                cmd,
		Proxy:              upstream.URL,
		CheckEndpoint:      "/health",
		HealthCheckTimeout: 10,
		ProxyApiKey:        key,
	})

	// Ready only if the health check carried the key.
	_ = runAsync(t, p)
	// Detection reads /v1/models before the process is marked ready.
	if u := p.Status().Upstream; u != hint.VLLM {
		t.Errorf("Status().Upstream = %q, want vllm: detection did not send the key", u)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	req.SetBasicAuth("", "client-key")
	req.Header.Set("x-api-key", "client-key")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("proxied request: status = %d, body = %q; want 200 with the client's key replaced", w.Code, w.Body.String())
	}

	// The reverse proxy drops headers named in Connection as hop-by-hop. That
	// must not take the upstream's key with them.
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Connection", "Authorization, x-api-key")
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Connection: Authorization: status = %d, body = %q; want 200 with the key still sent", w.Code, w.Body.String())
	}
}

// TestProcessCommand_ProxyApiKeyWebsocket pins that a websocket upgrade, such
// as the Playground's /v1/realtime, carries the upstream's key and still
// becomes a two-way connection through the wrapped transport.
func TestProcessCommand_ProxyApiKeyWebsocket(t *testing.T) {
	skipIfNoSimpleResponder(t)

	const key = "upstream-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key {
			http.Error(w, "invalid api key", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Upgrade") != "websocket" {
			// /health, and the upstream detection that runs before ready.
			w.WriteHeader(http.StatusOK)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(rw, buf); err == nil {
			_, _ = rw.Write(buf)
			_ = rw.Flush()
		}
	}))
	t.Cleanup(upstream.Close)

	cmd, _ := simpleResponderCmd(t, "-silent")
	p := newProcessCommand(t, config.ModelConfig{
		Cmd:                cmd,
		Proxy:              upstream.URL,
		CheckEndpoint:      "/health",
		HealthCheckTimeout: 10,
		ProxyApiKey:        key,
	})
	_ = runAsync(t, p)

	// A real server in front, since an upgrade needs a connection to hijack.
	front := httptest.NewServer(p)
	t.Cleanup(front.Close)
	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testReturnTimeout))

	_, _ = io.WriteString(conn, "GET /v1/realtime HTTP/1.1\r\nHost: llama-swap\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	_, _ = io.WriteString(conn, "ping")
	echo := make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "ping" {
		t.Errorf("echo = %q, err = %v; want the upgraded connection to carry data both ways", echo, err)
	}
}

// TestProcessCommand_ProxyApiKeyUnset pins that without proxyApiKey the
// client's credentials still reach the upstream untouched.
func TestProcessCommand_ProxyApiKeyUnset(t *testing.T) {
	skipIfNoSimpleResponder(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = io.WriteString(w, r.Header.Get("Authorization")+"|"+r.Header.Get("x-api-key"))
	}))
	t.Cleanup(upstream.Close)

	cmd, _ := simpleResponderCmd(t, "-silent")
	p := newProcessCommand(t, config.ModelConfig{
		Cmd:                cmd,
		Proxy:              upstream.URL,
		CheckEndpoint:      "/health",
		HealthCheckTimeout: 10,
	})
	_ = runAsync(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer client-key")
	req.Header.Set("x-api-key", "client-key")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if got, want := w.Body.String(), "Bearer client-key|client-key"; got != want {
		t.Errorf("upstream saw %q, want the client's own %q", got, want)
	}
}
