package arcjet

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestDefaultClientHonorsProxyEnv verifies that when Config.HTTPClient is nil,
// Arcjet RPCs are routed through the proxy named by the standard HTTPS_PROXY
// environment variable. The Go standard library's http.DefaultTransport sets
// Proxy: http.ProxyFromEnvironment, so HTTP_PROXY, HTTPS_PROXY, and NO_PROXY
// (plus their lowercase variants) are honored automatically — matching the
// outbound-proxy support added to arcjet-js in PR #6089.
func TestDefaultClientHonorsProxyEnv(t *testing.T) {
	// A minimal HTTP CONNECT proxy. It records the CONNECT target host and
	// closes the connection, which is enough to prove the client dialed us
	// instead of the origin. The client then fails open, which we ignore.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	connectCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reqLine, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		// e.g. "CONNECT decide.arcjet.test:443 HTTP/1.1"
		fields := strings.Fields(reqLine)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "CONNECT") {
			connectCh <- fields[1]
		}
	}()

	// http.ProxyFromEnvironment reads these once and caches them. No other
	// test in this package exercises the default transport (they all inject a
	// custom RoundTripper), so this test gets a fresh read.
	t.Setenv("HTTPS_PROXY", "http://"+ln.Addr().String())
	t.Setenv("HTTP_PROXY", "http://"+ln.Addr().String())
	t.Setenv("NO_PROXY", "")

	client, err := NewClient(Config{
		Key:     "ajkey_test",
		BaseURL: "https://decide.arcjet.test",
		// HTTPClient intentionally nil: exercise the http.DefaultClient path.
		Rules: []Rule{Shield(ShieldOptions{Mode: ModeLive})},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := httptestNewProxyRequest()
	// The decision fails open because our fake proxy closes the tunnel; we
	// only care that the request was routed through the proxy.
	_, _ = client.Protect(ctx, req)

	select {
	case target := <-connectCh:
		if target != "decide.arcjet.test:443" {
			t.Fatalf("proxy received CONNECT for %q, want decide.arcjet.test:443", target)
		}
	case <-ctx.Done():
		t.Fatal("proxy was never contacted; HTTPS_PROXY was not honored by the default client")
	}
}

func httptestNewProxyRequest() *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/api", http.NoBody)
	req.RemoteAddr = "203.0.113.10:4567"
	req.Header.Set("User-Agent", "go-test")
	return req
}
