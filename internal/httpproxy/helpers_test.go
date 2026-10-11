package httpproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"filterproxy/internal/logging"
	"filterproxy/internal/policy"
	"filterproxy/internal/tlsmitm"
)

type staticLookup map[string][]netip.Addr

func (s staticLookup) LookupHost(_ context.Context, host string) ([]netip.Addr, error) {
	if addrs, ok := s[host]; ok {
		return addrs, nil
	}
	return nil, fmt.Errorf("no such host: %s", host)
}

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(logging.Options{Level: "error", Writer: io.Discard})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

func newTestCA(t *testing.T) *tlsmitm.CA {
	t.Helper()
	ca, err := tlsmitm.LoadOrCreate(tlsmitm.CAOptions{
		DataDir:  filepath.Join(t.TempDir(), "ca"),
		Validity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	return ca
}

func newMatcher(t *testing.T) *policy.Matcher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(path, []byte("blocked.test\n"), 0o600); err != nil {
		t.Fatalf("blocklist: %v", err)
	}
	m, _, err := policy.New(path, "")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return m
}

// testProxy builds and starts a Proxy on ephemeral ports with a static
// resolver that maps allowed.test to loopback.
func testProxy(t *testing.T, ca *tlsmitm.CA, mut func(*Options)) *Proxy {
	t.Helper()
	if ca == nil {
		ca = newTestCA(t)
	}
	certs := tlsmitm.NewCertCache(ca, 64, time.Hour)
	opts := Options{
		HTTPListen:            "127.0.0.1:0",
		HTTPSListen:           "127.0.0.1:0",
		ALPN:                  []string{"h2", "http/1.1"},
		DialTimeout:           3 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ReadHeaderTimeout:     5 * time.Second,
		IdleTimeout:           30 * time.Second,
		MaxHeaderBytes:        1 << 16,
		MaxConns:              256,
		ShutdownTimeout:       3 * time.Second,
		UnknownSNI:            "reject",
		Lookup: staticLookup{
			"allowed.test":       {mustAddr(t, "127.0.0.1")},
			"sub.allowed.test":   {mustAddr(t, "127.0.0.1")},
			"blocked.test":       {mustAddr(t, "127.0.0.1")},
			"blocked2.test":      {mustAddr(t, "127.0.0.1")},
			"upstream-fail.test": {mustAddr(t, "127.0.0.1")},
		},
	}
	if mut != nil {
		mut(&opts)
	}
	p, err := New(opts, newMatcher(t), testLogger(t), certs)
	if err != nil {
		t.Fatalf("New proxy: %v", err)
	}
	if err := p.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	p.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	return p
}

func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u.Port()
}

// doRaw sends raw bytes to addr and parses the HTTP response.
func doRaw(t *testing.T, addr, request string) (*http.Response, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

type countingHandler struct {
	calls atomic.Int64
	fn    http.HandlerFunc
}

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.calls.Add(1)
	h.fn(w, r)
}
