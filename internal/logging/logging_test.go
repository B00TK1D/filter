package logging

import (
	"io"
	"net/http"
	"net/url"
	"testing"
)

func testLogger(t *testing.T, opts Options) *Logger {
	t.Helper()
	if opts.Writer == nil {
		opts.Writer = io.Discard
	}
	l, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestURLLoggingDisabledByDefault(t *testing.T) {
	l := testLogger(t, Options{Level: "info"})
	req := &http.Request{URL: &url.URL{Path: "/secret", RawQuery: "token=abc"}}
	if got := l.URL(req); got != "" {
		t.Errorf("URL = %q, want empty when URL logging disabled", got)
	}
}

func TestURLLoggingEnabled(t *testing.T) {
	l := testLogger(t, Options{Level: "info", LogURLs: true})
	req := &http.Request{URL: &url.URL{Path: "/secret", RawQuery: "token=abc"}}
	if got := l.URL(req); got != "/secret?token=abc" {
		t.Errorf("URL = %q", got)
	}
}

func TestPrivacyModeOverridesURLs(t *testing.T) {
	l := testLogger(t, Options{Level: "info", LogURLs: true, PrivacyMode: true})
	req := &http.Request{URL: &url.URL{Path: "/secret", RawQuery: "token=abc"}}
	if got := l.URL(req); got != "" {
		t.Errorf("URL = %q, want empty in privacy mode", got)
	}
}

func TestRedactedHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer sekret")
	h.Set("Cookie", "session=abc")
	h.Set("X-Custom", "visible")
	h.Set("Content-Length", "10")
	out := RedactedHeaders(h)
	if out["Authorization"][0] != "[redacted]" {
		t.Errorf("authorization not redacted: %v", out["Authorization"])
	}
	if out["Cookie"][0] != "[redacted]" {
		t.Errorf("cookie not redacted: %v", out["Cookie"])
	}
	if out["X-Custom"][0] != "visible" {
		t.Errorf("X-Custom lost: %v", out["X-Custom"])
	}
	if out["Content-Length"][0] != "10" {
		t.Errorf("Content-Length lost: %v", out["Content-Length"])
	}
}
