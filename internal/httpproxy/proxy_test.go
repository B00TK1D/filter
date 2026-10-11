package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHTTPForward(t *testing.T) {
	var gotHost, gotMethod, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotMethod, gotPath = r.Host, r.Method, r.URL.RequestURI()
		w.Header().Set("X-Upstream", "yes")
		fmt.Fprint(w, "hello from upstream")
	}))
	defer upstream.Close()
	p := testProxy(t, nil, nil)
	upPort := portOf(t, upstream.URL)

	req, err := http.NewRequest(http.MethodGet, "http://"+p.HTTPAddr().String()+"/path?q=1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = net.JoinHostPort("allowed.test", upPort)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "hello from upstream" {
		t.Fatalf("body = %q", body)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Error("upstream response header not preserved")
	}
	if gotMethod != http.MethodGet || gotPath != "/path?q=1" {
		t.Errorf("upstream saw method=%q path=%q", gotMethod, gotPath)
	}
	if gotHost != net.JoinHostPort("allowed.test", upPort) {
		t.Errorf("upstream Host = %q, want allowed.test:%s", gotHost, upPort)
	}
}

func TestHTTPAbsoluteForm(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "abs:%s", r.URL.Path)
	}))
	defer upstream.Close()
	p := testProxy(t, nil, nil)
	upPort := portOf(t, upstream.URL)

	req := fmt.Sprintf("GET http://allowed.test:%s/abs HTTP/1.1\r\nHost: allowed.test:%s\r\n\r\n", upPort, upPort)
	resp, body := doRaw(t, p.HTTPAddr().String(), req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%q", resp.StatusCode, body)
	}
	if body != "abs:/abs" {
		t.Fatalf("body = %q", body)
	}
}

func TestRequestHostAmbiguous(t *testing.T) {
	r := &http.Request{
		URL:  &url.URL{Scheme: "http", Host: "allowed.test"},
		Host: "evil.test",
	}
	if _, err := requestHost(r); err == nil {
		t.Fatal("expected error for mismatched absolute URI and Host")
	}
}

func TestRequestHostMissing(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/"}, Host: ""}
	if _, err := requestHost(r); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestRequestHostOriginForm(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/x"}, Host: "Example.COM:8080"}
	host, err := requestHost(r)
	if err != nil {
		t.Fatalf("requestHost: %v", err)
	}
	if host != "example.com" {
		t.Fatalf("host = %q, want example.com", host)
	}
}

func TestHTTPMissingHostRejected(t *testing.T) {
	p := testProxy(t, nil, nil)
	req := "GET / HTTP/1.1\r\n\r\n"
	resp, _ := doRaw(t, p.HTTPAddr().String(), req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHTTPBlockedNotForwarded(t *testing.T) {
	h := &countingHandler{fn: func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "should not happen") }}
	upstream := httptest.NewServer(h)
	defer upstream.Close()
	p := testProxy(t, nil, nil)
	upPort := portOf(t, upstream.URL)

	req, _ := http.NewRequest(http.MethodGet, "http://"+p.HTTPAddr().String()+"/", nil)
	req.Host = net.JoinHostPort("blocked.test", upPort)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if h.calls.Load() != 0 {
		t.Fatalf("upstream was called %d times for a blocked host", h.calls.Load())
	}
}

func TestHTTPBlockedSubdomain(t *testing.T) {
	p := testProxy(t, nil, nil)
	req := "GET / HTTP/1.1\r\nHost: deep.blocked.test\r\n\r\n"
	resp, _ := doRaw(t, p.HTTPAddr().String(), req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHTTPHopByHopStripped(t *testing.T) {
	var xfoo, conn string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfoo = r.Header.Get("X-Foo")
		conn = r.Header.Get("Connection")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	p := testProxy(t, nil, nil)
	upPort := portOf(t, upstream.URL)

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: allowed.test:%s\r\nConnection: X-Foo\r\nX-Foo: bar\r\n\r\n", upPort)
	resp, _ := doRaw(t, p.HTTPAddr().String(), req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if xfoo != "" {
		t.Errorf("hop-by-hop header X-Foo leaked upstream: %q", xfoo)
	}
	if conn != "" {
		t.Errorf("Connection header leaked upstream: %q", conn)
	}
}

func TestHTTPRedirectPreserved(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://allowed.test/new", http.StatusFound)
	}))
	defer upstream.Close()
	p := testProxy(t, nil, nil)
	upPort := portOf(t, upstream.URL)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, "http://"+p.HTTPAddr().String()+"/old", nil)
	req.Host = net.JoinHostPort("allowed.test", upPort)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://allowed.test/new" {
		t.Fatalf("location = %q", loc)
	}
}

func TestHTTPStreamingBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(w, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "|received:%d", n)
	}))
	defer upstream.Close()
	p := testProxy(t, nil, nil)
	upPort := portOf(t, upstream.URL)

	payload := strings.Repeat("abcdefgh", 128*1024) // 1 MiB
	req, _ := http.NewRequest(http.MethodPost, "http://"+p.HTTPAddr().String()+"/upload", strings.NewReader(payload))
	req.Host = net.JoinHostPort("allowed.test", upPort)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	want := fmt.Sprintf("|received:%d", len(payload))
	if !strings.HasSuffix(string(body), want) {
		t.Fatalf("body suffix = %q, want %q", string(body), want)
	}
}

func TestHTTPWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		line, _ := buf.ReadString('\n')
		buf.WriteString("echo:" + line)
		buf.Flush()
	}))
	defer upstream.Close()
	p := testProxy(t, nil, nil)
	upPort := portOf(t, upstream.URL)

	conn, err := net.DialTimeout("tcp", p.HTTPAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := fmt.Sprintf("GET /ws HTTP/1.1\r\nHost: allowed.test:%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", upPort)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status line = %q", status)
	}
	// Drain headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	echo, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echo != "echo:ping\n" {
		t.Fatalf("echo = %q", echo)
	}
}

func TestHTTPUpstreamFailure(t *testing.T) {
	// Nothing is listening on the resolved address: dial fails.
	p := testProxy(t, nil, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://"+p.HTTPAddr().String()+"/", nil)
	req.Host = net.JoinHostPort("allowed.test", "1") // port 1 is not listening
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}
