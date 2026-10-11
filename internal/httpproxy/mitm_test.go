package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"filterproxy/internal/tlsmitm"
)

// startUpstreamTLS starts an HTTPS server whose certificate is issued by ca for
// allowed.test, on an ephemeral loopback port.
func startUpstreamTLS(t *testing.T, ca *tlsmitm.CA, handler http.Handler) string {
	t.Helper()
	cert, err := tlsmitm.NewCertCache(ca, 4, time.Hour).Get("allowed.test")
	if err != nil {
		t.Fatalf("upstream cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	return port
}

// httpsClient returns a client that connects to the proxy's HTTPS listener but
// presents the requested hostname via TLS SNI and trusts ca.
func httpsClient(p *Proxy, ca *tlsmitm.CA, alpn []string) *http.Client {
	proxyAddr := p.HTTPSAddr().String()
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: len(alpn) == 0,
			TLSClientConfig: &tls.Config{
				RootCAs:    ca.CertPool(),
				NextProtos: alpn,
				MinVersion: tls.VersionTLS12,
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, proxyAddr)
			},
		},
	}
}

func TestHTTPSMITMForward(t *testing.T) {
	proxyCA := newTestCA(t)
	upstreamCA := newTestCA(t)
	var gotHost, gotPath string
	var gotTLS *tls.ConnectionState
	upPort := startUpstreamTLS(t, upstreamCA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.Path
		gotTLS = r.TLS
		w.Header().Set("X-Server", "upstream")
		fmt.Fprint(w, "secure hello")
	}))

	p := testProxy(t, proxyCA, func(o *Options) { o.RootCAs = upstreamCA.CertPool() })
	client := httpsClient(p, proxyCA, []string{"http/1.1"})
	resp, err := client.Get(fmt.Sprintf("https://allowed.test:%s/secure", upPort))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "secure hello" {
		t.Fatalf("body = %q", body)
	}
	if gotHost != "allowed.test:"+upPort {
		t.Errorf("upstream host = %q", gotHost)
	}
	if gotPath != "/secure" {
		t.Errorf("upstream path = %q", gotPath)
	}
	if gotTLS == nil || gotTLS.ServerName == "" {
		t.Errorf("upstream did not complete TLS")
	}
	// The proxy must have presented a certificate valid for allowed.test.
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("client did not receive a peer certificate")
	}
	if err := resp.TLS.PeerCertificates[0].VerifyHostname("allowed.test"); err != nil {
		t.Errorf("leaf certificate not valid for allowed.test: %v", err)
	}
}

func TestHTTPSMITMHTTP2(t *testing.T) {
	proxyCA := newTestCA(t)
	upstreamCA := newTestCA(t)
	upPort := startUpstreamTLS(t, upstreamCA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "h2 hello")
	}))
	p := testProxy(t, proxyCA, func(o *Options) { o.RootCAs = upstreamCA.CertPool() })
	client := httpsClient(p, proxyCA, nil) // allow h2 negotiation
	resp, err := client.Get(fmt.Sprintf("https://allowed.test:%s/h2", upPort))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s, want HTTP/2", resp.Proto)
	}
}

func TestHTTPSBlocked(t *testing.T) {
	proxyCA := newTestCA(t)
	upstreamCA := newTestCA(t)
	h := &countingHandler{fn: func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "nope") }}
	upPort := startUpstreamTLS(t, upstreamCA, h)

	p := testProxy(t, proxyCA, func(o *Options) { o.RootCAs = upstreamCA.CertPool() })
	client := httpsClient(p, proxyCA, []string{"http/1.1"})
	_, err := client.Get(fmt.Sprintf("https://blocked.test:%s/", upPort))
	if err == nil {
		t.Fatal("expected TLS handshake failure for blocked host")
	}
	if h.calls.Load() != 0 {
		t.Fatalf("upstream called %d times for blocked host", h.calls.Load())
	}
}

func TestHTTPSUpstreamTLSVerificationFailure(t *testing.T) {
	proxyCA := newTestCA(t)
	upstreamCA := newTestCA(t)
	upPort := startUpstreamTLS(t, upstreamCA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secret")
	}))
	// Proxy does not trust the upstream CA: verification must fail.
	p := testProxy(t, proxyCA, nil)
	client := httpsClient(p, proxyCA, []string{"http/1.1"})
	resp, err := client.Get(fmt.Sprintf("https://allowed.test:%s/", upPort))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestHTTPSUnknownSNIRejected(t *testing.T) {
	proxyCA := newTestCA(t)
	p := testProxy(t, proxyCA, nil)
	conn, err := tls.Dial("tcp", p.HTTPSAddr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // testing the proxy, not a server
		MinVersion:         tls.VersionTLS12,
	})
	if err == nil {
		conn.Close()
		t.Fatal("expected connection rejection when no SNI is present")
	}
}
