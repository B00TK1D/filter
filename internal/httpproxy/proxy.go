// Package httpproxy implements the transparent HTTP request handler and the
// TLS-terminating HTTPS (MITM) listener.
package httpproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/netutil"

	"filterproxy/internal/intercept"
	"filterproxy/internal/logging"
	"filterproxy/internal/policy"
	"filterproxy/internal/resolver"
	"filterproxy/internal/tlsmitm"
)

// HostLookup resolves a hostname to addresses. *resolver.Resolver implements
// it; tests may provide their own.
type HostLookup interface {
	LookupHost(ctx context.Context, host string) ([]netip.Addr, error)
}

// Options configures the HTTP/HTTPS proxy.
type Options struct {
	HTTPListen            string
	HTTPSListen           string
	ALPN                  []string
	Upstream              []string
	UpstreamMark          int
	DialTimeout           time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	ReadHeaderTimeout     time.Duration
	IdleTimeout           time.Duration
	MaxHeaderBytes        int
	MaxConns              int
	ShutdownTimeout       time.Duration
	UnknownSNI            string
	// Lookup overrides upstream resolution. When nil a resolver is built from
	// Upstream.
	Lookup HostLookup
	// RootCAs optionally overrides the trust store used to verify upstream TLS
	// certificates. When nil the system roots are used.
	RootCAs *x509.CertPool
	// LocalAddrs are the proxy's own interception addresses, used to detect
	// when passthrough cannot determine an upstream destination.
	LocalAddrs []netip.Addr
}

// Proxy serves intercepted HTTP and HTTPS traffic.
type Proxy struct {
	opts      Options
	matcher   *policy.Matcher
	log       *logging.Logger
	lookup    HostLookup
	certs     *tlsmitm.CertCache
	dialer    *net.Dialer
	transport *http.Transport
	reverse   *httputil.ReverseProxy

	httpServer  *http.Server
	httpsServer *http.Server
	httpLn      net.Listener
	httpsLn     net.Listener
	serveErr    chan error
}

// New builds a Proxy.
func New(opts Options, matcher *policy.Matcher, logger *logging.Logger, certs *tlsmitm.CertCache) (*Proxy, error) {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.TLSHandshakeTimeout <= 0 {
		opts.TLSHandshakeTimeout = 10 * time.Second
	}
	if opts.ResponseHeaderTimeout <= 0 {
		opts.ResponseHeaderTimeout = 30 * time.Second
	}
	if opts.MaxHeaderBytes <= 0 {
		opts.MaxHeaderBytes = 1 << 16
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 1024
	}

	var lookup HostLookup
	if opts.Lookup != nil {
		lookup = opts.Lookup
	} else {
		res, err := resolver.New(opts.Upstream, opts.DialTimeout, opts.UpstreamMark)
		if err != nil {
			return nil, err
		}
		lookup = res
	}

	p := &Proxy{
		opts:    opts,
		matcher: matcher,
		log:     logger,
		lookup:  lookup,
		certs:   certs,
		dialer: &net.Dialer{
			Timeout: opts.DialTimeout,
			Control: intercept.MarkControl(opts.UpstreamMark),
		},
		serveErr: make(chan error, 2),
	}

	p.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           p.dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       opts.IdleTimeout,
		TLSHandshakeTimeout:   opts.TLSHandshakeTimeout,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    opts.RootCAs,
		},
	}
	p.reverse = p.newReverseProxy()

	if certs != nil {
		certs.SetAuthorizer(p.authorizeCertificate)
	}
	return p, nil
}

// newReverseProxy builds the ReverseProxy used for both HTTP and HTTPS.
func (p *Proxy) newReverseProxy() *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Transport:     p.transport,
		FlushInterval: 100 * time.Millisecond,
		Rewrite: func(pr *httputil.ProxyRequest) {
			scheme := "http"
			if pr.In.TLS != nil {
				scheme = "https"
			}
			host, port := upstreamTarget(pr.In, scheme)
			target := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}
			pr.SetURL(target)
			// Preserve the client-provided authority so virtual hosts match.
			pr.Out.Host = pr.In.Host
		},
		ErrorHandler: p.upstreamError,
		ErrorLog:     slog.NewLogLogger(p.log.Handler(), slog.LevelWarn),
	}
	return rp
}

// upstreamTarget returns the hostname and port to connect to for a request.
func upstreamTarget(r *http.Request, scheme string) (string, string) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	host := authority
	port := ""
	if h, p, err := net.SplitHostPort(authority); err == nil {
		host, port = h, p
	}
	host = tlsmitm.NormalizeHost(host)
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return host, port
}

// ServeHTTP handles an intercepted request.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method == http.MethodConnect {
		p.deny(w, r, http.StatusMethodNotAllowed, "CONNECT is not supported by transparent interception", "method", start)
		return
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	host, err := requestHost(r)
	if err != nil {
		p.deny(w, r, http.StatusBadRequest, err.Error(), "malformed", start)
		return
	}

	if scheme == "https" && r.TLS != nil {
		sni := tlsmitm.NormalizeHost(r.TLS.ServerName)
		if sni != "" && !strings.EqualFold(sni, host) {
			p.deny(w, r, http.StatusMisdirectedRequest,
				fmt.Sprintf("Host %q does not match TLS SNI %q", host, sni), "sni-mismatch", start)
			return
		}
		if sni != "" {
			host = sni
		}
	}

	res := p.matcher.Decide(host)
	if res.Decision == policy.Block {
		p.log.Info("request blocked",
			"event", "http_request", "client", clientIP(r), "scheme", scheme,
			"host", host, "method", r.Method, "path", p.log.URL(r),
			"action", "block", "reason", res.Reason,
			"latency_ms", millis(start))
		p.writeStatus(w, r, http.StatusForbidden)
		return
	}

	// Count request bytes in.
	cr := &countingReader{r: r.Body}
	r.Body = cr

	host2, port := upstreamTarget(r, scheme)
	rw := newResponseRecorder(w)
	p.reverse.ServeHTTP(rw, r)

	fields := []any{
		"event", "http_request", "client", clientIP(r), "scheme", scheme,
		"host", host2, "port", port, "method", r.Method, "path", p.log.URL(r),
		"action", "allow", "reason", res.Reason,
		"status", rw.statusCode(), "bytes_in", cr.n, "bytes_out", rw.bytes,
		"latency_ms", millis(start),
	}
	if rw.errored() {
		p.log.Warn("request failed", fields...)
	} else {
		p.log.Info("request forwarded", fields...)
	}
}

func (p *Proxy) deny(w http.ResponseWriter, r *http.Request, status int, reason, action string, start time.Time) {
	p.log.Info("request denied",
		"event", "http_request", "client", clientIP(r), "host", requestHostForLog(r),
		"method", r.Method, "path", p.log.URL(r), "action", action, "reason", reason,
		"status", status, "latency_ms", millis(start))
	p.writeStatus(w, r, status)
}

func (p *Proxy) writeStatus(w http.ResponseWriter, r *http.Request, status int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Blocked-By", "proxyd")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, http.StatusText(status)+"\n")
	}
}

// upstreamError is invoked by the ReverseProxy when the upstream call fails.
func (p *Proxy) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if rec, ok := w.(*responseRecorder); ok {
		rec.markError()
		if !rec.wroteHeader {
			rec.WriteHeader(http.StatusBadGateway)
		}
	} else {
		w.WriteHeader(http.StatusBadGateway)
	}
	p.log.Warn("upstream request failed",
		"event", "http_request", "client", clientIP(r), "host", requestHostForLog(r),
		"method", r.Method, "path", p.log.URL(r), "action", "error",
		"reason", "upstream", "error", err.Error())
}

// authorizeCertificate blocks certificate issuance for policy-blocked hosts.
func (p *Proxy) authorizeCertificate(host string) error {
	res := p.matcher.Decide(host)
	if res.Decision == policy.Block {
		p.log.Info("tls connection blocked",
			"event", "tls_handshake", "host", host, "action", "block", "reason", res.Reason)
		return fmt.Errorf("host %q blocked by policy (%s)", host, res.Reason)
	}
	return nil
}

// dialContext resolves the target host through configured upstream resolvers
// and dials the resulting addresses.
func (p *Proxy) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := p.lookup.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	var lastErr error
	for _, ip := range addrs {
		conn, err := p.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses for %s", host)
	}
	return nil, lastErr
}

// requestHost extracts and validates the target hostname from a request.
func requestHost(r *http.Request) (string, error) {
	var urlHost string
	if r.URL != nil && r.URL.IsAbs() {
		urlHost = tlsmitm.NormalizeHost(r.URL.Host)
	}
	headerHost := tlsmitm.NormalizeHost(r.Host)
	if r.URL != nil && r.URL.IsAbs() && r.Host != "" && urlHost != headerHost {
		return "", fmt.Errorf("ambiguous request: absolute URI host %q differs from Host header %q", r.URL.Host, r.Host)
	}
	host := headerHost
	if host == "" {
		host = urlHost
	}
	if host == "" {
		return "", errors.New("missing Host")
	}
	if strings.ContainsAny(host, " \t\r\n\x00") {
		return "", fmt.Errorf("invalid host %q", host)
	}
	return host, nil
}

func requestHostForLog(r *http.Request) string {
	host, err := requestHost(r)
	if err != nil {
		return tlsmitm.NormalizeHost(r.Host)
	}
	return host
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return strings.Trim(host, "[]")
}

func millis(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

// countingReader counts bytes read from a request body.
type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error { return c.r.Close() }

// Listen binds the HTTP and HTTPS listeners.
func (p *Proxy) Listen() error {
	httpLn, err := net.Listen("tcp", p.opts.HTTPListen)
	if err != nil {
		return fmt.Errorf("listen http %s: %w", p.opts.HTTPListen, err)
	}
	p.httpLn = netutil.LimitListener(httpLn, p.opts.MaxConns)
	p.httpServer = p.newHTTPServer()

	httpsLn, err := net.Listen("tcp", p.opts.HTTPSListen)
	if err != nil {
		p.httpLn.Close()
		return fmt.Errorf("listen https %s: %w", p.opts.HTTPSListen, err)
	}
	cfg := p.certs.TLSConfig(p.opts.ALPN)
	p.httpsServer = p.newHTTPServer()
	p.httpsServer.TLSConfig = cfg
	if err := http2.ConfigureServer(p.httpsServer, &http2.Server{}); err != nil {
		p.httpLn.Close()
		httpsLn.Close()
		return fmt.Errorf("configure http/2: %w", err)
	}
	p.httpsLn = &mitmListener{
		base:             netutil.LimitListener(httpsLn, p.opts.MaxConns),
		cfg:              cfg,
		log:              p.log,
		unknownSNI:       p.opts.UnknownSNI,
		handshakeTimeout: p.opts.TLSHandshakeTimeout,
		dialer:           p.dialer,
		localAddrs:       p.opts.LocalAddrs,
	}
	return nil
}

func (p *Proxy) newHTTPServer() *http.Server {
	return &http.Server{
		Handler:           p,
		ReadHeaderTimeout: p.opts.ReadHeaderTimeout,
		IdleTimeout:       p.opts.IdleTimeout,
		MaxHeaderBytes:    p.opts.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(p.log.Handler(), slog.LevelWarn),
	}
}

// HTTPAddr returns the bound HTTP address.
func (p *Proxy) HTTPAddr() net.Addr {
	if p.httpLn == nil {
		return nil
	}
	return p.httpLn.Addr()
}

// HTTPSAddr returns the bound HTTPS address.
func (p *Proxy) HTTPSAddr() net.Addr {
	if p.httpsLn == nil {
		return nil
	}
	return p.httpsLn.Addr()
}

// ServeErrors returns a channel reporting fatal serve errors.
func (p *Proxy) ServeErrors() <-chan error { return p.serveErr }

// Start begins serving HTTP and HTTPS.
func (p *Proxy) Start() {
	go func() {
		if err := p.httpServer.Serve(p.httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.serveErr <- fmt.Errorf("http server: %w", err)
		}
	}()
	go func() {
		if err := p.httpsServer.Serve(p.httpsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.serveErr <- fmt.Errorf("https server: %w", err)
		}
	}()
}

// Shutdown gracefully stops both servers.
func (p *Proxy) Shutdown(ctx context.Context) error {
	var errs []error
	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if p.httpsServer != nil {
		if err := p.httpsServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	p.transport.CloseIdleConnections()
	return errors.Join(errs...)
}
