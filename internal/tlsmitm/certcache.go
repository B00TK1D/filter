package tlsmitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// CertCache generates and caches leaf certificates signed by a CA.
type CertCache struct {
	ca           *CA
	leafValidity time.Duration
	max          int

	mu        sync.Mutex
	entries   map[string]*cacheEntry
	now       func() time.Time
	authorize func(host string) error
}

type cacheEntry struct {
	cert     *tls.Certificate
	expires  time.Time
	lastUsed time.Time
}

// NewCertCache creates a leaf certificate cache. max bounds the number of
// cached certificates; values <= 0 select a default.
func NewCertCache(ca *CA, max int, leafValidity time.Duration) *CertCache {
	if max <= 0 {
		max = 1024
	}
	if leafValidity <= 0 {
		leafValidity = 30 * 24 * time.Hour
	}
	return &CertCache{
		ca:           ca,
		leafValidity: leafValidity,
		max:          max,
		entries:      make(map[string]*cacheEntry),
		now:          time.Now,
	}
}

// SetAuthorizer installs a policy hook invoked before a certificate is issued.
// A non-nil error aborts the TLS handshake.
func (c *CertCache) SetAuthorizer(fn func(host string) error) {
	c.mu.Lock()
	c.authorize = fn
	c.mu.Unlock()
}

// NormalizeHost canonicalizes a hostname for certificate issuance and caching.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	// Drop an accidental port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	return strings.ToLower(host)
}

// Get returns a leaf certificate for host, generating and caching one on
// demand.
func (c *CertCache) Get(host string) (*tls.Certificate, error) {
	host = NormalizeHost(host)
	if host == "" {
		return nil, errors.New("cannot issue certificate for empty hostname")
	}

	c.mu.Lock()
	authorize := c.authorize
	c.mu.Unlock()
	if authorize != nil {
		if err := authorize(host); err != nil {
			return nil, err
		}
	}

	now := c.now()

	c.mu.Lock()
	if e, ok := c.entries[host]; ok && now.Before(e.expires) {
		e.lastUsed = now
		cert := e.cert
		c.mu.Unlock()
		return cert, nil
	}
	c.mu.Unlock()

	cert, expires, err := c.issue(host, now)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.evictLocked(now)
	c.entries[host] = &cacheEntry{cert: cert, expires: expires, lastUsed: now}
	c.mu.Unlock()
	return cert, nil
}

// Len returns the number of cached certificates.
func (c *CertCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Purge empties the cache.
func (c *CertCache) Purge() {
	c.mu.Lock()
	c.entries = make(map[string]*cacheEntry)
	c.mu.Unlock()
}

func (c *CertCache) evictLocked(now time.Time) {
	for host, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, host)
		}
	}
	for len(c.entries) >= c.max {
		var oldestHost string
		var oldest time.Time
		first := true
		for host, e := range c.entries {
			if first || e.lastUsed.Before(oldest) {
				oldestHost, oldest, first = host, e.lastUsed, false
			}
		}
		if first {
			return
		}
		delete(c.entries, oldestHost)
	}
}

func (c *CertCache) issue(host string, now time.Time) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate leaf key: %w", err)
	}

	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(c.leafValidity)
	// Never outlive the CA.
	if caExpiry := c.ca.cert.NotAfter.Add(-1 * time.Hour); caExpiry.Before(notAfter) {
		notAfter = caExpiry
	}
	expires := notAfter

	serial, err := randSerial()
	if err != nil {
		return nil, time.Time{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		tmpl.IPAddresses = []net.IP{addr.AsSlice()}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca.cert, key.Public(), c.ca.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign leaf certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, expires, nil
}

// TLSConfig returns a *tls.Config that issues leaf certificates based on SNI.
// It advertises the supplied ALPN protocols and requires TLS 1.2 or newer.
func (c *CertCache) TLSConfig(alpn []string) *tls.Config {
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: append([]string(nil), alpn...),
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				return nil, errors.New("no SNI provided")
			}
			return c.Get(host)
		},
	}
}
