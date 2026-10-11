// Package config defines the proxy service configuration, defaults, loading and
// validation.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from YAML strings such as "3s".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// DNSConfig controls the DNS forwarder.
type DNSConfig struct {
	ListenUDP     string   `yaml:"listen_udp"`
	ListenTCP     string   `yaml:"listen_tcp"`
	Upstream      []string `yaml:"upstream"`
	InterceptIPv4 string   `yaml:"intercept_ipv4"`
	InterceptIPv6 string   `yaml:"intercept_ipv6"`
	IPv6Enabled   bool     `yaml:"ipv6_enabled"`
	// BlockMode is "nxdomain" (default) or "sinkhole".
	BlockMode string `yaml:"block_mode"`
	// SinkholeIPv4/SinkholeIPv6 are returned for blocked names when BlockMode
	// is "sinkhole". Defaults to a zero/unspecified address when empty.
	SinkholeIPv4 string `yaml:"sinkhole_ipv4"`
	SinkholeIPv6 string `yaml:"sinkhole_ipv6"`
	TTL          int    `yaml:"ttl"`
	// Timeout bounds a single upstream exchange.
	Timeout Duration `yaml:"timeout"`
	// QueryTimeout bounds the total handling time of a client query.
	QueryTimeout Duration `yaml:"query_timeout"`
	// MaxUDPSize is the advertised EDNS0 UDP payload size.
	MaxUDPSize int `yaml:"max_udp_size"`
}

// HTTPConfig controls the transparent HTTP listener.
type HTTPConfig struct {
	Listen string `yaml:"listen"`
}

// HTTPSConfig controls the transparent HTTPS (TLS MITM) listener.
type HTTPSConfig struct {
	Listen string `yaml:"listen"`
	// ALPN is the list of protocols advertised to intercepted clients.
	ALPN []string `yaml:"alpn"`
}

// PolicyConfig points at policy data and reload behaviour.
type PolicyConfig struct {
	Blocklist      string   `yaml:"blocklist"`
	Allowlist      string   `yaml:"allowlist"`
	ReloadInterval Duration `yaml:"reload_interval"`
}

// CAConfig controls the root CA and leaf certificate generation.
type CAConfig struct {
	DataDir       string   `yaml:"data_dir"`
	CertFile      string   `yaml:"cert_file"`
	KeyFile       string   `yaml:"key_file"`
	Validity      Duration `yaml:"validity"`
	LeafValidity  Duration `yaml:"leaf_validity"`
	LeafCacheSize int      `yaml:"leaf_cache_size"`
	// Regenerate deletes and recreates the root CA at startup. Development only.
	Regenerate bool `yaml:"regenerate"`
}

// CertPath returns the resolved root CA certificate path.
func (c CAConfig) CertPath() string {
	if c.CertFile != "" {
		return c.CertFile
	}
	return filepath.Join(c.DataDir, "rootCA.pem")
}

// KeyPath returns the resolved root CA private key path.
func (c CAConfig) KeyPath() string {
	if c.KeyFile != "" {
		return c.KeyFile
	}
	return filepath.Join(c.DataDir, "rootCA-key.pem")
}

// LoggingConfig controls structured logging.
type LoggingConfig struct {
	Level string `yaml:"level"`
	// Format is "json" (default) or "text".
	Format string `yaml:"format"`
	// Output is "" (stdout) or a file path.
	Output string `yaml:"output"`
	// LogURLs enables logging of full request paths and query strings.
	LogURLs bool `yaml:"log_urls"`
	// PrivacyMode reduces logged fields to hostnames and metadata only.
	PrivacyMode bool `yaml:"privacy_mode"`
}

// TLSConfig controls TLS interception behaviour.
type TLSConfig struct {
	// UnknownSNI is "reject" (default) or "passthrough".
	UnknownSNI string `yaml:"unknown_sni"`
}

// LimitsConfig bounds resource usage.
type LimitsConfig struct {
	MaxConns              int      `yaml:"max_conns"`
	MaxHeaderBytes        int      `yaml:"max_header_bytes"`
	ReadHeaderTimeout     Duration `yaml:"read_header_timeout"`
	IdleTimeout           Duration `yaml:"idle_timeout"`
	DialTimeout           Duration `yaml:"dial_timeout"`
	TLSHandshakeTimeout   Duration `yaml:"tls_handshake_timeout"`
	ResponseHeaderTimeout Duration `yaml:"response_header_timeout"`
	ShutdownTimeout       Duration `yaml:"shutdown_timeout"`
	// UpstreamMark, when non-zero, is applied as SO_MARK to proxy-originated
	// sockets so firewall rules can bypass interception for them.
	UpstreamMark int `yaml:"upstream_mark"`
}

// UDP443Mode enumerates the firewall-facing UDP/443 policy.
type UDP443Mode string

const (
	UDP443Allow  UDP443Mode = "allow"
	UDP443Reject UDP443Mode = "reject"
	UDP443Drop   UDP443Mode = "drop"
)

// UDP443Config documents the QUIC/HTTP3 handling policy. Enforcement is done by
// the deploy firewall scripts; this value is surfaced for logging and for the
// scripts to read.
type UDP443Config struct {
	Mode UDP443Mode `yaml:"mode"`
}

// ManagementConfig controls the health endpoints.
type ManagementConfig struct {
	Listen string `yaml:"listen"`
	// AllowNonLoopback must be set to listen on a non-loopback address.
	AllowNonLoopback bool `yaml:"allow_non_loopback"`
}

// Config is the top-level service configuration.
type Config struct {
	DNS        DNSConfig        `yaml:"dns"`
	HTTP       HTTPConfig       `yaml:"http"`
	HTTPS      HTTPSConfig      `yaml:"https"`
	Policy     PolicyConfig     `yaml:"policy"`
	CA         CAConfig         `yaml:"ca"`
	Logging    LoggingConfig    `yaml:"logging"`
	TLS        TLSConfig        `yaml:"tls"`
	Limits     LimitsConfig     `yaml:"limits"`
	UDP443     UDP443Config     `yaml:"udp443"`
	Management ManagementConfig `yaml:"management"`
}

// Default returns a configuration populated with safe defaults.
func Default() Config {
	return Config{
		DNS: DNSConfig{
			ListenUDP:     "127.0.0.1:5353",
			ListenTCP:     "127.0.0.1:5353",
			Upstream:      []string{"1.1.1.1:53", "9.9.9.9:53"},
			InterceptIPv4: "127.0.0.1",
			InterceptIPv6: "::1",
			IPv6Enabled:   false,
			BlockMode:     "nxdomain",
			TTL:           60,
			Timeout:       Duration(3 * time.Second),
			QueryTimeout:  Duration(5 * time.Second),
			MaxUDPSize:    1232,
		},
		HTTP:  HTTPConfig{Listen: "127.0.0.1:8080"},
		HTTPS: HTTPSConfig{Listen: "127.0.0.1:8443", ALPN: []string{"h2", "http/1.1"}},
		Policy: PolicyConfig{
			ReloadInterval: 0,
		},
		CA: CAConfig{
			DataDir:       "/var/lib/proxyd",
			Validity:      Duration(8760 * time.Hour), // 1 year
			LeafValidity:  Duration(720 * time.Hour),  // 30 days
			LeafCacheSize: 1024,
		},
		Logging: LoggingConfig{Level: "info", Format: "json"},
		TLS:     TLSConfig{UnknownSNI: "reject"},
		Limits: LimitsConfig{
			MaxConns:              1024,
			MaxHeaderBytes:        1 << 16,
			ReadHeaderTimeout:     Duration(10 * time.Second),
			IdleTimeout:           Duration(90 * time.Second),
			DialTimeout:           Duration(10 * time.Second),
			TLSHandshakeTimeout:   Duration(10 * time.Second),
			ResponseHeaderTimeout: Duration(30 * time.Second),
			ShutdownTimeout:       Duration(15 * time.Second),
			UpstreamMark:          0,
		},
		UDP443:     UDP443Config{Mode: UDP443Allow},
		Management: ManagementConfig{Listen: "127.0.0.1:9090"},
	}
}

// Load reads, defaults and validates configuration from path.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	def := Default()
	if c.DNS.ListenUDP == "" {
		c.DNS.ListenUDP = def.DNS.ListenUDP
	}
	if c.DNS.ListenTCP == "" {
		c.DNS.ListenTCP = def.DNS.ListenTCP
	}
	if len(c.DNS.Upstream) == 0 {
		c.DNS.Upstream = def.DNS.Upstream
	}
	if c.DNS.BlockMode == "" {
		c.DNS.BlockMode = def.DNS.BlockMode
	}
	if c.DNS.TTL == 0 {
		c.DNS.TTL = def.DNS.TTL
	}
	if c.DNS.Timeout == 0 {
		c.DNS.Timeout = def.DNS.Timeout
	}
	if c.DNS.QueryTimeout == 0 {
		c.DNS.QueryTimeout = def.DNS.QueryTimeout
	}
	if c.DNS.MaxUDPSize == 0 {
		c.DNS.MaxUDPSize = def.DNS.MaxUDPSize
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = def.HTTP.Listen
	}
	if c.HTTPS.Listen == "" {
		c.HTTPS.Listen = def.HTTPS.Listen
	}
	if len(c.HTTPS.ALPN) == 0 {
		c.HTTPS.ALPN = def.HTTPS.ALPN
	}
	if c.CA.DataDir == "" {
		c.CA.DataDir = def.CA.DataDir
	}
	if c.CA.Validity == 0 {
		c.CA.Validity = def.CA.Validity
	}
	if c.CA.LeafValidity == 0 {
		c.CA.LeafValidity = def.CA.LeafValidity
	}
	if c.CA.LeafCacheSize == 0 {
		c.CA.LeafCacheSize = def.CA.LeafCacheSize
	}
	if c.Logging.Level == "" {
		c.Logging.Level = def.Logging.Level
	}
	if c.Logging.Format == "" {
		c.Logging.Format = def.Logging.Format
	}
	if c.TLS.UnknownSNI == "" {
		c.TLS.UnknownSNI = def.TLS.UnknownSNI
	}
	if c.Limits.MaxConns == 0 {
		c.Limits.MaxConns = def.Limits.MaxConns
	}
	if c.Limits.MaxHeaderBytes == 0 {
		c.Limits.MaxHeaderBytes = def.Limits.MaxHeaderBytes
	}
	if c.Limits.ReadHeaderTimeout == 0 {
		c.Limits.ReadHeaderTimeout = def.Limits.ReadHeaderTimeout
	}
	if c.Limits.IdleTimeout == 0 {
		c.Limits.IdleTimeout = def.Limits.IdleTimeout
	}
	if c.Limits.DialTimeout == 0 {
		c.Limits.DialTimeout = def.Limits.DialTimeout
	}
	if c.Limits.TLSHandshakeTimeout == 0 {
		c.Limits.TLSHandshakeTimeout = def.Limits.TLSHandshakeTimeout
	}
	if c.Limits.ResponseHeaderTimeout == 0 {
		c.Limits.ResponseHeaderTimeout = def.Limits.ResponseHeaderTimeout
	}
	if c.Limits.ShutdownTimeout == 0 {
		c.Limits.ShutdownTimeout = def.Limits.ShutdownTimeout
	}
	if c.UDP443.Mode == "" {
		c.UDP443.Mode = def.UDP443.Mode
	}
	if c.Management.Listen == "" {
		c.Management.Listen = def.Management.Listen
	}
}

// Validate checks configuration consistency and returns an actionable error.
func (c Config) Validate() error {
	var errs []error

	if err := checkListenAddr(c.DNS.ListenUDP, "dns.listen_udp", true); err != nil {
		errs = append(errs, err)
	}
	if err := checkListenAddr(c.DNS.ListenTCP, "dns.listen_tcp", true); err != nil {
		errs = append(errs, err)
	}
	if err := checkListenAddr(c.HTTP.Listen, "http.listen", true); err != nil {
		errs = append(errs, err)
	}
	if err := checkListenAddr(c.HTTPS.Listen, "https.listen", true); err != nil {
		errs = append(errs, err)
	}
	if err := checkListenAddr(c.Management.Listen, "management.listen", false); err != nil {
		errs = append(errs, err)
	}

	if len(c.DNS.Upstream) == 0 {
		errs = append(errs, errors.New("dns.upstream must contain at least one resolver"))
	}
	for i, up := range c.DNS.Upstream {
		if err := checkHostPort(up); err != nil {
			errs = append(errs, fmt.Errorf("dns.upstream[%d]: %w", i, err))
		}
	}

	if c.DNS.InterceptIPv4 != "" {
		addr, err := netip.ParseAddr(c.DNS.InterceptIPv4)
		if err != nil || !addr.Is4() {
			errs = append(errs, fmt.Errorf("dns.intercept_ipv4 %q is not an IPv4 address", c.DNS.InterceptIPv4))
		}
	} else {
		errs = append(errs, errors.New("dns.intercept_ipv4 is required"))
	}
	if c.DNS.IPv6Enabled {
		addr, err := netip.ParseAddr(c.DNS.InterceptIPv6)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			errs = append(errs, fmt.Errorf("dns.intercept_ipv6 %q is not an IPv6 address", c.DNS.InterceptIPv6))
		}
	}

	switch strings.ToLower(c.DNS.BlockMode) {
	case "nxdomain", "sinkhole":
	default:
		errs = append(errs, fmt.Errorf("dns.block_mode %q must be \"nxdomain\" or \"sinkhole\"", c.DNS.BlockMode))
	}
	if c.DNS.BlockMode == "sinkhole" && c.DNS.SinkholeIPv4 == "" && c.DNS.SinkholeIPv6 == "" {
		errs = append(errs, errors.New("dns.block_mode \"sinkhole\" requires sinkhole_ipv4 or sinkhole_ipv6"))
	}
	if c.DNS.SinkholeIPv4 != "" {
		if _, err := netip.ParseAddr(c.DNS.SinkholeIPv4); err != nil {
			errs = append(errs, fmt.Errorf("dns.sinkhole_ipv4 %q is not an IP address", c.DNS.SinkholeIPv4))
		}
	}
	if c.DNS.SinkholeIPv6 != "" {
		if _, err := netip.ParseAddr(c.DNS.SinkholeIPv6); err != nil {
			errs = append(errs, fmt.Errorf("dns.sinkhole_ipv6 %q is not an IP address", c.DNS.SinkholeIPv6))
		}
	}
	if c.DNS.TTL < 0 {
		errs = append(errs, errors.New("dns.ttl must not be negative"))
	}
	if c.DNS.MaxUDPSize < 512 {
		errs = append(errs, fmt.Errorf("dns.max_udp_size %d must be at least 512", c.DNS.MaxUDPSize))
	}

	if c.Policy.Blocklist == "" {
		errs = append(errs, errors.New("policy.blocklist is required"))
	}
	if c.Policy.ReloadInterval < 0 {
		errs = append(errs, errors.New("policy.reload_interval must not be negative"))
	}

	switch strings.ToLower(c.Logging.Format) {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("logging.format %q must be \"json\" or \"text\"", c.Logging.Format))
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Errorf("logging.level %q is not a valid level", c.Logging.Level))
	}

	switch strings.ToLower(c.TLS.UnknownSNI) {
	case "reject", "passthrough":
	default:
		errs = append(errs, fmt.Errorf("tls.unknown_sni %q must be \"reject\" or \"passthrough\"", c.TLS.UnknownSNI))
	}

	if c.CA.Validity <= 0 {
		errs = append(errs, errors.New("ca.validity must be positive"))
	}
	if c.CA.LeafValidity <= 0 {
		errs = append(errs, errors.New("ca.leaf_validity must be positive"))
	}
	if c.CA.LeafCacheSize < 0 {
		errs = append(errs, errors.New("ca.leaf_cache_size must not be negative"))
	}

	if c.Limits.MaxConns <= 0 {
		errs = append(errs, errors.New("limits.max_conns must be positive"))
	}
	if c.Limits.MaxHeaderBytes < 4096 {
		errs = append(errs, fmt.Errorf("limits.max_header_bytes %d is too small", c.Limits.MaxHeaderBytes))
	}

	switch c.UDP443.Mode {
	case UDP443Allow, UDP443Reject, UDP443Drop:
	default:
		errs = append(errs, fmt.Errorf("udp443.mode %q must be \"allow\", \"reject\" or \"drop\"", c.UDP443.Mode))
	}

	if !c.Management.AllowNonLoopback {
		if err := loopbackOnly(c.Management.Listen); err != nil {
			errs = append(errs, fmt.Errorf("management.listen: %w (set management.allow_non_loopback to override)", err))
		}
	}

	return errors.Join(errs...)
}

func checkListenAddr(addr, field string, allowEmpty bool) error {
	if addr == "" {
		if allowEmpty {
			return fmt.Errorf("%s must not be empty", field)
		}
		return nil
	}
	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		return fmt.Errorf("%s %q is not a valid address: %w", field, addr, err)
	}
	return nil
}

func checkHostPort(addr string) error {
	if addr == "" {
		return errors.New("empty resolver address")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("resolver %q must be host:port", addr)
	}
	if host == "" {
		return fmt.Errorf("resolver %q has empty host", addr)
	}
	if _, err := net.LookupPort("udp", port); err != nil {
		return fmt.Errorf("resolver %q has invalid port", addr)
	}
	return nil
}

func loopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("refusing to bind management to all interfaces")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		return fmt.Errorf("management address %q is not a loopback IP", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("management address %q is not a loopback IP", host)
	}
	return nil
}

// Redacted returns a copy of the config safe for logging (no secrets are
// currently stored in config, but this is the single place to strip them).
func (c Config) Redacted() Config { return c }
