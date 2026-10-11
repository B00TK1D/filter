// Command proxyd runs the transparent DNS + HTTP(S) filtering proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"filterproxy/internal/config"
	"filterproxy/internal/dns"
	"filterproxy/internal/health"
	"filterproxy/internal/httpproxy"
	"filterproxy/internal/logging"
	"filterproxy/internal/policy"
	"filterproxy/internal/tlsmitm"
)

// Version is the service version, overridable at build time with -ldflags.
var Version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("proxyd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "config.yaml", "path to the YAML configuration file")
	showVersion := fs.Bool("version", false, "print version and exit")
	devRegenerateCA := fs.Bool("dev-regenerate-ca", false, "development only: delete and recreate the root CA")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "proxyd %s - transparent DNS + HTTP(S) filtering proxy\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage: proxyd [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Printf("proxyd %s\n", Version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxyd: %v\n", err)
		return 1
	}
	if *devRegenerateCA {
		cfg.CA.Regenerate = true
	}

	logger, err := logging.New(logging.Options{
		Level:       cfg.Logging.Level,
		Format:      cfg.Logging.Format,
		Output:      cfg.Logging.Output,
		LogURLs:     cfg.Logging.LogURLs,
		PrivacyMode: cfg.Logging.PrivacyMode,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxyd: %v\n", err)
		return 1
	}
	defer logger.Close()

	if err := serve(cfg, logger); err != nil {
		logger.Error("service stopped with error", "error", err.Error())
		return 1
	}
	return 0
}

func serve(cfg config.Config, logger *logging.Logger) error {
	logger.Info("starting proxyd",
		"event", "startup", "version", Version,
		"dns_udp", cfg.DNS.ListenUDP, "dns_tcp", cfg.DNS.ListenTCP,
		"http", cfg.HTTP.Listen, "https", cfg.HTTPS.Listen,
		"management", cfg.Management.Listen,
		"udp443_mode", string(cfg.UDP443.Mode),
		"unknown_sni", cfg.TLS.UnknownSNI,
		"log_urls", cfg.Logging.LogURLs, "privacy_mode", cfg.Logging.PrivacyMode)

	// Policy.
	matcher, stats, err := policy.New(cfg.Policy.Blocklist, cfg.Policy.Allowlist)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	logger.Info("policy loaded",
		"event", "policy_load", "blocklist", cfg.Policy.Blocklist,
		"block_entries", stats.Block, "allowlist", cfg.Policy.Allowlist,
		"allow_entries", stats.Allow, "skipped", stats.Skipped)

	// Root CA and leaf cache.
	ca, err := tlsmitm.LoadOrCreate(tlsmitm.CAOptions{
		CertFile:   cfg.CA.CertFile,
		KeyFile:    cfg.CA.KeyFile,
		DataDir:    cfg.CA.DataDir,
		Validity:   cfg.CA.Validity.Duration(),
		Regenerate: cfg.CA.Regenerate,
	})
	if err != nil {
		return fmt.Errorf("root CA: %w", err)
	}
	logger.Info("root CA ready",
		"event", "ca_ready", "cert", ca.CertPath(),
		"subject", ca.Certificate().Subject.CommonName,
		"not_after", ca.Certificate().NotAfter.UTC().Format(time.RFC3339))
	if cfg.CA.Regenerate {
		logger.Warn("root CA was regenerated; clients must reinstall the new certificate",
			"event", "ca_regenerated", "cert", ca.CertPath())
	}
	certs := tlsmitm.NewCertCache(ca, cfg.CA.LeafCacheSize, cfg.CA.LeafValidity.Duration())

	interceptV4, interceptV6, localAddrs, err := parseInterceptAddrs(cfg)
	if err != nil {
		return err
	}

	// DNS.
	dnsServer := dns.New(dns.Options{
		ListenUDP:     cfg.DNS.ListenUDP,
		ListenTCP:     cfg.DNS.ListenTCP,
		Upstream:      cfg.DNS.Upstream,
		InterceptIPv4: interceptV4,
		InterceptIPv6: interceptV6,
		IPv6Enabled:   cfg.DNS.IPv6Enabled,
		BlockMode:     blockMode(cfg.DNS.BlockMode),
		SinkholeIPv4:  parseOptional(cfg.DNS.SinkholeIPv4),
		SinkholeIPv6:  parseOptional(cfg.DNS.SinkholeIPv6),
		TTL:           uint32(cfg.DNS.TTL),
		Timeout:       cfg.DNS.Timeout.Duration(),
		QueryTimeout:  cfg.DNS.QueryTimeout.Duration(),
		MaxUDPSize:    uint16(cfg.DNS.MaxUDPSize),
		UpstreamMark:  cfg.Limits.UpstreamMark,
	}, matcher, logger)
	if err := dnsServer.Listen(); err != nil {
		return err
	}

	// HTTP/HTTPS proxy.
	proxy, err := httpproxy.New(httpproxy.Options{
		HTTPListen:            cfg.HTTP.Listen,
		HTTPSListen:           cfg.HTTPS.Listen,
		ALPN:                  cfg.HTTPS.ALPN,
		Upstream:              cfg.DNS.Upstream,
		UpstreamMark:          cfg.Limits.UpstreamMark,
		DialTimeout:           cfg.Limits.DialTimeout.Duration(),
		TLSHandshakeTimeout:   cfg.Limits.TLSHandshakeTimeout.Duration(),
		ResponseHeaderTimeout: cfg.Limits.ResponseHeaderTimeout.Duration(),
		ReadHeaderTimeout:     cfg.Limits.ReadHeaderTimeout.Duration(),
		IdleTimeout:           cfg.Limits.IdleTimeout.Duration(),
		MaxHeaderBytes:        cfg.Limits.MaxHeaderBytes,
		MaxConns:              cfg.Limits.MaxConns,
		ShutdownTimeout:       cfg.Limits.ShutdownTimeout.Duration(),
		UnknownSNI:            cfg.TLS.UnknownSNI,
		LocalAddrs:            localAddrs,
	}, matcher, logger, certs)
	if err != nil {
		return err
	}
	if err := proxy.Listen(); err != nil {
		return err
	}

	// Management.
	healthServer := health.New(cfg.Management.Listen, cfg.Management.AllowNonLoopback, logger)
	if err := healthServer.Listen(); err != nil {
		return err
	}

	// Start everything.
	dnsServer.Start()
	proxy.Start()
	healthServer.Start()
	healthServer.SetReady(true)

	logger.Info("service ready",
		"event", "ready",
		"dns_udp", addrString(dnsServer.UDPAddr()),
		"dns_tcp", addrString(dnsServer.TCPAddr()),
		"http", addrString(proxy.HTTPAddr()),
		"https", addrString(proxy.HTTPSAddr()),
		"management", addrString(healthServer.Addr()))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	var reloadTicker *time.Ticker
	var reloadC <-chan time.Time
	if cfg.Policy.ReloadInterval > 0 {
		reloadTicker = time.NewTicker(cfg.Policy.ReloadInterval.Duration())
		reloadC = reloadTicker.C
		defer reloadTicker.Stop()
	}

	var fatal error
loop:
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown signal received", "event", "shutdown")
			break loop
		case <-hup:
			logger.Info("reload signal received", "event", "policy_reload")
			reloadPolicy(matcher, logger)
		case <-reloadC:
			reloadPolicy(matcher, logger)
		case err := <-dnsServer.ServeErrors():
			fatal = err
			logger.Error("dns server failed", "error", err.Error())
			break loop
		case err := <-proxy.ServeErrors():
			fatal = err
			logger.Error("http proxy failed", "error", err.Error())
			break loop
		case err := <-healthServer.ServeErrors():
			fatal = err
			logger.Error("management server failed", "error", err.Error())
			break loop
		}
	}

	healthServer.SetReady(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Limits.ShutdownTimeout.Duration())
	defer cancel()
	var errs []error
	if err := dnsServer.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, err)
	}
	if err := proxy.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, err)
	}
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	logger.Info("shutdown complete", "event", "shutdown")
	return fatal
}

func reloadPolicy(matcher *policy.Matcher, logger *logging.Logger) {
	snap, stats, err := matcher.Reload()
	if err != nil {
		logger.Error("policy reload failed", "event", "policy_reload", "error", err.Error())
		return
	}
	logger.Info("policy reloaded",
		"event", "policy_reload", "block_entries", stats.Block,
		"allow_entries", stats.Allow, "skipped", stats.Skipped,
		"loaded_at", snap.LoadedAt.Format(time.RFC3339))
}

func parseInterceptAddrs(cfg config.Config) (v4, v6 netip.Addr, local []netip.Addr, err error) {
	if cfg.DNS.InterceptIPv4 != "" {
		v4, err = netip.ParseAddr(cfg.DNS.InterceptIPv4)
		if err != nil {
			return v4, v6, nil, fmt.Errorf("intercept ipv4: %w", err)
		}
		local = append(local, v4.Unmap())
	}
	if cfg.DNS.IPv6Enabled && cfg.DNS.InterceptIPv6 != "" {
		v6, err = netip.ParseAddr(cfg.DNS.InterceptIPv6)
		if err != nil {
			return v4, v6, nil, fmt.Errorf("intercept ipv6: %w", err)
		}
		local = append(local, v6)
	}
	return v4, v6, local, nil
}

func parseOptional(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func blockMode(s string) dns.BlockMode {
	if s == string(dns.BlockSinkhole) {
		return dns.BlockSinkhole
	}
	return dns.BlockNXDomain
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}
