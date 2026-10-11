package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadDefaultsAndOverride(t *testing.T) {
	path := writeConfig(t, `
dns:
  listen_udp: "127.0.0.1:5353"
  listen_tcp: "127.0.0.1:5353"
  intercept_ipv4: "10.10.0.1"
  upstream:
    - "1.1.1.1:53"
http:
  listen: "127.0.0.1:8080"
https:
  listen: "127.0.0.1:8443"
policy:
  blocklist: "blocklist.txt"
ca:
  data_dir: "`+t.TempDir()+`"
management:
  listen: "127.0.0.1:9090"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DNS.TTL != 60 {
		t.Errorf("default TTL = %d, want 60", cfg.DNS.TTL)
	}
	if cfg.DNS.Timeout.Duration() != 3*time.Second {
		t.Errorf("default dns timeout = %v", cfg.DNS.Timeout.Duration())
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("default format = %q", cfg.Logging.Format)
	}
	if cfg.DNS.InterceptIPv4 != "10.10.0.1" {
		t.Errorf("intercept ipv4 = %q", cfg.DNS.InterceptIPv4)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"missing blocklist", func(c *Config) { c.Policy.Blocklist = "" }, "policy.blocklist"},
		{"bad ipv4", func(c *Config) { c.DNS.InterceptIPv4 = "not-an-ip" }, "intercept_ipv4"},
		{"bad block mode", func(c *Config) { c.DNS.BlockMode = "drop" }, "block_mode"},
		{"sinkhole without addr", func(c *Config) {
			c.DNS.BlockMode = "sinkhole"
			c.DNS.SinkholeIPv4 = ""
			c.DNS.SinkholeIPv6 = ""
		}, "sinkhole"},
		{"bad upstream", func(c *Config) { c.DNS.Upstream = []string{"missing-port"} }, "upstream"},
		{"bad unknown sni", func(c *Config) { c.TLS.UnknownSNI = "maybe" }, "unknown_sni"},
		{"management non-loopback", func(c *Config) { c.Management.Listen = "0.0.0.0:9090" }, "loopback"},
		{"ipv6 enabled invalid", func(c *Config) {
			c.DNS.IPv6Enabled = true
			c.DNS.InterceptIPv6 = "10.0.0.1"
		}, "intercept_ipv6"},
		{"bad udp443 mode", func(c *Config) { c.UDP443.Mode = "bogus" }, "udp443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Policy.Blocklist = "blocklist.txt"
			cfg.CA.DataDir = t.TempDir()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestManagementNonLoopbackAllowedWithOptIn(t *testing.T) {
	cfg := Default()
	cfg.Policy.Blocklist = "blocklist.txt"
	cfg.CA.DataDir = t.TempDir()
	cfg.Management.Listen = "0.0.0.0:9090"
	cfg.Management.AllowNonLoopback = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	path := writeConfig(t, "nonsense: true\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestDurationParsing(t *testing.T) {
	path := writeConfig(t, `
policy:
  blocklist: "blocklist.txt"
dns:
  upstream: ["1.1.1.1:53"]
  timeout: "1500ms"
ca:
  data_dir: "`+t.TempDir()+`"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DNS.Timeout.Duration() != 1500*time.Millisecond {
		t.Errorf("timeout = %v", cfg.DNS.Timeout.Duration())
	}
}
