package tlsmitm

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	ca, err := LoadOrCreate(CAOptions{DataDir: dir, Validity: 24 * time.Hour})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return ca, dir
}

func TestCreateAndReuseCA(t *testing.T) {
	ca, dir := newCA(t)
	keyPath := filepath.Join(dir, "rootCA-key.pem")

	if fi, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key missing: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("key permissions = %v, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(dir); err != nil {
		t.Fatalf("dir missing: %v", err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("dir permissions = %v, want 0700", fi.Mode().Perm())
	}
	if !ca.Certificate().IsCA {
		t.Error("created certificate is not a CA")
	}
	if ca.Certificate().KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA is missing CertSign key usage")
	}

	reloaded, err := LoadOrCreate(CAOptions{DataDir: dir})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.Certificate().Equal(ca.Certificate()) {
		t.Error("reloaded CA certificate differs; CA was not reused")
	}
	if string(reloaded.CertPEM()) != string(ca.CertPEM()) {
		t.Error("reloaded CA PEM differs")
	}
}

func TestIncompleteCAPairFails(t *testing.T) {
	_, dir := newCA(t)
	keyPath := filepath.Join(dir, "rootCA-key.pem")
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	if _, err := LoadOrCreate(CAOptions{DataDir: dir}); err == nil {
		t.Fatal("expected failure when key is missing")
	}
}

func TestMismatchedCAPairFails(t *testing.T) {
	_, dir := newCA(t)
	// Generate a second, unrelated CA and swap in its key.
	otherDir := t.TempDir()
	other, err := LoadOrCreate(CAOptions{DataDir: otherDir})
	if err != nil {
		t.Fatalf("second CA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rootCA-key.pem"), other.KeyPEM(), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := LoadOrCreate(CAOptions{DataDir: dir}); err == nil {
		t.Fatal("expected failure for mismatched cert/key pair")
	}
}

func TestCorruptCAFails(t *testing.T) {
	_, dir := newCA(t)
	if err := os.WriteFile(filepath.Join(dir, "rootCA.pem"), []byte("not a pem"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadOrCreate(CAOptions{DataDir: dir}); err == nil {
		t.Fatal("expected failure for corrupt certificate")
	}
}

func TestRegenerateChangesCA(t *testing.T) {
	ca, dir := newCA(t)
	first := append([]byte(nil), ca.CertPEM()...)
	regen, err := LoadOrCreate(CAOptions{DataDir: dir, Regenerate: true})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if string(regen.CertPEM()) == string(first) {
		t.Error("regenerated CA should differ")
	}
	again, err := LoadOrCreate(CAOptions{DataDir: dir})
	if err != nil {
		t.Fatalf("reload after regenerate: %v", err)
	}
	if !again.Certificate().Equal(regen.Certificate()) {
		t.Error("regenerated CA not persisted")
	}
}

func TestLeafIssuanceAndVerification(t *testing.T) {
	ca, _ := newCA(t)
	cache := NewCertCache(ca, 8, time.Hour)

	leaf, err := cache.Get("example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if leaf.Leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q", leaf.Leaf.Subject.CommonName)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   ca.CertPool(),
	}); err != nil {
		t.Errorf("leaf verification: %v", err)
	}

	// Cached: identical DER.
	again, err := cache.Get("EXAMPLE.com.")
	if err != nil {
		t.Fatalf("Get cached: %v", err)
	}
	if string(again.Leaf.Raw) != string(leaf.Leaf.Raw) {
		t.Error("expected cached certificate for normalized host")
	}

	// IP literal SAN.
	ipLeaf, err := cache.Get("127.0.0.1")
	if err != nil {
		t.Fatalf("Get ip: %v", err)
	}
	if _, err := ipLeaf.Leaf.Verify(x509.VerifyOptions{
		DNSName: "127.0.0.1",
		Roots:   ca.CertPool(),
	}); err != nil {
		t.Errorf("ip leaf verification: %v", err)
	}
}

func TestLeafCacheBounded(t *testing.T) {
	ca, _ := newCA(t)
	cache := NewCertCache(ca, 2, time.Hour)
	for _, h := range []string{"a.test", "b.test", "c.test", "d.test"} {
		if _, err := cache.Get(h); err != nil {
			t.Fatalf("Get(%s): %v", h, err)
		}
	}
	if cache.Len() > 2 {
		t.Errorf("cache len = %d, want <= 2", cache.Len())
	}
}

func TestLeafAuthorizerBlocks(t *testing.T) {
	ca, _ := newCA(t)
	cache := NewCertCache(ca, 4, time.Hour)
	cache.SetAuthorizer(func(host string) error {
		if host == "blocked.test" {
			return errors.New("blocked")
		}
		return nil
	})
	if _, err := cache.Get("blocked.test"); err == nil {
		t.Fatal("expected authorizer to block")
	}
	if _, err := cache.Get("allowed.test"); err != nil {
		t.Fatalf("allowed host failed: %v", err)
	}
}

func TestEmptyHostRejected(t *testing.T) {
	ca, _ := newCA(t)
	cache := NewCertCache(ca, 4, time.Hour)
	if _, err := cache.Get(""); err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestTLSConfigUnknownSNI(t *testing.T) {
	ca, _ := newCA(t)
	cache := NewCertCache(ca, 4, time.Hour)
	cfg := cache.TLSConfig(nil)
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
		t.Fatal("expected error for empty SNI")
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
}
