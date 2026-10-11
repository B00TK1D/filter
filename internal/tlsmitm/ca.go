// Package tlsmitm manages the local root CA, on-demand leaf certificates and
// the TLS listener used for transparent HTTPS interception.
package tlsmitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CAOptions configures CA creation/loading.
type CAOptions struct {
	// CertFile and KeyFile are absolute or relative paths to the root CA PEM
	// files. When empty they default to rootCA.pem / rootCA-key.pem inside
	// DataDir.
	CertFile string
	KeyFile  string
	DataDir  string
	// Validity is the root CA lifetime.
	Validity time.Duration
	// Regenerate deletes and recreates the CA. Development only.
	Regenerate bool
}

// CA is a loaded local root certificate authority.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pool *x509.CertPool

	certPEM []byte
	keyPEM  []byte

	certPath string
	keyPath  string
}

// LoadOrCreate loads the CA at the configured paths, or creates a new one when
// neither file exists. If only one file exists, the pair is invalid, the
// certificate is not a usable CA, or the key does not match, it fails closed.
func LoadOrCreate(opts CAOptions) (*CA, error) {
	certPath := opts.CertFile
	if certPath == "" {
		certPath = filepath.Join(opts.DataDir, "rootCA.pem")
	}
	keyPath := opts.KeyFile
	if keyPath == "" {
		keyPath = filepath.Join(opts.DataDir, "rootCA-key.pem")
	}
	validity := opts.Validity
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	if opts.Regenerate {
		if err := os.Remove(certPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("regenerate: remove certificate: %w", err)
		}
		if err := os.Remove(keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("regenerate: remove key: %w", err)
		}
		certExists, keyExists = false, false
	}

	switch {
	case certExists && keyExists:
		ca, err := loadCA(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		return ca, nil
	case certExists != keyExists:
		return nil, fmt.Errorf("root CA is incomplete: %s=%t %s=%t; refusing to replace and break client trust",
			certPath, certExists, keyPath, keyExists)
	default:
		ca, err := createCA(certPath, keyPath, validity)
		if err != nil {
			return nil, err
		}
		return ca, nil
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read root CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read root CA key: %w", err)
	}

	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse root CA certificate %s: %w", certPath, err)
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse root CA key %s: %w", keyPath, err)
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, fmt.Errorf("root CA certificate %s does not match key %s", certPath, keyPath)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("root CA certificate %s is not a certificate authority", certPath)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("root CA certificate %s is not valid until %s", certPath, cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("root CA certificate %s expired at %s", certPath, cert.NotAfter)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{
		cert:     cert,
		key:      key,
		pool:     pool,
		certPEM:  certPEM,
		keyPEM:   keyPEM,
		certPath: certPath,
		keyPath:  keyPath,
	}, nil
}

func createCA(certPath, keyPath string, validity time.Duration) (*CA, error) {
	if dir := filepath.Dir(certPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create data directory %s: %w", dir, err)
		}
	}
	if dir := filepath.Dir(keyPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create data directory %s: %w", dir, err)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "proxyd Local Root CA",
			Organization: []string{"proxyd"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create root CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal root CA key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write root CA key: %w", err)
	}
	if err := writeFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write root CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse newly created CA: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{
		cert:     cert,
		key:      key,
		pool:     pool,
		certPEM:  certPEM,
		keyPEM:   keyPEM,
		certPath: certPath,
		keyPath:  keyPath,
	}, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// OpenFile honours the process umask; enforce the mode explicitly.
	return os.Chmod(path, mode)
}

// CertPool returns a pool containing the root CA certificate.
func (c *CA) CertPool() *x509.CertPool { return c.pool }

// Certificate returns the parsed root CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// CertPEM returns the root CA certificate in PEM form.
func (c *CA) CertPEM() []byte { return c.certPEM }

// KeyPEM returns the root CA private key in PEM form. Callers must treat this
// as a secret and must never log or transmit it.
func (c *CA) KeyPEM() []byte { return c.keyPEM }

// CertPath returns the certificate file path.
func (c *CA) CertPath() string { return c.certPath }

// KeyPath returns the private key file path.
func (c *CA) KeyPath() string { return c.keyPath }

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key type %T is not a signer", key)
		}
		return signer, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unrecognised private key format")
}

func publicKeysEqual(a, b any) bool {
	ader, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bder, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return string(ader) == string(bder)
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return n, nil
}
