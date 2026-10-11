package tlsmitm

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type captureConn struct {
	bytes.Buffer
}

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

func clientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	cc := &captureConn{}
	client := tls.Client(cc, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // test-only capture
	})
	_ = client.Handshake() // writes ClientHello, then fails reading the reply
	return cc.Bytes()
}

func TestReadClientHelloSNI(t *testing.T) {
	raw := clientHelloBytes(t, "secure.example")
	sni, consumed, err := ReadClientHelloSNI(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadClientHelloSNI: %v", err)
	}
	if sni != "secure.example" {
		t.Errorf("sni = %q, want secure.example", sni)
	}
	if !bytes.Equal(consumed, raw) {
		t.Error("consumed bytes do not match input")
	}
}

func TestReadClientHelloNoSNI(t *testing.T) {
	raw := clientHelloBytes(t, "")
	sni, _, err := ReadClientHelloSNI(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadClientHelloSNI: %v", err)
	}
	if sni != "" {
		t.Errorf("sni = %q, want empty", sni)
	}
}

func TestReadClientHelloNotTLS(t *testing.T) {
	_, _, err := ReadClientHelloSNI(bytes.NewReader([]byte("GET / HTTP/1.1\r\n\r\n")))
	if !errors.Is(err, ErrNotTLS) {
		t.Fatalf("err = %v, want ErrNotTLS", err)
	}
}

func TestPeekClientHelloReplays(t *testing.T) {
	raw := clientHelloBytes(t, "replay.example")
	server, client := net.Pipe()
	go func() {
		_, _ = client.Write(raw)
	}()
	sni, pc, err := PeekClientHello(server, 2*time.Second)
	if err != nil {
		t.Fatalf("PeekClientHello: %v", err)
	}
	if sni != "replay.example" {
		t.Errorf("sni = %q", sni)
	}
	got := make([]byte, len(raw))
	if _, err := io.ReadFull(pc, got); err != nil {
		t.Fatalf("read replay: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Error("replayed bytes differ from original")
	}
}
