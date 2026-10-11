package httpproxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"time"

	"filterproxy/internal/intercept"
	"filterproxy/internal/logging"
	"filterproxy/internal/tlsmitm"
)

// mitmListener accepts raw TCP connections, peeks the TLS ClientHello to learn
// the SNI, and either returns a TLS server connection (for MITM) or rejects the
// connection. In passthrough mode connections without SNI are relayed to the
// original destination without inspection.
type mitmListener struct {
	base             net.Listener
	cfg              *tls.Config
	log              *logging.Logger
	unknownSNI       string
	handshakeTimeout time.Duration
	dialer           *net.Dialer
	localAddrs       []netip.Addr
}

// Accept implements net.Listener.
func (l *mitmListener) Accept() (net.Conn, error) {
	for {
		c, err := l.base.Accept()
		if err != nil {
			return nil, err
		}
		sni, pc, err := tlsmitm.PeekClientHello(c, l.handshakeTimeout)
		if err != nil {
			l.log.Warn("tls client hello rejected",
				"event", "tls_handshake", "client", c.RemoteAddr().String(),
				"action", "reject", "reason", "bad-client-hello", "error", err.Error())
			c.Close()
			continue
		}
		if sni == "" {
			if l.unknownSNI == "passthrough" {
				go l.passthrough(c, pc)
				continue
			}
			l.log.Warn("tls connection rejected",
				"event", "tls_handshake", "client", c.RemoteAddr().String(),
				"action", "reject", "reason", "no-sni")
			c.Close()
			continue
		}
		return tls.Server(pc, l.cfg), nil
	}
}

func (l *mitmListener) Addr() net.Addr { return l.base.Addr() }

func (l *mitmListener) Close() error { return l.base.Close() }

func (l *mitmListener) isLocal(addr netip.Addr) bool {
	if addr.IsLoopback() {
		return true
	}
	for _, a := range l.localAddrs {
		if a == addr {
			return true
		}
	}
	return false
}

// passthrough relays an inspected-free TLS connection to its original
// destination. It cannot enforce domain policy because no hostname is present.
func (l *mitmListener) passthrough(orig net.Conn, pc *tlsmitm.PeekConn) {
	defer orig.Close()

	dst, err := intercept.OriginalDestination(orig)
	if err != nil {
		l.log.Warn("tls passthrough failed",
			"event", "tls_handshake", "client", orig.RemoteAddr().String(),
			"action", "passthrough", "reason", "no-original-destination", "error", err.Error())
		return
	}
	if !dst.IsValid() || l.isLocal(dst.Addr()) {
		l.log.Warn("tls passthrough refused",
			"event", "tls_handshake", "client", orig.RemoteAddr().String(),
			"action", "passthrough", "reason", "destination-is-proxy")
		return
	}

	up, err := l.dialer.Dial("tcp", dst.String())
	if err != nil {
		l.log.Warn("tls passthrough dial failed",
			"event", "tls_handshake", "client", orig.RemoteAddr().String(),
			"destination", dst.String(), "action", "passthrough", "reason", "dial", "error", err.Error())
		return
	}
	l.log.Info("tls connection passed through uninspected",
		"event", "tls_handshake", "client", orig.RemoteAddr().String(),
		"destination", dst.String(), "action", "passthrough", "reason", "no-sni")
	relay(pc, up)
}

// relay copies bytes in both directions until one side closes.
func relay(client net.Conn, upstream net.Conn) {
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}
