package tlsmitm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const recordTypeHandshake = 22

var (
	// ErrNotTLS indicates the first bytes were not a TLS handshake.
	ErrNotTLS = errors.New("not a TLS handshake")
	// ErrMalformedHello indicates the ClientHello could not be parsed.
	ErrMalformedHello = errors.New("malformed TLS ClientHello")
)

// PeekConn is a net.Conn that replays bytes already consumed by peeking.
type PeekConn struct {
	net.Conn
	buf []byte
	off int
}

// Read returns buffered bytes first, then reads from the underlying conn.
func (c *PeekConn) Read(p []byte) (int, error) {
	if c.off < len(c.buf) {
		n := copy(p, c.buf[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// ReadClientHelloSNI reads the TLS ClientHello from r, returning the SNI value
// (which may be empty) and every byte consumed so callers can replay them.
func ReadClientHelloSNI(r io.Reader) (sni string, raw []byte, err error) {
	var handshake []byte
	firstRecord := true
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r, header); err != nil {
			return "", raw, fmt.Errorf("%w: reading record header: %v", ErrNotTLS, err)
		}
		raw = append(raw, header...)
		if header[0] != recordTypeHandshake {
			if firstRecord {
				return "", raw, ErrNotTLS
			}
			return "", raw, fmt.Errorf("%w: unexpected record type %d", ErrMalformedHello, header[0])
		}
		firstRecord = false
		recLen := int(header[3])<<8 | int(header[4])
		if recLen <= 0 || recLen > 1<<16 {
			return "", raw, fmt.Errorf("%w: invalid record length %d", ErrMalformedHello, recLen)
		}
		body := make([]byte, recLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", raw, fmt.Errorf("%w: reading record body: %v", ErrMalformedHello, err)
		}
		raw = append(raw, body...)
		handshake = append(handshake, body...)

		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 0x01 { // ClientHello
			return "", raw, fmt.Errorf("%w: handshake type %d", ErrMalformedHello, handshake[0])
		}
		hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if hsLen > 1<<16 {
			return "", raw, fmt.Errorf("%w: oversized handshake %d", ErrMalformedHello, hsLen)
		}
		if len(handshake) < 4+hsLen {
			continue // fragmented across records
		}
		name, err := parseClientHelloSNI(handshake[4 : 4+hsLen])
		if err != nil {
			return "", raw, err
		}
		return name, raw, nil
	}
}

func parseClientHelloSNI(p []byte) (string, error) {
	// client_version (2) + random (32)
	if len(p) < 34 {
		return "", ErrMalformedHello
	}
	p = p[34:]

	// session_id
	if len(p) < 1 {
		return "", ErrMalformedHello
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return "", ErrMalformedHello
	}
	p = p[sidLen:]

	// cipher_suites
	if len(p) < 2 {
		return "", ErrMalformedHello
	}
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen {
		return "", ErrMalformedHello
	}
	p = p[csLen:]

	// compression_methods
	if len(p) < 1 {
		return "", ErrMalformedHello
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return "", ErrMalformedHello
	}
	p = p[cmLen:]

	// extensions are optional
	if len(p) == 0 {
		return "", nil
	}
	if len(p) < 2 {
		return "", ErrMalformedHello
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if extLen > len(p) {
		extLen = len(p)
	}
	exts := p[:extLen]

	for len(exts) >= 4 {
		et := int(exts[0])<<8 | int(exts[1])
		el := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if el > len(exts) {
			return "", ErrMalformedHello
		}
		data := exts[:el]
		exts = exts[el:]
		if et != 0 { // server_name
			continue
		}
		if len(data) < 2 {
			return "", ErrMalformedHello
		}
		listLen := int(data[0])<<8 | int(data[1])
		list := data[2:]
		if listLen > len(list) {
			listLen = len(list)
		}
		list = list[:listLen]
		for len(list) >= 3 {
			nt := list[0]
			nl := int(list[1])<<8 | int(list[2])
			list = list[3:]
			if nl > len(list) {
				return "", ErrMalformedHello
			}
			name := list[:nl]
			list = list[nl:]
			if nt == 0 {
				return string(name), nil
			}
		}
		return "", nil
	}
	return "", nil
}

// PeekClientHello reads the ClientHello from conn and returns the SNI plus a
// Conn that replays the consumed bytes. The read deadline is restored after
// peeking.
func PeekClientHello(conn net.Conn, timeout time.Duration) (string, *PeekConn, error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	sni, raw, err := ReadClientHelloSNI(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", nil, err
	}
	return sni, &PeekConn{Conn: conn, buf: raw}, nil
}
