//go:build !linux

// Package intercept provides platform hooks for transparent proxying. On
// non-Linux platforms original destination recovery and socket marking are
// unavailable; transparent interception is not supported.
package intercept

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// ErrUnsupported is returned when original destination recovery is not
// available for the connection type or platform.
var ErrUnsupported = errors.New("original destination recovery unsupported on this platform")

// OriginalDestination is unsupported outside Linux.
func OriginalDestination(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, ErrUnsupported
}

// MarkControl returns nil because socket marking is Linux-only.
func MarkControl(mark int) func(network, address string, c syscall.RawConn) error {
	return nil
}
