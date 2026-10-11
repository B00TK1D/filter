//go:build linux

// Package intercept provides Linux transparent-proxy helpers: recovering the
// original destination address of a redirected connection and applying a
// socket mark so proxy-originated traffic can bypass interception rules.
package intercept

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	solIP         = 0  // unix.SOL_IP
	solIPv6       = 41 // unix.SOL_IPV6
	soOriginalDst = 80
)

// ErrUnsupported is returned when original destination recovery is not
// available for the connection type or platform.
var ErrUnsupported = errors.New("original destination recovery unsupported")

// OriginalDestination returns the pre-NAT destination of an intercepted TCP
// connection using SO_ORIGINAL_DST.
func OriginalDestination(conn net.Conn) (netip.AddrPort, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%w: %T", ErrUnsupported, conn)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var (
		result netip.AddrPort
		opErr  error
	)
	if err := raw.Control(func(fd uintptr) {
		result, opErr = originalDst(fd)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	return result, opErr
}

func originalDst(fd uintptr) (netip.AddrPort, error) {
	if ap, err := getsockopt4(fd); err == nil {
		return ap, nil
	}
	if ap, err := getsockopt6(fd); err == nil {
		return ap, nil
	}
	return netip.AddrPort{}, fmt.Errorf("%w: neither IPv4 nor IPv6 original destination available", ErrUnsupported)
}

func getsockopt4(fd uintptr) (netip.AddrPort, error) {
	var sa unix.RawSockaddrInet4
	size := uint32(unix.SizeofSockaddrInet4)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd,
		uintptr(solIP), uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return netip.AddrPort{}, errno
	}
	if sa.Family != unix.AF_INET {
		return netip.AddrPort{}, errors.New("not an IPv4 sockaddr")
	}
	port := uint16(sa.Port>>8) | uint16(sa.Port<<8)
	return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port), nil
}

func getsockopt6(fd uintptr) (netip.AddrPort, error) {
	var sa unix.RawSockaddrInet6
	size := uint32(unix.SizeofSockaddrInet6)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd,
		uintptr(solIPv6), uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return netip.AddrPort{}, errno
	}
	if sa.Family != unix.AF_INET6 {
		return netip.AddrPort{}, errors.New("not an IPv6 sockaddr")
	}
	port := uint16(sa.Port>>8) | uint16(sa.Port<<8)
	return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), port), nil
}

// MarkControl returns a net.Dialer Control function that sets SO_MARK on
// outbound sockets. A zero mark disables marking.
func MarkControl(mark int) func(network, address string, c syscall.RawConn) error {
	if mark == 0 {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var opErr error
		if err := c.Control(func(fd uintptr) {
			opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return opErr
	}
}
