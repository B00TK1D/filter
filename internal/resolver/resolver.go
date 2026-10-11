// Package resolver resolves upstream hostnames through explicitly configured
// resolvers, bypassing the system resolver so the proxy cannot loop back into
// its own DNS interception.
package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"filterproxy/internal/intercept"
)

// Resolver performs host lookups against a fixed set of upstream servers.
type Resolver struct {
	servers []string
	timeout time.Duration
	dialer  *net.Dialer
	next    atomic.Uint64
}

// New creates a Resolver. mark, when non-zero, is applied to upstream sockets.
func New(servers []string, timeout time.Duration, mark int) (*Resolver, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("resolver: at least one upstream server is required")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{
		servers: append([]string(nil), servers...),
		timeout: timeout,
		dialer: &net.Dialer{
			Timeout: timeout,
			Control: intercept.MarkControl(mark),
		},
	}, nil
}

// Servers returns the configured upstream servers.
func (r *Resolver) Servers() []string { return append([]string(nil), r.servers...) }

func (r *Resolver) resolverFor(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			switch network {
			case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
			default:
				network = "udp"
			}
			return r.dialer.DialContext(ctx, network, server)
		},
	}
}

// LookupHost resolves host to one or more IP addresses, trying each configured
// server in turn.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	start := int(r.next.Add(1)-1) % len(r.servers)
	var lastErr error
	for i := 0; i < len(r.servers); i++ {
		server := r.servers[(start+i)%len(r.servers)]
		ctx, cancel := context.WithTimeout(ctx, r.timeout)
		ips, err := r.resolverFor(server).LookupIPAddr(ctx, host)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		addrs := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip.IP); ok {
				addrs = append(addrs, a.Unmap())
			}
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
		lastErr = fmt.Errorf("resolver %s returned no addresses for %s", server, host)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolver available for %s", host)
	}
	return nil, lastErr
}
