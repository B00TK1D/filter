// Package dns implements the policy-aware DNS forwarder.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"filterproxy/internal/intercept"
	"filterproxy/internal/logging"
	"filterproxy/internal/policy"
)

// BlockMode selects the response for blocked names.
type BlockMode string

const (
	BlockNXDomain BlockMode = "nxdomain"
	BlockSinkhole BlockMode = "sinkhole"
)

// Options configures the DNS server.
type Options struct {
	ListenUDP     string
	ListenTCP     string
	Upstream      []string
	InterceptIPv4 netip.Addr
	InterceptIPv6 netip.Addr
	IPv6Enabled   bool
	BlockMode     BlockMode
	SinkholeIPv4  netip.Addr
	SinkholeIPv6  netip.Addr
	TTL           uint32
	Timeout       time.Duration
	QueryTimeout  time.Duration
	MaxUDPSize    uint16
	// UpstreamMark is applied to upstream sockets for firewall bypass.
	UpstreamMark int
}

// Server is a policy-aware DNS forwarder serving UDP and TCP.
type Server struct {
	opts    Options
	matcher *policy.Matcher
	log     *logging.Logger

	client    *dns.Client
	tcpClient *dns.Client

	udpServer *dns.Server
	tcpServer *dns.Server
	serveErr  chan error
}

// New builds a DNS server. Call Listen before Start.
func New(opts Options, matcher *policy.Matcher, logger *logging.Logger) *Server {
	if opts.TTL == 0 {
		opts.TTL = 60
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = 5 * time.Second
	}
	if opts.MaxUDPSize < 512 {
		opts.MaxUDPSize = 1232
	}
	dialer := &net.Dialer{
		Timeout: opts.Timeout,
		Control: intercept.MarkControl(opts.UpstreamMark),
	}
	return &Server{
		opts:      opts,
		matcher:   matcher,
		log:       logger,
		client:    &dns.Client{Net: "udp", Timeout: opts.Timeout, Dialer: dialer},
		tcpClient: &dns.Client{Net: "tcp", Timeout: opts.Timeout, Dialer: dialer},
		serveErr:  make(chan error, 2),
	}
}

// Listen binds the UDP and TCP sockets. Addresses ending in ":0" select an
// ephemeral port.
func (s *Server) Listen() error {
	if s.opts.ListenUDP != "" {
		pc, err := net.ListenPacket("udp", s.opts.ListenUDP)
		if err != nil {
			return fmt.Errorf("listen dns udp %s: %w", s.opts.ListenUDP, err)
		}
		s.udpServer = &dns.Server{PacketConn: pc, Handler: s, UDPSize: int(s.opts.MaxUDPSize)}
	}
	if s.opts.ListenTCP != "" {
		l, err := net.Listen("tcp", s.opts.ListenTCP)
		if err != nil {
			if s.udpServer != nil {
				s.udpServer.PacketConn.Close()
			}
			return fmt.Errorf("listen dns tcp %s: %w", s.opts.ListenTCP, err)
		}
		s.tcpServer = &dns.Server{Listener: l, Handler: s, UDPSize: int(s.opts.MaxUDPSize)}
	}
	if s.udpServer == nil && s.tcpServer == nil {
		return errors.New("dns: no listen addresses configured")
	}
	return nil
}

// UDPAddr returns the bound UDP address, if any.
func (s *Server) UDPAddr() net.Addr {
	if s.udpServer == nil || s.udpServer.PacketConn == nil {
		return nil
	}
	return s.udpServer.PacketConn.LocalAddr()
}

// TCPAddr returns the bound TCP address, if any.
func (s *Server) TCPAddr() net.Addr {
	if s.tcpServer == nil || s.tcpServer.Listener == nil {
		return nil
	}
	return s.tcpServer.Listener.Addr()
}

// ServeErrors returns a channel reporting fatal serve errors.
func (s *Server) ServeErrors() <-chan error { return s.serveErr }

// Start begins serving on the bound sockets.
func (s *Server) Start() {
	if s.udpServer != nil {
		go func() {
			if err := s.udpServer.ActivateAndServe(); err != nil {
				s.serveErr <- fmt.Errorf("dns udp: %w", err)
			}
		}()
	}
	if s.tcpServer != nil {
		go func() {
			if err := s.tcpServer.ActivateAndServe(); err != nil {
				s.serveErr <- fmt.Errorf("dns tcp: %w", err)
			}
		}()
	}
}

// Shutdown gracefully stops both servers.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	if s.udpServer != nil {
		if err := s.udpServer.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ServeDNS handles a single DNS request.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	client := remoteIP(w.RemoteAddr())

	if len(req.Question) != 1 {
		s.log.Warn("dns query rejected",
			"event", "dns_query", "client", client, "action", "reject",
			"reason", "question-count", "count", len(req.Question))
		s.writeError(w, req, dns.RcodeFormatError)
		return
	}
	q := req.Question[0]
	name := policy.Normalize(q.Name)

	res := s.matcher.Decide(name)
	if res.Decision == policy.Block {
		s.respondBlocked(w, req, q, res.Reason, client, start)
		return
	}

	switch q.Qtype {
	case dns.TypeA:
		if s.opts.InterceptIPv4.IsValid() {
			s.respondAddr(w, req, q, s.opts.InterceptIPv4, "intercept", client, start)
			return
		}
	case dns.TypeAAAA:
		if s.opts.IPv6Enabled && s.opts.InterceptIPv6.IsValid() {
			s.respondAddr(w, req, q, s.opts.InterceptIPv6, "intercept", client, start)
			return
		}
		// IPv6 interception disabled: document NODATA rather than an
		// unusable address.
		s.respondNODATA(w, req, q, "ipv6-disabled", client, start)
		return
	}

	s.forward(w, req, q, client, start)
}

func (s *Server) respondBlocked(w dns.ResponseWriter, req *dns.Msg, q dns.Question, reason, client string, start time.Time) {
	if s.opts.BlockMode == BlockSinkhole {
		var addr netip.Addr
		switch q.Qtype {
		case dns.TypeA:
			addr = s.opts.SinkholeIPv4
		case dns.TypeAAAA:
			addr = s.opts.SinkholeIPv6
		}
		if addr.IsValid() {
			s.buildAddrResponse(w, req, q, addr)
			s.log.Info("dns query blocked",
				"event", "dns_query", "client", client, "question", q.Name,
				"type", dns.TypeToString[q.Qtype], "action", "block",
				"reason", reason, "answer", addr.String(),
				"latency_ms", millis(start))
			return
		}
	}
	// Default and sinkhole fallback: NXDOMAIN.
	s.writeError(w, req, dns.RcodeNameError)
	s.log.Info("dns query blocked",
		"event", "dns_query", "client", client, "question", q.Name,
		"type", dns.TypeToString[q.Qtype], "action", "block",
		"reason", reason, "rcode", "NXDOMAIN", "latency_ms", millis(start))
}

func (s *Server) respondAddr(w dns.ResponseWriter, req *dns.Msg, q dns.Question, addr netip.Addr, reason, client string, start time.Time) {
	s.buildAddrResponse(w, req, q, addr)
	s.log.Info("dns query answered",
		"event", "dns_query", "client", client, "question", q.Name,
		"type", dns.TypeToString[q.Qtype], "action", "allow",
		"reason", reason, "answer", addr.String(), "latency_ms", millis(start))
}

func (s *Server) respondNODATA(w dns.ResponseWriter, req *dns.Msg, q dns.Question, reason, client string, start time.Time) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Rcode = dns.RcodeSuccess
	s.addEdns(m, req)
	s.write(w, m)
	s.log.Info("dns query answered",
		"event", "dns_query", "client", client, "question", q.Name,
		"type", dns.TypeToString[q.Qtype], "action", "allow",
		"reason", reason, "answer", "nodata", "latency_ms", millis(start))
}

func (s *Server) buildAddrResponse(w dns.ResponseWriter, req *dns.Msg, q dns.Question, addr netip.Addr) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: s.opts.TTL}
	ip := addr.AsSlice()
	switch {
	case addr.Is4():
		hdr.Rrtype = dns.TypeA
		m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip})
	default:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
	}
	s.addEdns(m, req)
	s.write(w, m)
}

func (s *Server) forward(w dns.ResponseWriter, req *dns.Msg, q dns.Question, client string, start time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.QueryTimeout)
	defer cancel()

	resp, err := s.exchange(ctx, req)
	if err != nil {
		s.log.Warn("dns upstream error",
			"event", "dns_query", "client", client, "question", q.Name,
			"type", dns.TypeToString[q.Qtype], "action", "error",
			"reason", "upstream", "error", err.Error(), "latency_ms", millis(start))
		s.writeError(w, req, dns.RcodeServerFailure)
		return
	}
	resp.Id = req.Id
	s.write(w, resp)
	s.log.Info("dns query forwarded",
		"event", "dns_query", "client", client, "question", q.Name,
		"type", dns.TypeToString[q.Qtype], "action", "forward",
		"reason", "passthrough", "rcode", dns.RcodeToString[resp.Rcode],
		"answers", len(resp.Answer), "latency_ms", millis(start))
}

func (s *Server) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, server := range s.opts.Upstream {
		resp, _, err := s.client.ExchangeContext(ctx, req, server)
		if err == nil && resp != nil && resp.Truncated {
			if tcpResp, _, terr := s.tcpClient.ExchangeContext(ctx, req, server); terr == nil && tcpResp != nil {
				return tcpResp, nil
			}
		}
		if err == nil && resp != nil {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream resolver responded")
	}
	return nil, lastErr
}

func (s *Server) write(w dns.ResponseWriter, m *dns.Msg) {
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		m.Truncate(int(s.opts.MaxUDPSize))
	}
	if err := w.WriteMsg(m); err != nil {
		s.log.Debug("dns write failed", "error", err.Error())
	}
}

func (s *Server) writeError(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	s.addEdns(m, req)
	s.write(w, m)
}

func (s *Server) addEdns(m, req *dns.Msg) {
	if opt := req.IsEdns0(); opt != nil && opt.UDPSize() > 0 {
		size := opt.UDPSize()
		if size < s.opts.MaxUDPSize {
			size = s.opts.MaxUDPSize
		}
		// Advertise no DNSSEC OK: rewritten answers are not validated.
		m.SetEdns0(size, false)
	}
}

func remoteIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip := a.IP
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	case *net.TCPAddr:
		ip := a.IP
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return strings.Trim(host, "[]")
	}
}

func millis(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}
