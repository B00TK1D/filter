package dns

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"

	"filterproxy/internal/logging"
	"filterproxy/internal/policy"
)

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(logging.Options{Level: "error", Writer: io.Discard})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}

func startUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 {
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeMX:
				m.Answer = append(m.Answer, &dns.MX{
					Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 30},
					Preference: 10,
					Mx:         "mail.example.",
				})
			case dns.TypePTR:
				m.Answer = append(m.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 30},
					Ptr: "host.example.",
				})
			}
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func blocklist(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/blocklist.txt"
	if err := writeFile(path, "blocked.test\n"); err != nil {
		t.Fatalf("write blocklist: %v", err)
	}
	return path
}

func newTestServer(t *testing.T, mut func(*Options)) *Server {
	t.Helper()
	m, _, err := policy.New(blocklist(t), "")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	opts := Options{
		ListenUDP:     "127.0.0.1:0",
		ListenTCP:     "127.0.0.1:0",
		Upstream:      []string{startUpstream(t)},
		InterceptIPv4: mustAddr(t, "10.0.0.1"),
		InterceptIPv6: mustAddr(t, "fd00::1"),
		BlockMode:     BlockNXDomain,
		TTL:           30,
		Timeout:       2 * time.Second,
		QueryTimeout:  3 * time.Second,
		MaxUDPSize:    1232,
	}
	if mut != nil {
		mut(&opts)
	}
	s := New(opts, m, testLogger(t))
	if err := s.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func query(t *testing.T, netProto, addr string, m *dns.Msg) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: netProto, Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return resp
}

func TestARewriteUDP(t *testing.T) {
	s := newTestServer(t, nil)
	m := new(dns.Msg)
	m.SetQuestion("allowed.test.", dns.TypeA)
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.0.0.1" {
		t.Fatalf("answer = %v", resp.Answer[0])
	}
}

func TestARewriteTCP(t *testing.T) {
	s := newTestServer(t, nil)
	m := new(dns.Msg)
	m.SetQuestion("allowed.test.", dns.TypeA)
	resp := query(t, "tcp", s.TCPAddr().String(), m)
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d", len(resp.Answer))
	}
}

func TestBlockedNXDOMAIN(t *testing.T) {
	s := newTestServer(t, nil)
	m := new(dns.Msg)
	m.SetQuestion("blocked.test.", dns.TypeA)
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("unexpected answers: %v", resp.Answer)
	}
}

func TestBlockedSinkhole(t *testing.T) {
	s := newTestServer(t, func(o *Options) {
		o.BlockMode = BlockSinkhole
		o.SinkholeIPv4 = mustAddr(t, "10.9.9.9")
	})
	m := new(dns.Msg)
	m.SetQuestion("blocked.test.", dns.TypeA)
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d", len(resp.Answer))
	}
	if a := resp.Answer[0].(*dns.A); a.A.String() != "10.9.9.9" {
		t.Fatalf("sinkhole answer = %v", a.A)
	}
}

func TestAAAAWhenIPv6DisabledIsNODATA(t *testing.T) {
	s := newTestServer(t, func(o *Options) { o.IPv6Enabled = false })
	m := new(dns.Msg)
	m.SetQuestion("allowed.test.", dns.TypeAAAA)
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected NODATA, got %v", resp.Answer)
	}
}

func TestAAAAWhenIPv6Enabled(t *testing.T) {
	s := newTestServer(t, func(o *Options) { o.IPv6Enabled = true })
	m := new(dns.Msg)
	m.SetQuestion("allowed.test.", dns.TypeAAAA)
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d", len(resp.Answer))
	}
	if aaaa := resp.Answer[0].(*dns.AAAA); aaaa.AAAA.String() != "fd00::1" {
		t.Fatalf("answer = %v", aaaa.AAAA)
	}
}

func TestForwardOtherTypes(t *testing.T) {
	s := newTestServer(t, nil)
	m := new(dns.Msg)
	m.SetQuestion("allowed.test.", dns.TypeMX)
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.MX); !ok {
		t.Fatalf("answer = %T", resp.Answer[0])
	}
}

func TestReverseLookupForwarded(t *testing.T) {
	s := newTestServer(t, nil)
	m := new(dns.Msg)
	m.SetQuestion("1.0.0.10.in-addr.arpa.", dns.TypePTR)
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d", len(resp.Answer))
	}
}

func TestMultipleQuestionsFormErr(t *testing.T) {
	s := newTestServer(t, nil)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{Name: "a.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[resp.Rcode])
	}
}

func TestBlockedSubdomain(t *testing.T) {
	s := newTestServer(t, nil)
	m := new(dns.Msg)
	m.SetQuestion("deep.blocked.test.", dns.TypeA)
	resp := query(t, "udp", s.UDPAddr().String(), m)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("subdomain should be blocked, rcode = %s", dns.RcodeToString[resp.Rcode])
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
