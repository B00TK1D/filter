//go:build linux && integration

// Package tests contains end-to-end network-namespace tests that exercise the
// real proxyd binary together with DNS rewriting, nftables interception and
// loop prevention. These require root, ip, nft, and curl.
//
// Run with:
//
//	go test -tags integration -run TestNetworkNamespace -v -timeout 180s ./tests/
package tests

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"filterproxy/internal/tlsmitm"
)

const (
	prefix        = "172.20.0."
	hostIP        = prefix + "1"
	nsIP          = prefix + "2"
	domain        = "www.poc.test"
	blockedDomain = "blocked-poc.test"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

func requireCmd(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s not available: %v", name, err)
		}
	}
}

func run(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func runStdin(t *testing.T, input string, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func nsExec(t *testing.T, ns string, args ...string) []byte {
	t.Helper()
	return run(t, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

func nsExecStdin(t *testing.T, ns, input string, args ...string) {
	t.Helper()
	runStdin(t, input, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

func TestNetworkNamespaceEndToEnd(t *testing.T) {
	requireRoot(t)
	requireCmd(t, "ip", "nft", "curl", "go")

	ns := fmt.Sprintf("proxyd-e2e-%d", os.Getpid())
	dir := t.TempDir()
	proxydBin := filepath.Join(dir, "proxyd")
	logPath := filepath.Join(dir, "proxyd.log")

	// --- start host-side services ------------------------------------------
	upstreamCA, err := tlsmitm.LoadOrCreate(tlsmitm.CAOptions{
		DataDir:  filepath.Join(dir, "upstream-ca"),
		Validity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("upstream CA: %v", err)
	}

	// Build a CA bundle that trusts system roots plus the upstream test CA.
	bundlePath := filepath.Join(dir, "ca-bundle.pem")
	writeTrustBundle(t, bundlePath, upstreamCA.CertPEM())

	// --- create the client network namespace -------------------------------
	run(t, "ip", "netns", "add", ns)
	cleanup := func() {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		_ = exec.Command("ip", "link", "del", "veth-h").Run()
		_ = os.RemoveAll("/etc/netns/" + ns)
	}
	t.Cleanup(cleanup)

	run(t, "ip", "link", "add", "veth-h", "type", "veth", "peer", "name", "veth-n")
	run(t, "ip", "link", "set", "veth-n", "netns", ns)
	run(t, "ip", "link", "set", "veth-h", "up")
	run(t, "ip", "addr", "add", hostIP+"/24", "dev", "veth-h")
	nsExec(t, ns, "ip", "addr", "add", nsIP+"/24", "dev", "veth-n")
	nsExec(t, ns, "ip", "link", "set", "lo", "up")
	nsExec(t, ns, "ip", "link", "set", "veth-n", "up")
	nsExec(t, ns, "ip", "route", "add", "default", "via", hostIP)

	// Host-side services bind to the veth address, so they start afterwards.
	startAuthoritativeDNS(t, net.JoinHostPort(hostIP, "5353"))
	startUpstreamHTTP(t)
	startUpstreamHTTPS(t, upstreamCA)

	// Point the namespace's resolver at proxyd.
	if err := os.MkdirAll("/etc/netns/"+ns, 0o755); err != nil {
		t.Fatalf("mkdir /etc/netns: %v", err)
	}
	if err := os.WriteFile("/etc/netns/"+ns+"/resolv.conf",
		[]byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatalf("resolv.conf: %v", err)
	}

	// --- nftables interception inside the namespace -------------------------
	nsExecStdin(t, ns, `
table ip poc {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    meta mark 1 accept
    tcp dport 80 redirect to :8080
    tcp dport 443 redirect to :8443
  }
  chain output {
    type nat hook output priority -100; policy accept;
    meta mark 1 accept
    tcp dport 80 redirect to :8080
    tcp dport 443 redirect to :8443
  }
}
`, "nft", "-f", "-")

	// --- proxyd configuration and startup -----------------------------------
	proxyCA := filepath.Join(dir, "proxy-ca")
	if err := os.MkdirAll(proxyCA, 0o700); err != nil {
		t.Fatalf("mkdir proxy CA: %v", err)
	}
	blocklist := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(blocklist, []byte(blockedDomain+"\n"), 0o600); err != nil {
		t.Fatalf("blocklist: %v", err)
	}
	cfg := fmt.Sprintf(`
dns:
  listen_udp: "127.0.0.1:53"
  listen_tcp: "127.0.0.1:53"
  upstream: ["%s:5353"]
  intercept_ipv4: "127.0.0.1"
  block_mode: "nxdomain"
  ttl: 60
  timeout: "2s"
  query_timeout: "3s"
http:
  listen: "127.0.0.1:8080"
https:
  listen: "127.0.0.1:8443"
policy:
  blocklist: "%s"
  allowlist: ""
ca:
  data_dir: "%s"
logging:
  level: "info"
  format: "json"
  output: "%s"
  log_urls: true
limits:
  upstream_mark: 1
  max_conns: 256
management:
  listen: "127.0.0.1:9090"
`, hostIP, blocklist, proxyCA, logPath)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("config: %v", err)
	}

	out, err := exec.Command("go", "build", "-o", proxydBin, "../cmd/proxyd").CombinedOutput()
	if err != nil {
		t.Fatalf("build proxyd: %v\n%s", err, out)
	}

	proc := exec.Command("ip", "netns", "exec", ns, proxydBin, "-config", cfgPath)
	proc.Env = append(os.Environ(), "SSL_CERT_FILE="+bundlePath, "SSL_CERT_DIR=")
	var stderr bytes.Buffer
	proc.Stderr = &stderr
	if err := proc.Start(); err != nil {
		t.Fatalf("start proxyd: %v", err)
	}
	defer func() {
		_ = proc.Process.Kill()
		_, _ = proc.Process.Wait()
	}()

	waitReady(t, ns)

	// --- client tests -------------------------------------------------------
	t.Run("dns-rewrite", func(t *testing.T) {
		// dig-style query against proxyd inside the namespace.
		cmd := exec.Command("ip", "netns", "exec", ns, "python3", "-c", qpython(domain, "A"))
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+bundlePath, "SSL_CERT_DIR=")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("query: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "127.0.0.1") {
			t.Fatalf("interception A record not returned:\n%s", out)
		}
	})

	t.Run("http-transparent", func(t *testing.T) {
		body := nsExec(t, ns, "curl", "-s", "--max-time", "10", "http://"+domain+"/hello?q=1")
		if string(body) != "http-ok" {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("https-transparent", func(t *testing.T) {
		cacert := filepath.Join(dir, "proxy-ca", "rootCA.pem")
		body := nsExec(t, ns, "curl", "-s", "--max-time", "10", "--cacert", cacert,
			"https://"+domain+"/secure")
		if string(body) != "https-ok" {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("blocked-domain", func(t *testing.T) {
		cmd := exec.Command("ip", "netns", "exec", ns, "curl", "-s", "--max-time", "5",
			"-o", "/dev/null", "http://"+blockedDomain+"/")
		out, err := cmd.CombinedOutput()
		// DNS returns NXDOMAIN so curl must fail to resolve (exit code != 0).
		if err == nil {
			t.Fatalf("expected blocked domain to fail resolution, got:\n%s", out)
		}
	})

	// --- verify logs --------------------------------------------------------
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	log := string(logBytes)
	for _, want := range []string{
		`"event":"dns_query"`, `"action":"block"`,
		`"event":"http_request"`, `"host":"` + domain + `"`,
		`"method":"GET"`, `"status":200`, `"action":"allow"`, `"latency_ms"`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q", want)
		}
	}
}

func waitReady(t *testing.T, ns string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ip", "netns", "exec", ns, "curl", "-fs", "--max-time", "2",
			"http://127.0.0.1:9090/readyz").CombinedOutput()
		if err == nil && bytes.Contains(out, []byte("ready")) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("proxyd did not become ready")
}

func startAuthoritativeDNS(t *testing.T, addr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("authoritative dns listen (is a resolver already on %s?): %v", addr, err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 {
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				if q.Name == dns.Fqdn(domain) {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
						A:   net.ParseIP(hostIP),
					})
				}
			}
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
}

func startUpstreamHTTP(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", hostIP+":80")
	if err != nil {
		t.Fatalf("upstream http listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Poc", "http")
		fmt.Fprint(w, "http-ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func startUpstreamHTTPS(t *testing.T, ca *tlsmitm.CA) {
	t.Helper()
	certs := tlsmitm.NewCertCache(ca, 4, time.Hour)
	cert, err := certs.Get(domain)
	if err != nil {
		t.Fatalf("upstream leaf: %v", err)
	}
	ln, err := tls.Listen("tcp", hostIP+":443", &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("upstream https listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Poc", "https")
		fmt.Fprint(w, "https-ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func writeTrustBundle(t *testing.T, path string, extraCerts ...[]byte) {
	t.Helper()
	var b bytes.Buffer
	if roots, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt"); err == nil {
		b.Write(roots)
	} else if roots, err := os.ReadFile("/etc/pki/tls/certs/ca-bundle.crt"); err == nil {
		b.Write(roots)
	}
	for _, c := range extraCerts {
		b.Write(c)
		b.WriteString("\n")
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

func qpython(host, typ string) string {
	return fmt.Sprintf(`
import socket, struct
Q = %q
q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
labels = b"".join(bytes([len(p)]) + p.encode() for p in Q.split(".")) + b"\x00"
q += labels + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(q, ("127.0.0.1", 53))
data, _ = s.recvfrom(4096)
print("%%d.%%d.%%d.%%d" %% tuple(data[-4:]) if len(data) >= 4 else "none")
`, host)
}
