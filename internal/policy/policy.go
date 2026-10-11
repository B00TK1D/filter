// Package policy implements normalized domain matching with deterministic
// allowlist/blocklist precedence and atomic reloads.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
)

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
)

// Decision is the outcome of a policy evaluation.
type Decision int

const (
	// Allow permits the request/host.
	Allow Decision = iota
	// Block denies the request/host.
	Block
)

// String renders a decision for logs.
func (d Decision) String() string {
	if d == Block {
		return "block"
	}
	return "allow"
}

// Result pairs a decision with a human-readable reason.
type Result struct {
	Decision Decision
	Reason   string
}

// Snapshot is an immutable view of the loaded policy.
type Snapshot struct {
	block     map[string]struct{}
	allow     map[string]struct{}
	BlockList string
	AllowList string
	BlockN    int
	AllowN    int
	LoadedAt  time.Time
}

// Blocks reports whether host is blocked by this snapshot (allowlist aware).
func (s *Snapshot) Blocks(host string) bool {
	h := Normalize(host)
	if h == "" {
		return false
	}
	if containsDomain(s.allow, h) {
		return false
	}
	return containsDomain(s.block, h)
}

// Decide evaluates host against this snapshot.
func (s *Snapshot) Decide(host string) Result {
	h := Normalize(host)
	if h == "" {
		return Result{Decision: Allow, Reason: "empty-host"}
	}
	if containsDomain(s.allow, h) {
		return Result{Decision: Allow, Reason: "allowlist"}
	}
	if containsDomain(s.block, h) {
		return Result{Decision: Block, Reason: "blocklist"}
	}
	return Result{Decision: Allow, Reason: "default"}
}

// Matcher holds the current policy snapshot and atomically swaps it on reload.
type Matcher struct {
	blocklistPath string
	allowlistPath string
	snap          atomic.Pointer[Snapshot]
}

// New loads policy files and returns a Matcher. A missing blocklist is an
// error. A missing allowlist is permitted when the path is empty.
func New(blocklistPath, allowlistPath string) (*Matcher, Stats, error) {
	m := &Matcher{blocklistPath: blocklistPath, allowlistPath: allowlistPath}
	snap, stats, err := load(blocklistPath, allowlistPath)
	if err != nil {
		return nil, stats, err
	}
	m.snap.Store(snap)
	return m, stats, nil
}

// Snapshot returns the current immutable snapshot.
func (m *Matcher) Snapshot() *Snapshot { return m.snap.Load() }

// Decide evaluates a host against the current snapshot.
func (m *Matcher) Decide(host string) Result { return m.snap.Load().Decide(host) }

// Blocks reports whether the host is blocked.
func (m *Matcher) Blocks(host string) bool { return m.snap.Load().Blocks(host) }

// Reload re-reads the policy files and atomically swaps in a new snapshot. If
// loading fails, the previous snapshot remains active and the error is
// returned.
func (m *Matcher) Reload() (*Snapshot, Stats, error) {
	snap, stats, err := load(m.blocklistPath, m.allowlistPath)
	if err != nil {
		return nil, stats, err
	}
	m.snap.Store(snap)
	return snap, stats, nil
}

// Paths returns the configured blocklist and allowlist paths.
func (m *Matcher) Paths() (blocklist, allowlist string) {
	return m.blocklistPath, m.allowlistPath
}

// Normalize canonicalizes a hostname for matching: trims whitespace and a
// trailing dot, lowercases, converts IDN to punycode, and canonicalizes IP
// literals.
func Normalize(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// Strip surrounding brackets from IPv6 literals.
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	// Remove a single trailing dot.
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	host = strings.ToLower(host)
	if ascii, err := idnaProfile.ToASCII(host); err == nil && ascii != "" {
		host = strings.ToLower(ascii)
	}
	return host
}

// containsDomain reports whether name, or any of its parent domains, is in the
// set. This implements exact plus subdomain matching: "example.com" matches
// itself and "a.example.com", but not "notexample.com".
func containsDomain(set map[string]struct{}, name string) bool {
	if len(set) == 0 || name == "" {
		return false
	}
	for {
		if _, ok := set[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

// parseLine extracts a domain from a blocklist line. It supports blank lines,
// comments beginning with '#', plain domains, and hosts-file lines of the form
// "0.0.0.0 domain". ok is false for lines that should be skipped.
func parseLine(line string) (domain string, ok bool) {
	// Strip inline comments.
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		// hosts-file style: first field is an IP address.
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			return validDomain(fields[1])
		}
	}
	if len(fields) == 1 {
		return validDomain(fields[0])
	}
	return "", false
}

func validDomain(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	// Allow and normalize a leading wildcard, which behaves like the domain
	// itself under exact-plus-subdomain matching.
	s = strings.TrimPrefix(s, "*.")
	// Strip a trailing dot before validation.
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false // IPs are not valid domain entries
	}
	if strings.ContainsAny(s, " \t/:?@[]") {
		return "", false
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return "", false
	}
	n := Normalize(s)
	if n == "" {
		return "", false
	}
	// Require at least one label character and only sane label characters.
	for _, label := range strings.Split(n, ".") {
		if label == "" {
			return "", false
		}
	}
	return n, true
}

// Stats summarizes a load operation.
type Stats struct {
	Block   int
	Allow   int
	Skipped int
}

// load reads both files and builds a snapshot.
func load(blocklistPath, allowlistPath string) (*Snapshot, Stats, error) {
	block, bskip, err := readList(blocklistPath, true)
	if err != nil {
		return nil, Stats{}, err
	}
	allow, askip, err := readList(allowlistPath, false)
	if err != nil {
		return nil, Stats{}, err
	}
	stats := Stats{Block: len(block), Allow: len(allow), Skipped: bskip + askip}
	return &Snapshot{
		block:     block,
		allow:     allow,
		BlockList: blocklistPath,
		AllowList: allowlistPath,
		BlockN:    len(block),
		AllowN:    len(allow),
		LoadedAt:  time.Now().UTC(),
	}, stats, nil
}

// readList reads a policy file. When required is true a missing file is an
// error; otherwise an empty path or missing file yields an empty set. Malformed
// lines are skipped and counted.
func readList(path string, required bool) (map[string]struct{}, int, error) {
	set := make(map[string]struct{})
	if strings.TrimSpace(path) == "" {
		if required {
			return nil, 0, fmt.Errorf("policy file path is empty")
		}
		return set, 0, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !required && errors.Is(err, os.ErrNotExist) {
			return set, 0, nil
		}
		return nil, 0, fmt.Errorf("read policy file %q: %w", path, err)
	}
	skipped := 0
	for _, line := range strings.Split(string(data), "\n") {
		domain, ok := parseLine(line)
		if !ok {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				skipped++
			}
			continue
		}
		set[domain] = struct{}{}
	}
	return set, skipped, nil
}
