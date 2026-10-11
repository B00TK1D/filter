package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return path
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"Example.COM":        "example.com",
		"example.com.":       "example.com",
		"  example.com  ":    "example.com",
		"EXAMPLE.com.":       "example.com",
		"sub.Example.com.":   "sub.example.com",
		"":                   "",
		".":                  "",
		"192.168.0.1":        "192.168.0.1",
		"[2001:db8::1]":      "2001:db8::1",
		"BÜCHER.example":     "xn--bcher-kva.example",
		"xn--bcher-kva.test": "xn--bcher-kva.test",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBlockSubdomains(t *testing.T) {
	path := writeTemp(t, "example.com\n")
	m, _, err := New(path, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	blocked := []string{"example.com", "EXAMPLE.com.", "a.example.com", "deep.a.example.com"}
	for _, h := range blocked {
		if !m.Blocks(h) {
			t.Errorf("expected %q to be blocked", h)
		}
	}
	allowed := []string{"notexample.com", "example.com.evil.test", "example.org", "com", ""}
	for _, h := range allowed {
		if m.Blocks(h) {
			t.Errorf("expected %q to be allowed", h)
		}
	}
}

func TestAllowlistPrecedence(t *testing.T) {
	block := writeTemp(t, "example.com\n")
	allow := writeTemp(t, "safe.example.com\n")
	m, _, err := New(block, allow)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.Blocks("example.com") {
		t.Error("example.com should be blocked")
	}
	if !m.Blocks("other.example.com") {
		t.Error("other.example.com should be blocked")
	}
	if m.Blocks("safe.example.com") {
		t.Error("safe.example.com should be allowlisted")
	}
	if m.Blocks("sub.safe.example.com") {
		t.Error("subdomain of allowlisted entry should be allowlisted")
	}
	res := m.Decide("safe.example.com")
	if res.Reason != "allowlist" {
		t.Errorf("reason = %q, want allowlist", res.Reason)
	}
}

func TestParsingForms(t *testing.T) {
	content := `
# comment
   
example.com   # inline comment
0.0.0.0 hosts-blocked.test
127.0.0.1    another.test
*.wild.test
not a domain with spaces
http://bad.test/path
`
	path := writeTemp(t, content)
	m, stats, err := New(path, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, h := range []string{"example.com", "hosts-blocked.test", "another.test", "wild.test", "x.wild.test"} {
		if !m.Blocks(h) {
			t.Errorf("expected %q blocked", h)
		}
	}
	for _, h := range []string{"bad.test", "not"} {
		if m.Blocks(h) {
			t.Errorf("expected %q not blocked", h)
		}
	}
	if stats.Block < 4 {
		t.Errorf("block entries = %d, want >= 4", stats.Block)
	}
	if stats.Skipped == 0 {
		t.Errorf("expected some skipped entries, got %d", stats.Skipped)
	}
}

func TestReload(t *testing.T) {
	path := writeTemp(t, "first.test\n")
	m, _, err := New(path, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.Blocks("first.test") {
		t.Fatal("first.test should be blocked initially")
	}
	if err := os.WriteFile(path, []byte("second.test\n"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if _, _, err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if m.Blocks("first.test") {
		t.Error("first.test should be allowed after reload")
	}
	if !m.Blocks("second.test") {
		t.Error("second.test should be blocked after reload")
	}
}

func TestReloadFailureKeepsSnapshot(t *testing.T) {
	path := writeTemp(t, "keep.test\n")
	m, _, err := New(path, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, _, err := m.Reload(); err == nil {
		t.Fatal("expected reload error for missing file")
	}
	if !m.Blocks("keep.test") {
		t.Error("previous snapshot should remain active after failed reload")
	}
}

func TestMissingBlocklistIsError(t *testing.T) {
	if _, _, err := New(filepath.Join(t.TempDir(), "missing.txt"), ""); err == nil {
		t.Fatal("expected error for missing blocklist")
	}
}

func TestEmptyAllowlistAllowed(t *testing.T) {
	path := writeTemp(t, "x.test\n")
	if _, _, err := New(path, ""); err != nil {
		t.Fatalf("empty allowlist should be fine: %v", err)
	}
}
