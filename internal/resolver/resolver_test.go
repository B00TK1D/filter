package resolver

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestLookupHostIPLiteral(t *testing.T) {
	r, err := New([]string{"127.0.0.1:9"}, time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	addrs, err := r.LookupHost(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("addrs = %v", addrs)
	}
}

func TestNewRequiresServers(t *testing.T) {
	if _, err := New(nil, time.Second, 0); err == nil {
		t.Fatal("expected error for empty server list")
	}
}

func TestServersCopy(t *testing.T) {
	src := []string{"1.1.1.1:53"}
	r, err := New(src, time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	src[0] = "9.9.9.9:53"
	if got := r.Servers(); got[0] != "1.1.1.1:53" {
		t.Fatalf("servers mutated externally: %v", got)
	}
}
