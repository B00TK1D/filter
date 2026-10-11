package intercept

import (
	"errors"
	"net"
	"testing"
)

func TestOriginalDestinationUnsupportedConnType(t *testing.T) {
	// net.Pipe connections are not *net.TCPConn and cannot be queried.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if _, err := OriginalDestination(server); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestMarkControlZero(t *testing.T) {
	if MarkControl(0) != nil {
		t.Fatal("zero mark should not install a control function")
	}
}
