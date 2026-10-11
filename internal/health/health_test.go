package health

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"filterproxy/internal/logging"
)

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(logging.Options{Level: "error", Writer: io.Discard})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}

func start(t *testing.T) *Server {
	t.Helper()
	s := New("127.0.0.1:0", false, testLogger(t))
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	s.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func get(t *testing.T, url string, wantStatus int) map[string]string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("get %s status = %d, want %d", url, resp.StatusCode, wantStatus)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

func TestHealthz(t *testing.T) {
	s := start(t)
	get(t, "http://"+s.Addr().String()+"/healthz", http.StatusOK)
}

func TestReadyz(t *testing.T) {
	s := start(t)
	get(t, "http://"+s.Addr().String()+"/readyz", http.StatusServiceUnavailable)
	s.SetReady(true)
	get(t, "http://"+s.Addr().String()+"/readyz", http.StatusOK)
	s.SetReady(false)
	get(t, "http://"+s.Addr().String()+"/readyz", http.StatusServiceUnavailable)
}
