// Package health exposes liveness and readiness endpoints on the management
// address.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"filterproxy/internal/logging"
)

// Server serves health endpoints.
type Server struct {
	addr             string
	allowNonLoopback bool
	log              *logging.Logger
	ready            atomic.Bool
	server           *http.Server
	ln               net.Listener
	errCh            chan error
}

// New builds a health server.
func New(addr string, allowNonLoopback bool, logger *logging.Logger) *Server {
	return &Server{addr: addr, allowNonLoopback: allowNonLoopback, log: logger}
}

// SetReady marks the service ready (or not) for /readyz.
func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }

// Listen binds the management socket.
func (s *Server) Listen() error {
	if s.addr == "" {
		return errors.New("health: management address is empty")
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen management %s: %w", s.addr, err)
	}
	if !s.allowNonLoopback {
		if err := checkLoopback(ln.Addr()); err != nil {
			ln.Close()
			return err
		}
	}
	s.ln = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Addr returns the bound management address.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// ServeErrors returns a channel reporting fatal serve errors.
func (s *Server) ServeErrors() <-chan error { return s.errCh }

// Start begins serving. It should only be called after Listen.
func (s *Server) Start() {
	s.errCh = make(chan error, 1)
	go func() {
		if err := s.server.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.errCh <- fmt.Errorf("management server: %w", err)
		}
	}()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func checkLoopback(addr net.Addr) error {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil
	}
	if !tcp.IP.IsLoopback() {
		return fmt.Errorf("refusing to expose management on non-loopback address %s", addr)
	}
	return nil
}
