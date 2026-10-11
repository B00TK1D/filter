// Package logging provides structured logging with privacy-aware helpers.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// Options configures the logger construction.
type Options struct {
	// Level is one of debug, info, warn, error.
	Level string
	// Format is "json" or "text".
	Format string
	// Output is "" for stdout or a file path (appended, created if missing).
	Output string
	// Writer overrides Output when non-nil (used by tests).
	Writer io.Writer
	// LogURLs enables logging of full paths and query strings.
	LogURLs bool
	// PrivacyMode limits logging to hostnames and coarse metadata.
	PrivacyMode bool
}

// Logger bundles a slog.Logger with privacy configuration.
type Logger struct {
	*slog.Logger
	logURLs     bool
	privacyMode bool
	closer      io.Closer
}

// URL returns the path/query to log for a request, honouring privacy settings.
// It returns "" when URL logging is disabled.
func (l *Logger) URL(r *http.Request) string {
	if l.privacyMode || !l.logURLs || r == nil || r.URL == nil {
		return ""
	}
	q := r.URL.RequestURI()
	if q == "" {
		return "/"
	}
	return q
}

// LogURLs reports whether full URL logging is enabled.
func (l *Logger) LogURLs() bool { return l.logURLs && !l.privacyMode }

// PrivacyMode reports whether privacy mode is enabled.
func (l *Logger) PrivacyMode() bool { return l.privacyMode }

// Close closes the underlying output when it is a file.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// New builds a Logger from Options.
func New(opts Options) (*Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	var w io.Writer = os.Stdout
	var closer io.Closer
	switch {
	case opts.Writer != nil:
		w = opts.Writer
	case opts.Output != "" && !strings.EqualFold(opts.Output, "stdout"):
		f, err := os.OpenFile(opts.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, fmt.Errorf("open log output: %w", err)
		}
		w = f
		closer = f
	}

	handlerOpts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(opts.Format) {
	case "", "json":
		handler = slog.NewJSONHandler(w, handlerOpts)
	case "text":
		handler = slog.NewTextHandler(w, handlerOpts)
	default:
		return nil, fmt.Errorf("unknown log format %q", opts.Format)
	}

	return &Logger{
		Logger:      slog.New(handler),
		logURLs:     opts.LogURLs,
		privacyMode: opts.PrivacyMode,
		closer:      closer,
	}, nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", s)
	}
}

// RedactedHeaders returns a copy of h with sensitive headers removed.
func RedactedHeaders(h http.Header) map[string][]string {
	if h == nil {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		switch strings.ToLower(k) {
		case "authorization", "proxy-authorization", "cookie", "set-cookie",
			"x-api-key", "x-auth-token", "proxy-authenticate":
			out[k] = []string{"[redacted]"}
		default:
			cp := make([]string, len(v))
			copy(cp, v)
			out[k] = cp
		}
	}
	return out
}
