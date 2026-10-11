package httpproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

// responseRecorder records the status code and byte count of a response while
// forwarding optional interfaces to the wrapped writer.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	bytes       int64
	err         bool
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, status: http.StatusOK}
}

func (w *responseRecorder) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseRecorder) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *responseRecorder) statusCode() int { return w.status }

func (w *responseRecorder) markError() { w.err = true }

func (w *responseRecorder) errored() bool { return w.err }

// Unwrap exposes the underlying writer to http.ResponseController.
func (w *responseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (w *responseRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *responseRecorder) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		w.bytes += n
		return n, err
	}
	n, err := io.Copy(writerOnly{w}, r)
	return n, err
}

// writerOnly hides extra methods so io.Copy does not recurse into ReadFrom.
type writerOnly struct{ io.Writer }
