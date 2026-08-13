package daemon

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

const (
	httpTLSHandshakeErrorLogBurst  = 5
	httpTLSHandshakeErrorLogWindow = time.Minute
)

var httpTLSHandshakeErrorMarker = []byte("http: TLS handshake error from ")

type httpServerErrorLogWriter struct {
	mu          sync.Mutex
	destination io.Writer
	now         func() time.Time
	windowStart time.Time
	emitted     int
	suppressed  uint64
}

func newHTTPServerErrorLogger() *log.Logger {
	return log.New(newHTTPServerErrorLogWriter(os.Stderr), "", log.LstdFlags)
}

func newHTTPServerErrorLogWriter(destination io.Writer) *httpServerErrorLogWriter {
	return &httpServerErrorLogWriter{
		destination: destination,
		now:         time.Now,
	}
}

func (writer *httpServerErrorLogWriter) Write(payload []byte) (int, error) {
	if writer == nil || writer.destination == nil {
		return len(payload), nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if !bytes.Contains(payload, httpTLSHandshakeErrorMarker) {
		if err := writeHTTPServerLog(writer.destination, payload); err != nil {
			return 0, err
		}
		return len(payload), nil
	}

	now := writer.now()
	if writer.windowStart.IsZero() || now.Before(writer.windowStart) ||
		now.Sub(writer.windowStart) >= httpTLSHandshakeErrorLogWindow {
		if writer.suppressed > 0 {
			summary := prefixedHTTPServerLogLine(payload, fmt.Sprintf(
				"http: suppressed %d TLS handshake errors during the previous rate-limit window",
				writer.suppressed,
			))
			if err := writeHTTPServerLog(writer.destination, summary); err != nil {
				return 0, err
			}
		}
		writer.windowStart = now
		writer.emitted = 0
		writer.suppressed = 0
	}
	if writer.emitted < httpTLSHandshakeErrorLogBurst {
		writer.emitted++
		if err := writeHTTPServerLog(writer.destination, payload); err != nil {
			return 0, err
		}
		return len(payload), nil
	}

	writer.suppressed++
	if writer.suppressed == 1 {
		notice := prefixedHTTPServerLogLine(payload,
			"http: TLS handshake error log rate limit reached; suppressing repeated errors")
		if err := writeHTTPServerLog(writer.destination, notice); err != nil {
			return 0, err
		}
	}
	return len(payload), nil
}

func writeHTTPServerLog(destination io.Writer, payload []byte) error {
	written, err := destination.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

func prefixedHTTPServerLogLine(reference []byte, message string) []byte {
	prefixLength := bytes.Index(reference, httpTLSHandshakeErrorMarker)
	line := make([]byte, 0, max(prefixLength, 0)+len(message)+1)
	if prefixLength > 0 {
		line = append(line, reference[:prefixLength]...)
	}
	line = append(line, message...)
	line = append(line, '\n')
	return line
}
