package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPServerErrorLogWriterLimitsTLSHandshakeErrors(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writer := newHTTPServerErrorLogWriter(&output)
	writer.now = func() time.Time { return now }

	const extraErrors = 3
	for index := 0; index < httpTLSHandshakeErrorLogBurst+extraErrors; index++ {
		line := fmt.Sprintf(
			"2026/08/13 12:00:00 http: TLS handshake error from 192.0.2.1:%d: remote error: tls: unknown certificate\n",
			40000+index,
		)
		if written, err := writer.Write([]byte(line)); err != nil || written != len(line) {
			t.Fatalf("write handshake error %d = %d, %v", index, written, err)
		}
	}

	logged := output.String()
	if got := strings.Count(logged, "TLS handshake error from"); got != httpTLSHandshakeErrorLogBurst {
		t.Fatalf("logged TLS handshake errors = %d, want %d\n%s", got, httpTLSHandshakeErrorLogBurst, logged)
	}
	if got := strings.Count(logged, "TLS handshake error log rate limit reached"); got != 1 {
		t.Fatalf("rate-limit notices = %d, want 1\n%s", got, logged)
	}

	now = now.Add(httpTLSHandshakeErrorLogWindow)
	next := []byte("2026/08/13 12:01:00 http: TLS handshake error from 192.0.2.2:41000: EOF\n")
	if _, err := writer.Write(next); err != nil {
		t.Fatalf("write handshake error in next window: %v", err)
	}
	logged = output.String()
	if !strings.Contains(logged, fmt.Sprintf("suppressed %d TLS handshake errors", extraErrors)) {
		t.Fatalf("suppression summary missing from log:\n%s", logged)
	}
	if !strings.Contains(logged, string(next)) {
		t.Fatalf("first error in next window was not logged:\n%s", logged)
	}
}

func TestHTTPServerErrorLogWriterPreservesOtherErrors(t *testing.T) {
	var output bytes.Buffer
	writer := newHTTPServerErrorLogWriter(&output)
	line := []byte("2026/08/13 12:00:00 http: Accept error: too many open files\n")
	if written, err := writer.Write(line); err != nil || written != len(line) {
		t.Fatalf("write non-handshake error = %d, %v", written, err)
	}
	if got := output.String(); got != string(line) {
		t.Fatalf("non-handshake error = %q, want %q", got, line)
	}
}

func TestHTTPServerErrorLogWriterSerializesConcurrentWrites(t *testing.T) {
	var output bytes.Buffer
	writer := newHTTPServerErrorLogWriter(&output)
	const writes = 32
	var wait sync.WaitGroup
	wait.Add(writes)
	for index := 0; index < writes; index++ {
		go func() {
			defer wait.Done()
			line := []byte("http: Accept error: temporary failure\n")
			if _, err := writer.Write(line); err != nil {
				t.Errorf("write concurrent server error: %v", err)
			}
		}()
	}
	wait.Wait()
	if got := strings.Count(output.String(), "temporary failure"); got != writes {
		t.Fatalf("concurrent server error lines = %d, want %d", got, writes)
	}
}

func TestHTTPServerErrorLogWriterReportsShortWrite(t *testing.T) {
	writer := newHTTPServerErrorLogWriter(shortHTTPServerLogWriter{})
	if written, err := writer.Write([]byte("http: Accept error: temporary failure\n")); written != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write = %d, %v, want 0, %v", written, err, io.ErrShortWrite)
	}
}

type shortHTTPServerLogWriter struct{}

func (shortHTTPServerLogWriter) Write(payload []byte) (int, error) {
	return max(len(payload)-1, 0), nil
}
