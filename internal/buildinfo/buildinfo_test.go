package buildinfo

import (
	"errors"
	"io"
	"testing"
)

func TestWriteTextReturnsWriterError(t *testing.T) {
	wantErr := errors.New("injected writer failure")
	err := WriteText(errorWriter{err: wantErr}, Info{Version: "test"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WriteText error = %v, want %v", err, wantErr)
	}
}

func TestWriteTextReturnsShortWrite(t *testing.T) {
	err := WriteText(shortWriter{}, Info{Version: "test"})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteText error = %v, want %v", err, io.ErrShortWrite)
	}
}

type errorWriter struct {
	err error
}

func (writer errorWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

type shortWriter struct{}

func (shortWriter) Write(payload []byte) (int, error) {
	return len(payload) - 1, nil
}
