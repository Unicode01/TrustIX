package ebpf

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestCaptureChecksumAddBytesMatchesReference(t *testing.T) {
	initialSums := []uint32{0, 1, 0xffff, 8 * 0xffff}
	check := func(name string, payload []byte) {
		t.Helper()
		for _, initial := range initialSums {
			got := captureChecksumFold(captureChecksumAddBytes(initial, payload))
			want := captureChecksumReference(initial, payload)
			if got != want {
				t.Fatalf("%s len=%d initial=%#x checksum=%#04x, want %#04x", name, len(payload), initial, got, want)
			}
		}
	}

	check("empty", nil)
	check("one", []byte{0xff})
	check("odd", []byte{0x01, 0x23, 0x45})
	check("carry", filledChecksumPayload(65535, 0xff))
	check("zeros", make([]byte, 65535))
	for size := 0; size <= 80; size++ {
		payload := make([]byte, size)
		for index := range payload {
			payload[index] = byte(index*37 + size)
		}
		check("boundary", payload)
	}
	rng := rand.New(rand.NewSource(1))
	for index := 0; index < 2000; index++ {
		size := rng.Intn(65536)
		payload := make([]byte, size)
		_, _ = rng.Read(payload)
		check("random", payload)
	}
}

func filledChecksumPayload(size int, value byte) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = value
	}
	return payload
}

func captureChecksumReference(sum uint32, payload []byte) uint16 {
	wide := uint64(sum)
	for len(payload) > 1 {
		wide += uint64(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		wide += uint64(payload[0]) << 8
	}
	for wide>>16 != 0 {
		wide = (wide & 0xffff) + (wide >> 16)
	}
	return ^uint16(wide)
}

func BenchmarkCaptureChecksumAddBytes4(b *testing.B) {
	benchmarkCaptureChecksumAddBytes(b, 4)
}

func BenchmarkCaptureChecksumAddBytes1500(b *testing.B) {
	benchmarkCaptureChecksumAddBytes(b, 1500)
}

func BenchmarkCaptureChecksumAddBytes64K(b *testing.B) {
	benchmarkCaptureChecksumAddBytes(b, 65535)
}

var captureChecksumBenchmarkSink uint16

func benchmarkCaptureChecksumAddBytes(b *testing.B, size int) {
	payload := make([]byte, size)
	_, _ = rand.New(rand.NewSource(1)).Read(payload)
	b.SetBytes(int64(size))
	b.ResetTimer()
	var checksum uint16
	for index := 0; index < b.N; index++ {
		checksum = captureChecksumFold(captureChecksumAddBytes(0, payload))
	}
	captureChecksumBenchmarkSink = checksum
}
