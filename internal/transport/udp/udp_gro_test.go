package udp

import "testing"

func TestAppendUDPGROPayloadSegments(t *testing.T) {
	payload := []byte("aaabbbcc")
	var packets [][]byte
	packets, segments := appendUDPGROPayloadSegments(packets, payload, 3)
	if segments != 3 {
		t.Fatalf("segments = %d, want 3", segments)
	}
	if got, want := len(packets), 3; got != want {
		t.Fatalf("packet count = %d, want %d", got, want)
	}
	if string(packets[0]) != "aaa" || string(packets[1]) != "bbb" || string(packets[2]) != "cc" {
		t.Fatalf("packets = %q", packets)
	}
	if &packets[0][0] != &payload[0] {
		t.Fatal("first segment does not borrow original payload")
	}
}

func TestAppendUDPGROPayloadSegmentsKeepsSinglePacket(t *testing.T) {
	payload := []byte("packet")
	for _, segmentSize := range []int{0, -1, len(payload), len(payload) + 1} {
		packets, segments := appendUDPGROPayloadSegments(nil, payload, segmentSize)
		if segments != 1 {
			t.Fatalf("segmentSize=%d segments=%d, want 1", segmentSize, segments)
		}
		if len(packets) != 1 || string(packets[0]) != "packet" {
			t.Fatalf("segmentSize=%d packets=%q", segmentSize, packets)
		}
	}
}

func TestSessionRecvPacketsWithReleaseKeepsPendingBorrowedPackets(t *testing.T) {
	session := &session{}
	released := false
	borrowed := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	packets := borrowed
	release := func() { released = true }
	max := 2

	if len(packets) > max {
		received := packets
		if release != nil {
			copied := make([][]byte, max)
			for i, packet := range packets[:max] {
				copied[i] = append([]byte(nil), packet...)
			}
			packets = copied
		}
		session.recvPending = udpPacketBatch{packets: received[max:], release: release}
		if release == nil {
			packets = received[:max]
		}
		release = nil
	}

	if len(packets) != 2 || string(packets[0]) != "one" || string(packets[1]) != "two" {
		t.Fatalf("first packets = %q, want one/two", packets)
	}
	if len(session.recvPending.packets) != 1 || string(session.recvPending.packets[0]) != "three" {
		t.Fatalf("pending packets = %q, want three", session.recvPending.packets)
	}
	if release != nil || released {
		t.Fatalf("release nil=%t released=%t, want true/false", release == nil, released)
	}
	pending, pendingRelease, err := session.recvPendingLocked(8)
	if err != nil {
		t.Fatalf("recv pending: %v", err)
	}
	if len(pending) != 1 || string(pending[0]) != "three" {
		t.Fatalf("pending recv = %q, want three", pending)
	}
	if pendingRelease == nil {
		t.Fatal("pending release is nil")
	}
	pendingRelease()
	if !released {
		t.Fatal("borrowed release was not called")
	}
}

func TestCompactUDPPacketBatchForQueueReleasesOversizedArena(t *testing.T) {
	arena := make([]byte, 4*1024*1024)
	copy(arena[0:4], []byte("ping"))
	copy(arena[1024:1028], []byte("pong"))
	released := false
	batch := udpPacketBatch{
		packets:       [][]byte{arena[0:4], arena[1024:1028]},
		release:       func() { released = true },
		retainedBytes: cap(arena),
	}

	compacted := compactUDPPacketBatchForQueue(batch, 0, userspaceUDPListenerBufferDefault)
	if !released {
		t.Fatal("oversized borrowed batch was not released after compaction")
	}
	if compacted.release != nil {
		t.Fatal("compacted batch retained borrowed release")
	}
	if len(compacted.packets) != 2 || string(compacted.packets[0]) != "ping" || string(compacted.packets[1]) != "pong" {
		t.Fatalf("compacted packets = %q", compacted.packets)
	}
	if &compacted.packets[0][0] == &arena[0] {
		t.Fatal("compacted payload still points at oversized arena")
	}
	if got, wantMax := cap(compacted.packets[0]), len("ping")+len("pong"); got > wantMax {
		t.Fatalf("compacted first packet cap = %d, want <= %d", got, wantMax)
	}
}

func TestCompactUDPPacketBatchForQueueKeepsDenseArena(t *testing.T) {
	arena := []byte("pingpong")
	released := false
	batch := udpPacketBatch{
		packets:       [][]byte{arena[:4], arena[4:]},
		release:       func() { released = true },
		retainedBytes: cap(arena),
	}

	kept := compactUDPPacketBatchForQueue(batch, 0, userspaceUDPListenerBufferDefault)
	if released {
		t.Fatal("dense borrowed batch was released unexpectedly")
	}
	if kept.release == nil {
		t.Fatal("dense borrowed batch lost release callback")
	}
	kept.release()
	if !released {
		t.Fatal("dense borrowed release callback was not preserved")
	}
}
