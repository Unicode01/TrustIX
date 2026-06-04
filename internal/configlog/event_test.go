package configlog

import (
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
)

func TestEventHashExcludesSignature(t *testing.T) {
	event := Event{
		DomainID:  core.DomainID("lab.local"),
		EventID:   core.EventID("evt-1"),
		Seq:       1,
		Resource:  core.ResourcePath("/ix/ix-a/endpoint/sh-udp"),
		Action:    ActionUpsert,
		Payload:   []byte(`{"enabled":true}`),
		SignerID:  core.SignerID("admin-1"),
		Signature: []byte("signature-a"),
		CreatedAt: time.Unix(1, 0).UTC(),
	}

	hashA, err := event.Hash()
	if err != nil {
		t.Fatalf("hash event: %v", err)
	}
	event.Signature = []byte("signature-b")
	hashB, err := event.Hash()
	if err != nil {
		t.Fatalf("hash event: %v", err)
	}
	if hashA != hashB {
		t.Fatalf("hash changed when only signature changed")
	}
}

func TestMemoryStoreRequiresHashChain(t *testing.T) {
	store := NewMemoryStore()
	first := Event{
		DomainID:  core.DomainID("lab.local"),
		EventID:   core.EventID("evt-1"),
		Seq:       1,
		Resource:  core.ResourcePath("/ix/ix-a"),
		Action:    ActionUpsert,
		SignerID:  core.SignerID("admin-1"),
		Signature: []byte("signature"),
		CreatedAt: time.Unix(1, 0).UTC(),
	}
	if err := store.Append(first); err != nil {
		t.Fatalf("append first event: %v", err)
	}

	second := first
	second.EventID = core.EventID("evt-2")
	second.Seq = 2
	second.PrevHash = "wrong"
	if err := store.Append(second); err == nil {
		t.Fatal("expected prev_hash mismatch")
	}
}
