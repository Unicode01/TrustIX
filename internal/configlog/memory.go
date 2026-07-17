package configlog

import (
	"fmt"
	"sync"
)

type MemoryStore struct {
	mu     sync.RWMutex
	events []Event
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (store *MemoryStore) Append(event Event) error {
	return store.AppendBatch([]Event{event})
}

func (store *MemoryStore) AppendBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	next := append([]Event(nil), store.events...)
	for _, event := range events {
		if err := event.ValidateBasic(); err != nil {
			return err
		}
		expectedSeq := uint64(len(next) + 1)
		if event.Seq != expectedSeq {
			return fmt.Errorf("%w: expected seq %d, got %d", ErrConflict, expectedSeq, event.Seq)
		}
		if len(next) == 0 {
			if event.PrevHash != "" {
				return fmt.Errorf("%w: first event must not have prev_hash", ErrConflict)
			}
			next = append(next, event)
			continue
		}
		prevHash, err := next[len(next)-1].Hash()
		if err != nil {
			return err
		}
		if event.PrevHash != prevHash {
			return fmt.Errorf("%w: prev_hash mismatch", ErrConflict)
		}
		next = append(next, event)
	}
	store.events = next
	return nil
}

func (store *MemoryStore) ReplaceAll(events []Event) error {
	next := NewMemoryStore()
	if err := next.AppendBatch(events); err != nil {
		return err
	}
	next.mu.RLock()
	copied := append([]Event(nil), next.events...)
	next.mu.RUnlock()

	store.mu.Lock()
	store.events = copied
	store.mu.Unlock()
	return nil
}

func (store *MemoryStore) Head() (Head, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if len(store.events) == 0 {
		return Head{}, nil
	}
	last := store.events[len(store.events)-1]
	hash, err := last.Hash()
	if err != nil {
		return Head{}, err
	}
	return Head{Seq: last.Seq, Hash: hash}, nil
}

func (store *MemoryStore) Range(fromSeq, toSeq uint64) ([]Event, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if fromSeq == 0 {
		return nil, fmt.Errorf("from seq is required")
	}
	if toSeq < fromSeq {
		return nil, fmt.Errorf("to seq %d is before from seq %d", toSeq, fromSeq)
	}
	if toSeq > uint64(len(store.events)) {
		return nil, fmt.Errorf("to seq %d exceeds head %d", toSeq, len(store.events))
	}

	result := make([]Event, 0, toSeq-fromSeq+1)
	for seq := fromSeq; seq <= toSeq; seq++ {
		result = append(result, store.events[seq-1])
	}
	return result, nil
}

func (store *MemoryStore) snapshot() []Event {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return append([]Event(nil), store.events...)
}
