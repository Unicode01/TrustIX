// Package configlog models the signed append-only configuration log. It owns
// event canonicalization and storage contracts, while certificate validation is
// delegated to the trust package.
package configlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trustix.local/trustix/internal/core"
)

var ErrConflict = errors.New("config log conflict")

type Action string

const (
	ActionCreate Action = "create"
	ActionUpsert Action = "upsert"
	ActionDelete Action = "delete"
)

type Event struct {
	DomainID    core.DomainID     `json:"domain_id"`
	EventID     core.EventID      `json:"event_id"`
	Seq         uint64            `json:"seq"`
	PrevHash    string            `json:"prev_hash"`
	Resource    core.ResourcePath `json:"resource"`
	Action      Action            `json:"action"`
	Payload     []byte            `json:"payload"`
	SignerID    core.SignerID     `json:"signer_id"`
	Signature   []byte            `json:"signature"`
	CreatedAt   time.Time         `json:"created_at"`
	EffectiveAt time.Time         `json:"effective_at"`
	AdminProofs []AdminProof      `json:"admin_proofs,omitempty"`
}

type AdminProof struct {
	SignerID    core.SignerID `json:"signer_id"`
	Certificate []byte        `json:"certificate"`
	Method      string        `json:"method"`
	RequestURI  string        `json:"request_uri"`
	BodySHA256  string        `json:"body_sha256"`
	Timestamp   time.Time     `json:"timestamp"`
	Signature   []byte        `json:"signature"`
}

type Head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

type Store interface {
	Append(event Event) error
	AppendBatch(events []Event) error
	ReplaceAll(events []Event) error
	Head() (Head, error)
	Range(fromSeq, toSeq uint64) ([]Event, error)
}

func (event Event) ValidateBasic() error {
	if err := event.DomainID.Validate(); err != nil {
		return err
	}
	if err := event.EventID.Validate(); err != nil {
		return err
	}
	if event.Seq == 0 {
		return fmt.Errorf("event seq is required")
	}
	if event.Seq > 1 && event.PrevHash == "" {
		return fmt.Errorf("event prev_hash is required for seq %d", event.Seq)
	}
	if err := event.Resource.Validate(); err != nil {
		return err
	}
	if event.Action != ActionCreate && event.Action != ActionUpsert && event.Action != ActionDelete {
		return fmt.Errorf("unsupported config action %q", event.Action)
	}
	if err := event.SignerID.Validate(); err != nil {
		return err
	}
	if len(event.Signature) == 0 {
		return fmt.Errorf("event signature is required")
	}
	if event.CreatedAt.IsZero() {
		return fmt.Errorf("event created_at is required")
	}
	return nil
}

func (event Event) SigningBytes() ([]byte, error) {
	canonical := struct {
		DomainID    core.DomainID     `json:"domain_id"`
		EventID     core.EventID      `json:"event_id"`
		Seq         uint64            `json:"seq"`
		PrevHash    string            `json:"prev_hash"`
		Resource    core.ResourcePath `json:"resource"`
		Action      Action            `json:"action"`
		Payload     []byte            `json:"payload"`
		SignerID    core.SignerID     `json:"signer_id"`
		CreatedAt   time.Time         `json:"created_at"`
		EffectiveAt time.Time         `json:"effective_at"`
		AdminProofs []AdminProof      `json:"admin_proofs,omitempty"`
	}{
		DomainID:    event.DomainID,
		EventID:     event.EventID,
		Seq:         event.Seq,
		PrevHash:    event.PrevHash,
		Resource:    event.Resource,
		Action:      event.Action,
		Payload:     event.Payload,
		SignerID:    event.SignerID,
		CreatedAt:   event.CreatedAt,
		EffectiveAt: event.EffectiveAt,
		AdminProofs: event.AdminProofs,
	}
	return json.Marshal(canonical)
}

func (event Event) Hash() (string, error) {
	payload, err := event.SigningBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}
