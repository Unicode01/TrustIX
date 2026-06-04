package dataplane

import (
	"time"

	"trustix.local/trustix/internal/core"
)

type TransportPathTelemetry struct {
	Protocol               string          `json:"protocol,omitempty"`
	FlowID                 uint64          `json:"flow_id"`
	Peer                   core.IXID       `json:"peer,omitempty"`
	Endpoint               core.EndpointID `json:"endpoint,omitempty"`
	LocalAddress           string          `json:"local_address,omitempty"`
	RemoteAddress          string          `json:"remote_address,omitempty"`
	SourcePort             uint16          `json:"source_port,omitempty"`
	DestinationPort        uint16          `json:"destination_port,omitempty"`
	CryptoPlacement        CryptoPlacement `json:"crypto_placement,omitempty"`
	TXFrames               uint64          `json:"tx_frames"`
	TXBytes                uint64          `json:"tx_bytes"`
	RXFrames               uint64          `json:"rx_frames"`
	RXBytes                uint64          `json:"rx_bytes"`
	RXLastSequence         uint64          `json:"rx_last_sequence,omitempty"`
	RXExpectedSequence     uint64          `json:"rx_expected_sequence,omitempty"`
	RXSequenceGaps         uint64          `json:"rx_sequence_gaps"`
	RXMissingFrames        uint64          `json:"rx_missing_frames"`
	RXDuplicateOrReordered uint64          `json:"rx_duplicate_or_reordered"`
	RXLossEstimatePPM      uint64          `json:"rx_loss_estimate_ppm"`
	FirstSeen              time.Time       `json:"first_seen,omitempty"`
	LastSeen               time.Time       `json:"last_seen,omitempty"`
}

func (telemetry *TransportPathTelemetry) ObserveTX(bytes int, now time.Time) {
	if telemetry == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	telemetry.ensureSeen(now)
	telemetry.TXFrames++
	if bytes > 0 {
		telemetry.TXBytes += uint64(bytes)
	}
	telemetry.LastSeen = now
}

func (telemetry *TransportPathTelemetry) ObserveTXBatch(frames uint64, bytes uint64, now time.Time) {
	if telemetry == nil || frames == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	telemetry.ensureSeen(now)
	telemetry.TXFrames += frames
	telemetry.TXBytes += bytes
	telemetry.LastSeen = now
}

func (telemetry *TransportPathTelemetry) ObserveRX(sequence uint64, bytes int, now time.Time) {
	telemetry.ObserveRXSpan(sequence, 1, bytes, now)
}

func (telemetry *TransportPathTelemetry) ObserveRXSpan(sequence uint64, sequenceCount uint64, bytes int, now time.Time) {
	if telemetry == nil {
		return
	}
	if sequenceCount == 0 {
		sequenceCount = 1
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	telemetry.ensureSeen(now)
	telemetry.RXFrames++
	if bytes > 0 {
		telemetry.RXBytes += uint64(bytes)
	}
	telemetry.observeRXSequenceSpan(sequence, sequenceCount, 1)
	telemetry.refreshLossEstimate()
	telemetry.LastSeen = now
}

func (telemetry *TransportPathTelemetry) ObserveRXBatch(firstSequence uint64, frames uint64, bytes uint64, now time.Time) {
	telemetry.ObserveRXBatchSpan(firstSequence, frames, frames, bytes, now)
}

func (telemetry *TransportPathTelemetry) ObserveRXBatchSpan(firstSequence uint64, frames uint64, sequenceCount uint64, bytes uint64, now time.Time) {
	if telemetry == nil || frames == 0 {
		return
	}
	if sequenceCount == 0 {
		sequenceCount = frames
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	telemetry.ensureSeen(now)
	telemetry.RXFrames += frames
	telemetry.RXBytes += bytes
	if firstSequence != 0 {
		lastSequence := firstSequence + sequenceCount - 1
		if lastSequence < firstSequence {
			sequence := firstSequence
			for i := uint64(0); i < sequenceCount; i++ {
				telemetry.observeRXSequence(sequence)
				sequence++
			}
		} else {
			switch {
			case telemetry.RXLastSequence == 0:
				telemetry.RXLastSequence = lastSequence
				telemetry.RXExpectedSequence = lastSequence + 1
			case firstSequence == telemetry.RXExpectedSequence:
				telemetry.RXLastSequence = lastSequence
				telemetry.RXExpectedSequence = lastSequence + 1
			case firstSequence > telemetry.RXExpectedSequence:
				telemetry.RXSequenceGaps++
				telemetry.RXMissingFrames += firstSequence - telemetry.RXExpectedSequence
				telemetry.RXLastSequence = lastSequence
				telemetry.RXExpectedSequence = lastSequence + 1
			default:
				reordered := telemetry.RXExpectedSequence - firstSequence
				if reordered >= sequenceCount {
					telemetry.RXDuplicateOrReordered += frames
				} else {
					telemetry.RXDuplicateOrReordered += reordered
					telemetry.RXLastSequence = lastSequence
					telemetry.RXExpectedSequence = lastSequence + 1
				}
			}
		}
	}
	telemetry.refreshLossEstimate()
	telemetry.LastSeen = now
}

func (telemetry *TransportPathTelemetry) observeRXSequence(sequence uint64) {
	telemetry.observeRXSequenceSpan(sequence, 1, 1)
}

func (telemetry *TransportPathTelemetry) observeRXSequenceSpan(sequence uint64, sequenceCount uint64, deliveredFrames uint64) {
	if sequenceCount == 0 {
		sequenceCount = 1
	}
	if deliveredFrames == 0 {
		deliveredFrames = 1
	}
	lastSequence := sequence + sequenceCount - 1
	if lastSequence < sequence {
		for i := uint64(0); i < sequenceCount; i++ {
			telemetry.observeRXSequence(sequence + i)
		}
		return
	}
	switch {
	case sequence == 0:
	case telemetry.RXLastSequence == 0:
		telemetry.RXLastSequence = lastSequence
		telemetry.RXExpectedSequence = lastSequence + 1
	case sequence == telemetry.RXExpectedSequence:
		telemetry.RXLastSequence = lastSequence
		telemetry.RXExpectedSequence = lastSequence + 1
	case sequence > telemetry.RXExpectedSequence:
		telemetry.RXSequenceGaps++
		telemetry.RXMissingFrames += sequence - telemetry.RXExpectedSequence
		telemetry.RXLastSequence = lastSequence
		telemetry.RXExpectedSequence = lastSequence + 1
	default:
		reordered := telemetry.RXExpectedSequence - sequence
		if reordered >= sequenceCount {
			telemetry.RXDuplicateOrReordered += deliveredFrames
		} else {
			telemetry.RXDuplicateOrReordered += reordered
			telemetry.RXLastSequence = lastSequence
			telemetry.RXExpectedSequence = lastSequence + 1
		}
	}
}

func (telemetry *TransportPathTelemetry) ensureSeen(now time.Time) {
	if telemetry.FirstSeen.IsZero() {
		telemetry.FirstSeen = now
	}
}

func (telemetry *TransportPathTelemetry) refreshLossEstimate() {
	denominator := telemetry.RXFrames + telemetry.RXMissingFrames
	if denominator == 0 {
		telemetry.RXLossEstimatePPM = 0
		return
	}
	telemetry.RXLossEstimatePPM = telemetry.RXMissingFrames * 1_000_000 / denominator
}
