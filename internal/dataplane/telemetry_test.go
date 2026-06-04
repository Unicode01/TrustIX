package dataplane

import (
	"testing"
	"time"
)

func TestTransportPathTelemetryTracksSequenceGapsWithoutACK(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var telemetry TransportPathTelemetry

	telemetry.ObserveRX(1, 100, now)
	telemetry.ObserveRX(2, 100, now.Add(time.Second))
	telemetry.ObserveRX(5, 100, now.Add(2*time.Second))
	telemetry.ObserveRX(4, 100, now.Add(3*time.Second))
	telemetry.ObserveTX(120, now.Add(4*time.Second))

	if telemetry.RXFrames != 4 || telemetry.RXBytes != 400 || telemetry.TXFrames != 1 || telemetry.TXBytes != 120 {
		t.Fatalf("counters = %+v", telemetry)
	}
	if telemetry.RXSequenceGaps != 1 || telemetry.RXMissingFrames != 2 {
		t.Fatalf("gap counters = gaps %d missing %d, want 1/2", telemetry.RXSequenceGaps, telemetry.RXMissingFrames)
	}
	if telemetry.RXDuplicateOrReordered != 1 {
		t.Fatalf("duplicate/reordered = %d, want 1", telemetry.RXDuplicateOrReordered)
	}
	if telemetry.RXLastSequence != 5 || telemetry.RXExpectedSequence != 6 {
		t.Fatalf("sequence state = last %d expected %d, want 5/6", telemetry.RXLastSequence, telemetry.RXExpectedSequence)
	}
	if telemetry.RXLossEstimatePPM != 333333 {
		t.Fatalf("loss ppm = %d, want 333333", telemetry.RXLossEstimatePPM)
	}
	if telemetry.FirstSeen.IsZero() || telemetry.LastSeen.IsZero() {
		t.Fatalf("seen timestamps were not recorded: %+v", telemetry)
	}
}

func TestTransportPathTelemetryTracksSequentialRXBatch(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var telemetry TransportPathTelemetry

	telemetry.ObserveRXBatch(10, 4, 400, now)
	telemetry.ObserveRXBatch(14, 2, 200, now.Add(time.Second))
	telemetry.ObserveRXBatch(20, 3, 300, now.Add(2*time.Second))
	telemetry.ObserveRXBatch(18, 2, 200, now.Add(3*time.Second))

	if telemetry.RXFrames != 11 || telemetry.RXBytes != 1100 {
		t.Fatalf("counters = %+v", telemetry)
	}
	if telemetry.RXLastSequence != 22 || telemetry.RXExpectedSequence != 23 {
		t.Fatalf("sequence state = last %d expected %d, want 22/23", telemetry.RXLastSequence, telemetry.RXExpectedSequence)
	}
	if telemetry.RXSequenceGaps != 1 || telemetry.RXMissingFrames != 4 {
		t.Fatalf("gap counters = gaps %d missing %d, want 1/4", telemetry.RXSequenceGaps, telemetry.RXMissingFrames)
	}
	if telemetry.RXDuplicateOrReordered != 2 {
		t.Fatalf("duplicate/reordered = %d, want 2", telemetry.RXDuplicateOrReordered)
	}
}

func TestTransportPathTelemetryTracksWrappedRXBatch(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var telemetry TransportPathTelemetry

	telemetry.ObserveRXBatch(^uint64(1), 3, 300, now)

	if telemetry.RXFrames != 3 || telemetry.RXBytes != 300 {
		t.Fatalf("counters = %+v", telemetry)
	}
	if telemetry.RXLastSequence != ^uint64(0) || telemetry.RXExpectedSequence != 0 {
		t.Fatalf("sequence state = last %d expected %d, want max/0", telemetry.RXLastSequence, telemetry.RXExpectedSequence)
	}
}

func TestTransportPathTelemetryTracksRXSpanWithoutFalseGap(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var telemetry TransportPathTelemetry

	telemetry.ObserveRXSpan(77, 3, 2000, now)
	telemetry.ObserveRX(80, 100, now.Add(time.Second))

	if telemetry.RXFrames != 2 || telemetry.RXBytes != 2100 {
		t.Fatalf("counters = %+v", telemetry)
	}
	if telemetry.RXLastSequence != 80 || telemetry.RXExpectedSequence != 81 {
		t.Fatalf("sequence state = last %d expected %d, want 80/81", telemetry.RXLastSequence, telemetry.RXExpectedSequence)
	}
	if telemetry.RXSequenceGaps != 0 || telemetry.RXMissingFrames != 0 || telemetry.RXDuplicateOrReordered != 0 {
		t.Fatalf("unexpected sequence anomaly counters: %+v", telemetry)
	}
}

func TestTransportPathTelemetryTracksRXBatchSpanWithoutFalseGap(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var telemetry TransportPathTelemetry

	telemetry.ObserveRXBatchSpan(77, 2, 4, 2400, now)
	telemetry.ObserveRX(81, 100, now.Add(time.Second))

	if telemetry.RXFrames != 3 || telemetry.RXBytes != 2500 {
		t.Fatalf("counters = %+v", telemetry)
	}
	if telemetry.RXLastSequence != 81 || telemetry.RXExpectedSequence != 82 {
		t.Fatalf("sequence state = last %d expected %d, want 81/82", telemetry.RXLastSequence, telemetry.RXExpectedSequence)
	}
	if telemetry.RXSequenceGaps != 0 || telemetry.RXMissingFrames != 0 || telemetry.RXDuplicateOrReordered != 0 {
		t.Fatalf("unexpected sequence anomaly counters: %+v", telemetry)
	}
}
