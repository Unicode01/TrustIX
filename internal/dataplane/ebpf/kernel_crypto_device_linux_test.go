//go:build linux

package ebpf

import (
	"reflect"
	"testing"
)

func TestKernelCryptoDeviceReplayBatchMatchesPerPacketCommit(t *testing.T) {
	for _, sequences := range [][]uint64{
		rangeUint64ForTest(1, 130),
		{10, 12, 11, 15, 14, 13, 64, 63, 62, 130},
		{1, 9000, 9001, 8999, 9020, 9019},
	} {
		want := newKernelCryptoDeviceReplayTestDevice()
		commitKernelCryptoDeviceReplayPerPacketForTest(t, want, sequences)

		got := newKernelCryptoDeviceReplayTestDevice()
		validateKernelCryptoDeviceReplayBatchForTest(t, got, sequences)

		if got.recvLast != want.recvLast || !reflect.DeepEqual(got.recvSeen, want.recvSeen) {
			t.Fatalf("batch replay state for %v = last %d seen %x, want last %d seen %x", sequences, got.recvLast, got.recvSeen, want.recvLast, want.recvSeen)
		}
	}
}

func TestKernelCryptoDeviceReplayBatchRejectsDuplicate(t *testing.T) {
	device := newKernelCryptoDeviceReplayTestDevice()
	requests := kernelCryptoDeviceReplayOpenRequestsForTest(1, 2, 2)
	if _, _, _, err := device.validateOpenBatchLocked(requests); err == nil {
		t.Fatalf("duplicate sequence in open batch was accepted")
	}
}

func TestKernelCryptoDeviceReplayBatchRejectsAlreadySeen(t *testing.T) {
	device := newKernelCryptoDeviceReplayTestDevice()
	validateKernelCryptoDeviceReplayBatchForTest(t, device, []uint64{1, 2, 3})

	requests := kernelCryptoDeviceReplayOpenRequestsForTest(2)
	if _, _, _, err := device.validateOpenBatchLocked(requests); err == nil {
		t.Fatalf("already seen sequence was accepted")
	}
}

func TestKernelCryptoDeviceReplayBatchAcceptsUnseenOutOfOrder(t *testing.T) {
	device := newKernelCryptoDeviceReplayTestDevice()
	validateKernelCryptoDeviceReplayBatchForTest(t, device, []uint64{10, 12})

	requests := kernelCryptoDeviceReplayOpenRequestsForTest(11)
	_, _, replay, err := device.validateOpenBatchLocked(requests)
	if err != nil {
		t.Fatalf("unseen out-of-order sequence was rejected: %v", err)
	}
	device.commitRecvReplayStateLocked(replay)

	requests = kernelCryptoDeviceReplayOpenRequestsForTest(11)
	if _, _, _, err := device.validateOpenBatchLocked(requests); err == nil {
		t.Fatalf("committed out-of-order sequence replay was accepted")
	}
}

func TestKernelCryptoDeviceNoReplayAcceptsDuplicates(t *testing.T) {
	device := newKernelCryptoDeviceReplayTestDevice()
	device.flow.RecvFlags = kernelCryptoFlowFlagNoReplay
	device.recvLast = 32
	device.recvSeen[0] = ^uint64(0)

	requests := kernelCryptoDeviceReplayOpenRequestsForTest(2, 2, 1)
	_, _, replay, err := device.validateOpenBatchLocked(requests)
	if err != nil {
		t.Fatalf("no-replay duplicate sequence batch was rejected: %v", err)
	}
	device.commitRecvReplayStateLocked(replay)
	if device.recvLast != 32 || device.recvSeen[0] != ^uint64(0) {
		t.Fatalf("no-replay commit changed replay state: last %d seen %x", device.recvLast, device.recvSeen)
	}
}

func TestKernelCryptoDeviceNoReplayRejectsZeroSequence(t *testing.T) {
	device := newKernelCryptoDeviceReplayTestDevice()
	device.flow.RecvFlags = kernelCryptoFlowFlagNoReplay

	if _, _, _, err := device.validateOpenBatchLocked(kernelCryptoDeviceReplayOpenRequestsForTest(0)); err == nil {
		t.Fatalf("no-replay zero sequence was accepted")
	}
}

func TestNewKernelCryptoDeviceFlowCopiesFlags(t *testing.T) {
	const flowID = 42
	entries := []kernelCryptoFlowEntry{
		{
			Key: kernelCryptoFlowKeyFor(kernelCryptoNamespaceTIXTCP, flowID, kernelCryptoDirectionSend),
			Value: kernelCryptoFlowValue{
				Flags:  kernelCryptoFlowFlagHotStats,
				KeyLen: kernelCryptoAES256KeyLen,
				Suite:  kernelCryptoSuiteIDTrustIXAES256GCMX25519,
				Epoch:  7,
			},
		},
		{
			Key: kernelCryptoFlowKeyFor(kernelCryptoNamespaceTIXTCP, flowID, kernelCryptoDirectionRecv),
			Value: kernelCryptoFlowValue{
				Flags:  kernelCryptoFlowFlagNoReplay,
				KeyLen: kernelCryptoAES256KeyLen,
				Suite:  kernelCryptoSuiteIDTrustIXAES256GCMX25519,
				Epoch:  7,
			},
		},
	}
	flow, ok := newKernelCryptoDeviceFlow(entries, kernelCryptoNamespaceTIXTCP, flowID)
	if !ok {
		t.Fatalf("flow was not built")
	}
	if flow.SendFlags != kernelCryptoFlowFlagHotStats {
		t.Fatalf("send flags = %d, want %d", flow.SendFlags, kernelCryptoFlowFlagHotStats)
	}
	if flow.RecvFlags != kernelCryptoFlowFlagNoReplay {
		t.Fatalf("recv flags = %d, want %d", flow.RecvFlags, kernelCryptoFlowFlagNoReplay)
	}
}

func newKernelCryptoDeviceReplayTestDevice() *kernelCryptoDevice {
	window := kernelCryptoDeviceReplayWindow(64)
	return &kernelCryptoDevice{
		flow: kernelCryptoDeviceFlow{
			SuiteID: kernelCryptoSuiteIDTrustIXAES256GCMX25519,
			Epoch:   7,
		},
		recvWindow: window,
		recvSeen:   make([]uint64, int(window/64)),
	}
}

func commitKernelCryptoDeviceReplayPerPacketForTest(t *testing.T, device *kernelCryptoDevice, sequences []uint64) {
	t.Helper()
	for _, sequence := range sequences {
		request := kernelCryptoDeviceReplayOpenRequestsForTest(sequence)[0]
		if _, err := kernelCryptoParseSecureFrame(request.Payload, byte(request.SuiteID), request.Epoch, request.Sequence); err != nil {
			t.Fatalf("parse secure frame %d: %v", sequence, err)
		}
		if err := device.checkRecvSequenceLocked(sequence); err != nil {
			t.Fatalf("check sequence %d: %v", sequence, err)
		}
		device.commitRecvSequenceLocked(sequence)
	}
}

func validateKernelCryptoDeviceReplayBatchForTest(t *testing.T, device *kernelCryptoDevice, sequences []uint64) {
	t.Helper()
	_, _, replay, err := device.validateOpenBatchLocked(kernelCryptoDeviceReplayOpenRequestsForTest(sequences...))
	if err != nil {
		t.Fatalf("validate open batch %v: %v", sequences, err)
	}
	device.commitRecvReplayStateLocked(replay)
}

func kernelCryptoDeviceReplayOpenRequestsForTest(sequences ...uint64) []kernelCryptoDeviceOpenRequest {
	requests := make([]kernelCryptoDeviceOpenRequest, len(sequences))
	for i, sequence := range sequences {
		payload := make([]byte, kernelCryptoSecureHeaderLen+kernelCryptoFrameTagLen)
		kernelCryptoPutSecureHeader(payload[:kernelCryptoSecureHeaderLen], byte(kernelCryptoSuiteIDTrustIXAES256GCMX25519), 7, sequence)
		requests[i] = kernelCryptoDeviceOpenRequest{
			SuiteID:  kernelCryptoSuiteIDTrustIXAES256GCMX25519,
			Epoch:    7,
			Sequence: sequence,
			Payload:  payload,
		}
	}
	return requests
}

func rangeUint64ForTest(first, last uint64) []uint64 {
	out := make([]uint64, 0, last-first+1)
	for value := first; value <= last; value++ {
		out = append(out, value)
	}
	return out
}
