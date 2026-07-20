//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/kernelmodule"
)

const (
	kernelCryptoDeviceBatchMax       = 4096
	kernelCryptoDevicePoolMinBatch   = 1
	kernelCryptoDevicePoolAlignment  = 64
	kernelCryptoDevicePoolPageSize   = 4096
	kernelCryptoDeviceSecureMaxPlain = kernelmodule.TrustIXAEADInputMax - kernelmodule.TrustIXAEADTagLen
)

var errKernelCryptoBorrowedUnavailable = errors.New("kernel crypto borrowed pool path is unavailable")

type kernelCryptoDeviceFlow struct {
	SendKey      [kernelCryptoMaxKeyLen]byte
	RecvKey      [kernelCryptoMaxKeyLen]byte
	SendIV       [kernelCryptoAESGCMIVLen]byte
	RecvIV       [kernelCryptoAESGCMIVLen]byte
	SendFlags    uint32
	RecvFlags    uint32
	KeyLen       uint32
	Epoch        uint64
	SuiteID      uint16
	ReplayWindow uint32
}

type kernelCryptoDevice struct {
	sealMu       sync.Mutex
	openMu       sync.Mutex
	seal         *kernelmodule.AEADDevice
	open         *kernelmodule.AEADDevice
	flow         kernelCryptoDeviceFlow
	sealOps      []kernelmodule.AEADBatchOp
	openOps      []kernelmodule.AEADBatchOp
	sealPoolOps  []kernelmodule.AEADPoolBatchOp
	openPoolOps  []kernelmodule.AEADPoolBatchOp
	sealNonces   []([kernelCryptoAESGCMIVLen]byte)
	openNonces   []([kernelCryptoAESGCMIVLen]byte)
	sealPool     []byte
	openPool     []byte
	sealBorrowed [][]byte
	openIn       [][]byte
	openOut      []kernelCryptoDeviceOpenResult
	recvScratch  []uint64
	sendLast     uint64
	recvLast     uint64
	recvSeen     []uint64
	recvWindow   uint32
	poolMinBatch int
	closed       bool
	closeErr     error
}

type kernelCryptoDeviceSealRequest struct {
	FlowID   uint64
	SuiteID  uint16
	Epoch    uint64
	Sequence uint64
	Plain    []byte
}

type kernelCryptoDeviceOpenRequest struct {
	FlowID   uint64
	SuiteID  uint16
	Epoch    uint64
	Sequence uint64
	Payload  []byte
	Plain    []byte
}

type kernelCryptoDeviceOpenResult struct {
	Plain []byte
	Suite string
	Epoch uint64
}

type kernelCryptoDeviceReplayState struct {
	last           uint64
	seen           []uint64
	pendingAdvance uint64
}

type kernelCryptoDeviceOpenBatchError struct {
	Results []kernelCryptoDeviceOpenResult
	Failed  []int
	Err     error
}

func (err *kernelCryptoDeviceOpenBatchError) Error() string {
	if err == nil {
		return ""
	}
	if err.Err != nil {
		return err.Err.Error()
	}
	return "kernel AEAD device open batch failed"
}

func (err *kernelCryptoDeviceOpenBatchError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func newKernelCryptoDeviceFlow(entries []kernelCryptoFlowEntry, namespace uint8, flowID uint64) (kernelCryptoDeviceFlow, bool) {
	var flow kernelCryptoDeviceFlow
	var haveSend, haveRecv bool
	for _, entry := range entries {
		if entry.Key.FlowID != flowID || entry.Key.Reserved[0] != namespace {
			continue
		}
		switch entry.Key.Direction {
		case kernelCryptoDirectionSend:
			flow.SendKey = entry.Value.Key
			flow.SendIV = entry.Value.IV
			flow.SendFlags = entry.Value.Flags
			flow.KeyLen = entry.Value.KeyLen
			flow.Epoch = entry.Value.Epoch
			flow.SuiteID = entry.Value.Suite
			flow.ReplayWindow = entry.Value.ReplayWindow
			haveSend = true
		case kernelCryptoDirectionRecv:
			flow.RecvKey = entry.Value.Key
			flow.RecvIV = entry.Value.IV
			flow.RecvFlags = entry.Value.Flags
			if flow.KeyLen == 0 {
				flow.KeyLen = entry.Value.KeyLen
			}
			if flow.Epoch == 0 {
				flow.Epoch = entry.Value.Epoch
			}
			if flow.SuiteID == 0 {
				flow.SuiteID = entry.Value.Suite
			}
			if flow.ReplayWindow == 0 {
				flow.ReplayWindow = entry.Value.ReplayWindow
			}
			haveRecv = true
		}
	}
	return flow, haveSend && haveRecv && flow.KeyLen > 0
}

func newKernelCryptoDevice(flow kernelCryptoDeviceFlow) (*kernelCryptoDevice, error) {
	seal, err := kernelmodule.OpenAEADDevice("")
	if err != nil {
		return nil, err
	}
	open, err := kernelmodule.OpenAEADDevice("")
	if err != nil {
		return nil, errors.Join(err, wrapEBPFOperation("close kernel AEAD seal device after open failure", seal.Close()))
	}
	device := &kernelCryptoDevice{
		seal:         seal,
		open:         open,
		flow:         flow,
		recvWindow:   kernelCryptoDeviceReplayWindow(flow.ReplayWindow),
		poolMinBatch: kernelCryptoDevicePoolMinBatchConfigured(),
	}
	if !device.recvNoReplayLocked() {
		device.recvSeen = make([]uint64, int(device.recvWindow/64))
	}
	if err := seal.SetKey(flow.SendKey[:flow.KeyLen]); err != nil {
		return nil, errors.Join(err, wrapEBPFOperation("close kernel AEAD device after seal key setup failure", device.Close()))
	}
	if err := open.SetKey(flow.RecvKey[:flow.KeyLen]); err != nil {
		return nil, errors.Join(err, wrapEBPFOperation("close kernel AEAD device after open key setup failure", device.Close()))
	}
	return device, nil
}

func (device *kernelCryptoDevice) Close() error {
	if device == nil {
		return nil
	}
	device.sealMu.Lock()
	device.openMu.Lock()
	defer device.openMu.Unlock()
	defer device.sealMu.Unlock()
	if device.closed {
		return device.closeErr
	}
	device.closed = true
	var errs []error
	if device.seal != nil {
		errs = append(errs, wrapEBPFOperation("close kernel AEAD seal device", device.seal.Close()))
		device.seal = nil
	}
	if device.open != nil {
		errs = append(errs, wrapEBPFOperation("close kernel AEAD open device", device.open.Close()))
		device.open = nil
	}
	device.flow = kernelCryptoDeviceFlow{}
	clear(device.sealPool)
	clear(device.openPool)
	clear(device.sealOps)
	clear(device.openOps)
	clear(device.sealPoolOps)
	clear(device.openPoolOps)
	clear(device.sealNonces)
	clear(device.openNonces)
	clear(device.recvSeen)
	device.closeErr = errors.Join(errs...)
	return device.closeErr
}

func (device *kernelCryptoDevice) SealBatch(requests []kernelCryptoDeviceSealRequest) ([][]byte, error) {
	if len(requests) == 0 {
		return nil, nil
	}
	if device == nil {
		return nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	device.sealMu.Lock()
	defer device.sealMu.Unlock()
	if device.seal == nil {
		return nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	maxSequence, err := device.validateSealBatchLocked(requests)
	if err != nil {
		return nil, err
	}
	out := kernelCryptoDeviceSealOutputs(requests)
	if len(requests) >= device.poolMinBatchConfigured() {
		if err := device.sealPreparedPoolBatchLocked(requests, out); err == nil {
			device.sendLast = maxSequence
			return out, nil
		}
	}
	if cap(device.sealOps) < len(requests) {
		device.sealOps = make([]kernelmodule.AEADBatchOp, len(requests))
	} else {
		device.sealOps = device.sealOps[:len(requests)]
	}
	if cap(device.sealNonces) < len(requests) {
		device.sealNonces = make([][kernelCryptoAESGCMIVLen]byte, len(requests))
	} else {
		device.sealNonces = device.sealNonces[:len(requests)]
	}
	for i, request := range requests {
		device.sealNonces[i] = kernelCryptoNonce(device.flow.SendIV, request.Sequence)
		device.sealOps[i] = kernelmodule.AEADBatchOp{
			Nonce: device.sealNonces[i][:],
			In:    request.Plain,
			Out:   out[i][kernelCryptoSecureHeaderLen:],
		}
	}
	if err := device.seal.SealBatch(device.sealOps); err != nil {
		return nil, err
	}
	for i := range requests {
		device.sealOps[i] = kernelmodule.AEADBatchOp{}
		device.sealNonces[i] = [kernelCryptoAESGCMIVLen]byte{}
	}
	device.sendLast = maxSequence
	return out, nil
}

func (device *kernelCryptoDevice) SealBatchBorrowed(requests []kernelCryptoDeviceSealRequest) ([][]byte, func(), error) {
	if len(requests) == 0 {
		return nil, func() {}, nil
	}
	if device == nil {
		return nil, nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	device.sealMu.Lock()
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		device.sealMu.Unlock()
	}
	if device.seal == nil {
		release()
		return nil, nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	if len(requests) < device.poolMinBatchConfigured() {
		release()
		return nil, nil, errKernelCryptoBorrowedUnavailable
	}
	maxSequence, err := device.validateSealBatchLocked(requests)
	if err != nil {
		release()
		return nil, nil, err
	}
	out, err := device.sealPreparedPoolBatchBorrowedLocked(requests)
	if err != nil {
		release()
		return nil, nil, err
	}
	device.sendLast = maxSequence
	return out, release, nil
}

func (device *kernelCryptoDevice) OpenBatch(requests []kernelCryptoDeviceOpenRequest) ([]kernelCryptoDeviceOpenResult, error) {
	if len(requests) == 0 {
		return nil, nil
	}
	if device == nil {
		return nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	device.openMu.Lock()
	defer device.openMu.Unlock()
	if device.open == nil {
		return nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	ciphertexts, results, replay, err := device.validateOpenBatchLocked(requests)
	if err != nil {
		return nil, err
	}
	if len(requests) >= device.poolMinBatchConfigured() {
		if err := device.openPreparedPoolBatchLocked(requests, ciphertexts, results); err == nil {
			clear(ciphertexts)
			device.commitRecvReplayStateLocked(replay)
			return results, nil
		} else if partial, ok := device.partialOpenBatchErrorLocked(err, requests, results); ok {
			clear(ciphertexts)
			return partial.Results, partial
		}
	}
	if cap(device.openOps) < len(requests) {
		device.openOps = make([]kernelmodule.AEADBatchOp, len(requests))
	} else {
		device.openOps = device.openOps[:len(requests)]
	}
	if cap(device.openNonces) < len(requests) {
		device.openNonces = make([][kernelCryptoAESGCMIVLen]byte, len(requests))
	} else {
		device.openNonces = device.openNonces[:len(requests)]
	}
	for i, request := range requests {
		device.openNonces[i] = kernelCryptoNonce(device.flow.RecvIV, request.Sequence)
		device.openOps[i] = kernelmodule.AEADBatchOp{Nonce: device.openNonces[i][:], In: ciphertexts[i], Out: results[i].Plain}
	}
	if err := device.open.OpenBatch(device.openOps); err != nil {
		clear(ciphertexts)
		return nil, err
	}
	for i := range requests {
		results[i].Plain = device.openOps[i].Out
		device.openOps[i] = kernelmodule.AEADBatchOp{}
		device.openNonces[i] = [kernelCryptoAESGCMIVLen]byte{}
	}
	device.commitRecvReplayStateLocked(replay)
	clear(ciphertexts)
	return results, nil
}

func (device *kernelCryptoDevice) OpenBatchBorrowed(requests []kernelCryptoDeviceOpenRequest) ([]kernelCryptoDeviceOpenResult, func(), error) {
	if len(requests) == 0 {
		return nil, func() {}, nil
	}
	if device == nil {
		return nil, nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	device.openMu.Lock()
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		device.openMu.Unlock()
	}
	if device.open == nil {
		release()
		return nil, nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	if len(requests) < device.poolMinBatchConfigured() {
		release()
		return nil, nil, errKernelCryptoBorrowedUnavailable
	}
	ciphertexts, results, replay, err := device.validateOpenBatchLocked(requests)
	if err != nil {
		clear(ciphertexts)
		release()
		return nil, nil, err
	}
	if err := device.openPreparedPoolBatchBorrowedLocked(requests, ciphertexts, results); err != nil {
		clear(ciphertexts)
		release()
		return nil, nil, err
	}
	clear(ciphertexts)
	device.commitRecvReplayStateLocked(replay)
	return results, release, nil
}

func (device *kernelCryptoDevice) validateSealBatchLocked(requests []kernelCryptoDeviceSealRequest) (uint64, error) {
	maxSequence := device.sendLast
	var seen map[uint64]struct{}
	for i, request := range requests {
		if request.SuiteID != device.flow.SuiteID {
			return 0, fmt.Errorf("kernel AEAD device suite %d != flow suite %d", request.SuiteID, device.flow.SuiteID)
		}
		if request.Epoch != device.flow.Epoch {
			return 0, fmt.Errorf("kernel AEAD device epoch %d != flow epoch %d", request.Epoch, device.flow.Epoch)
		}
		if len(request.Plain) > kernelCryptoDeviceSecureMaxPlain {
			return 0, fmt.Errorf("kernel AEAD device plaintext size %d exceeds max %d", len(request.Plain), kernelCryptoDeviceSecureMaxPlain)
		}
		if request.Sequence == 0 || request.Sequence <= device.sendLast {
			return 0, fmt.Errorf("kernel AEAD device frame seal returned -114")
		}
		if request.Sequence <= maxSequence {
			if seen == nil {
				seen = make(map[uint64]struct{}, len(requests))
				for _, previous := range requests[:i] {
					seen[previous.Sequence] = struct{}{}
				}
			}
		}
		if seen != nil {
			if _, ok := seen[request.Sequence]; ok {
				return 0, fmt.Errorf("kernel_udp AEAD device frame seal returned -114")
			}
			seen[request.Sequence] = struct{}{}
		}
		if request.Sequence > maxSequence {
			maxSequence = request.Sequence
		}
	}
	return maxSequence, nil
}

func (device *kernelCryptoDevice) validateOpenBatchLocked(requests []kernelCryptoDeviceOpenRequest) ([][]byte, []kernelCryptoDeviceOpenResult, kernelCryptoDeviceReplayState, error) {
	if cap(device.openIn) < len(requests) {
		device.openIn = make([][]byte, len(requests))
	} else {
		device.openIn = device.openIn[:len(requests)]
	}
	ciphertexts := device.openIn
	noReplay := device.recvNoReplayLocked()
	var replay kernelCryptoDeviceReplayState
	if !noReplay {
		replay = device.recvReplayStateForValidationLocked()
	}
	for i, request := range requests {
		if request.SuiteID != device.flow.SuiteID {
			return nil, nil, kernelCryptoDeviceReplayState{}, fmt.Errorf("kernel AEAD device suite %d != flow suite %d", request.SuiteID, device.flow.SuiteID)
		}
		if request.Epoch != device.flow.Epoch {
			return nil, nil, kernelCryptoDeviceReplayState{}, fmt.Errorf("kernel AEAD device epoch %d != flow epoch %d", request.Epoch, device.flow.Epoch)
		}
		ciphertext, err := kernelCryptoParseSecureFrame(request.Payload, byte(request.SuiteID), request.Epoch, request.Sequence)
		if err != nil {
			return nil, nil, kernelCryptoDeviceReplayState{}, err
		}
		if noReplay {
			if request.Sequence == 0 {
				return nil, nil, kernelCryptoDeviceReplayState{}, fmt.Errorf("kernel_udp AEAD device frame open returned -22")
			}
		} else {
			if err := replay.acceptOpenSequence(device.recvWindow, request.Sequence); err != nil {
				return nil, nil, kernelCryptoDeviceReplayState{}, err
			}
		}
		ciphertexts[i] = ciphertext
	}
	if cap(device.openOut) < len(requests) {
		device.openOut = make([]kernelCryptoDeviceOpenResult, len(requests))
	} else {
		device.openOut = device.openOut[:len(requests)]
	}
	results := device.openOut
	for i, request := range requests {
		plainLen := len(ciphertexts[i]) - kernelCryptoFrameTagLen
		plain := request.Plain
		if len(plain) < plainLen {
			plain = request.Payload[kernelCryptoSecureHeaderLen : kernelCryptoSecureHeaderLen+plainLen]
		} else {
			plain = plain[:plainLen]
		}
		results[i] = kernelCryptoDeviceOpenResult{
			Plain: plain,
			Suite: kernelCryptoSuiteName(request.SuiteID),
			Epoch: request.Epoch,
		}
	}
	return ciphertexts, results, replay, nil
}

func (device *kernelCryptoDevice) partialOpenBatchErrorLocked(err error, requests []kernelCryptoDeviceOpenRequest, results []kernelCryptoDeviceOpenResult) (*kernelCryptoDeviceOpenBatchError, bool) {
	opResults, ok := kernelmodule.AEADPoolBatchResults(err)
	if !ok || len(opResults) != len(requests) {
		return nil, false
	}
	failed := make([]int, 0)
	for i, result := range opResults {
		if result == 0 {
			device.commitRecvSequenceLocked(requests[i].Sequence)
			continue
		}
		failed = append(failed, i)
		results[i].Plain = nil
	}
	if len(failed) == len(requests) {
		return nil, false
	}
	return &kernelCryptoDeviceOpenBatchError{
		Results: results,
		Failed:  failed,
		Err:     err,
	}, true
}

func kernelCryptoDeviceSealOutputs(requests []kernelCryptoDeviceSealRequest) [][]byte {
	total := 0
	for _, request := range requests {
		total += kernelCryptoSecureHeaderLen + len(request.Plain) + kernelCryptoFrameTagLen
	}
	arena := make([]byte, total)
	out := make([][]byte, len(requests))
	offset := 0
	for i, request := range requests {
		wireLen := kernelCryptoSecureHeaderLen + len(request.Plain) + kernelCryptoFrameTagLen
		payload := arena[offset : offset+wireLen]
		kernelCryptoPutSecureHeader(payload[:kernelCryptoSecureHeaderLen], byte(request.SuiteID), request.Epoch, request.Sequence)
		out[i] = payload
		offset += wireLen
	}
	return out
}

func kernelCryptoDevicePoolMinBatchConfigured() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_POOL_MIN_BATCH"))
	if value == "" {
		return kernelCryptoDevicePoolMinBatch
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return kernelCryptoDevicePoolMinBatch
	}
	if parsed > kernelCryptoDeviceBatchMax {
		return kernelCryptoDeviceBatchMax
	}
	return parsed
}

func (device *kernelCryptoDevice) poolMinBatchConfigured() int {
	if device == nil || device.poolMinBatch <= 0 {
		return kernelCryptoDevicePoolMinBatch
	}
	return device.poolMinBatch
}

func (device *kernelCryptoDevice) sealPreparedPoolBatchLocked(requests []kernelCryptoDeviceSealRequest, out [][]byte) error {
	if device.seal == nil {
		return fmt.Errorf("kernel crypto AEAD device is not open")
	}
	opsOff, nonceBase, outputBase, need := kernelCryptoDeviceSealPoolLayout(requests)
	pool, err := device.ensureSealPoolLocked(need)
	if err != nil {
		return err
	}
	ops := device.sealPoolOpsForLocked(len(requests))
	outputOff := outputBase
	for i, request := range requests {
		nonceOff := nonceBase + i*kernelCryptoAESGCMIVLen
		nonce := kernelCryptoNonce(device.flow.SendIV, request.Sequence)
		wireLen := kernelCryptoSecureHeaderLen + len(request.Plain) + kernelCryptoFrameTagLen
		payloadOff := outputOff + kernelCryptoSecureHeaderLen
		cipherLen := len(request.Plain) + kernelCryptoFrameTagLen
		copy(pool[nonceOff:nonceOff+kernelCryptoAESGCMIVLen], nonce[:])
		kernelCryptoPutSecureHeader(pool[outputOff:outputOff+kernelCryptoSecureHeaderLen], byte(request.SuiteID), request.Epoch, request.Sequence)
		copy(pool[payloadOff:payloadOff+len(request.Plain)], request.Plain)
		ops[i] = kernelmodule.AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(payloadOff),
			OutOff:   uint64(payloadOff),
			NonceLen: kernelCryptoAESGCMIVLen,
			InLen:    uint32(len(request.Plain)),
			OutLen:   uint32(cipherLen),
		}
		outputOff += wireLen
	}
	if err := device.seal.PrepareRunPoolBatchOps(opsOff, ops, false); err != nil {
		if !isKernelCryptoPrepareRunUnsupported(err) {
			return err
		}
		if err := device.seal.PrepareKernelPoolBatch(opsOff, len(ops), false); err != nil {
			return err
		}
		if err := device.seal.SealKernelPreparedPoolBatch(0, len(ops)); err != nil {
			return err
		}
	}
	outputOff = outputBase
	for i, request := range requests {
		wireLen := kernelCryptoSecureHeaderLen + len(request.Plain) + kernelCryptoFrameTagLen
		copy(out[i], pool[outputOff:outputOff+wireLen])
		outputOff += wireLen
	}
	return nil
}

func (device *kernelCryptoDevice) sealPreparedPoolBatchBorrowedLocked(requests []kernelCryptoDeviceSealRequest) ([][]byte, error) {
	if device.seal == nil {
		return nil, fmt.Errorf("kernel crypto AEAD device is not open")
	}
	opsOff, nonceBase, outputBase, need := kernelCryptoDeviceSealPoolLayout(requests)
	pool, err := device.ensureSealPoolLocked(need)
	if err != nil {
		return nil, err
	}
	ops := device.sealPoolOpsForLocked(len(requests))
	if cap(device.sealBorrowed) < len(requests) {
		device.sealBorrowed = make([][]byte, len(requests))
	} else {
		device.sealBorrowed = device.sealBorrowed[:len(requests)]
		clear(device.sealBorrowed)
	}
	out := device.sealBorrowed
	outputOff := outputBase
	for i, request := range requests {
		nonceOff := nonceBase + i*kernelCryptoAESGCMIVLen
		nonce := kernelCryptoNonce(device.flow.SendIV, request.Sequence)
		wireLen := kernelCryptoSecureHeaderLen + len(request.Plain) + kernelCryptoFrameTagLen
		payloadOff := outputOff + kernelCryptoSecureHeaderLen
		cipherLen := len(request.Plain) + kernelCryptoFrameTagLen
		copy(pool[nonceOff:nonceOff+kernelCryptoAESGCMIVLen], nonce[:])
		kernelCryptoPutSecureHeader(pool[outputOff:outputOff+kernelCryptoSecureHeaderLen], byte(request.SuiteID), request.Epoch, request.Sequence)
		copy(pool[payloadOff:payloadOff+len(request.Plain)], request.Plain)
		ops[i] = kernelmodule.AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(payloadOff),
			OutOff:   uint64(payloadOff),
			NonceLen: kernelCryptoAESGCMIVLen,
			InLen:    uint32(len(request.Plain)),
			OutLen:   uint32(cipherLen),
		}
		out[i] = pool[outputOff : outputOff+wireLen]
		outputOff += wireLen
	}
	if err := device.seal.PrepareRunPoolBatchOps(opsOff, ops, false); err != nil {
		if !isKernelCryptoPrepareRunUnsupported(err) {
			return nil, err
		}
		if err := device.seal.PrepareKernelPoolBatch(opsOff, len(ops), false); err != nil {
			return nil, err
		}
		if err := device.seal.SealKernelPreparedPoolBatch(0, len(ops)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (device *kernelCryptoDevice) openPreparedPoolBatchLocked(requests []kernelCryptoDeviceOpenRequest, ciphertexts [][]byte, results []kernelCryptoDeviceOpenResult) error {
	if device.open == nil {
		return fmt.Errorf("kernel crypto AEAD device is not open")
	}
	opsOff, nonceBase, inputBase, need := kernelCryptoDeviceOpenPoolLayout(ciphertexts)
	pool, err := device.ensureOpenPoolLocked(need)
	if err != nil {
		return err
	}
	ops := device.openPoolOpsForLocked(len(requests))
	inputOff := inputBase
	for i, request := range requests {
		ciphertext := ciphertexts[i]
		nonceOff := nonceBase + i*kernelCryptoAESGCMIVLen
		nonce := kernelCryptoNonce(device.flow.RecvIV, request.Sequence)
		copy(pool[nonceOff:nonceOff+kernelCryptoAESGCMIVLen], nonce[:])
		copy(pool[inputOff:inputOff+len(ciphertext)], ciphertext)
		plainLen := len(ciphertext) - kernelCryptoFrameTagLen
		ops[i] = kernelmodule.AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(inputOff),
			// AEAD open is safe in-place and avoids a second mmap output arena.
			OutOff:   uint64(inputOff),
			NonceLen: kernelCryptoAESGCMIVLen,
			InLen:    uint32(len(ciphertext)),
			OutLen:   uint32(plainLen),
		}
		inputOff += len(ciphertext)
	}
	if err := device.open.PrepareRunPoolBatchOps(opsOff, ops, true); err != nil {
		if !isKernelCryptoPrepareRunUnsupported(err) {
			device.copyOpenPreparedPoolResultsLocked(pool, inputBase, ciphertexts, results, err)
			return err
		}
		if err := device.open.PrepareKernelPoolBatch(opsOff, len(ops), true); err != nil {
			return err
		}
		if err := device.open.OpenKernelPreparedPoolBatch(0, len(ops)); err != nil {
			device.copyOpenPreparedPoolResultsLocked(pool, inputBase, ciphertexts, results, err)
			return err
		}
	}
	device.copyOpenPreparedPoolResultsLocked(pool, inputBase, ciphertexts, results, nil)
	return nil
}

func (device *kernelCryptoDevice) openPreparedPoolBatchBorrowedLocked(requests []kernelCryptoDeviceOpenRequest, ciphertexts [][]byte, results []kernelCryptoDeviceOpenResult) error {
	if device.open == nil {
		return fmt.Errorf("kernel crypto AEAD device is not open")
	}
	opsOff, nonceBase, inputBase, need := kernelCryptoDeviceOpenPoolLayout(ciphertexts)
	pool, err := device.ensureOpenPoolLocked(need)
	if err != nil {
		return err
	}
	ops := device.openPoolOpsForLocked(len(requests))
	inputOff := inputBase
	for i, request := range requests {
		ciphertext := ciphertexts[i]
		nonceOff := nonceBase + i*kernelCryptoAESGCMIVLen
		nonce := kernelCryptoNonce(device.flow.RecvIV, request.Sequence)
		copy(pool[nonceOff:nonceOff+kernelCryptoAESGCMIVLen], nonce[:])
		copy(pool[inputOff:inputOff+len(ciphertext)], ciphertext)
		plainLen := len(ciphertext) - kernelCryptoFrameTagLen
		ops[i] = kernelmodule.AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(inputOff),
			OutOff:   uint64(inputOff),
			NonceLen: kernelCryptoAESGCMIVLen,
			InLen:    uint32(len(ciphertext)),
			OutLen:   uint32(plainLen),
		}
		inputOff += len(ciphertext)
	}
	if err := device.open.PrepareRunPoolBatchOps(opsOff, ops, true); err != nil {
		if !isKernelCryptoPrepareRunUnsupported(err) {
			device.borrowOpenPreparedPoolResultsLocked(pool, inputBase, ciphertexts, results, err)
			return err
		}
		if err := device.open.PrepareKernelPoolBatch(opsOff, len(ops), true); err != nil {
			return err
		}
		if err := device.open.OpenKernelPreparedPoolBatch(0, len(ops)); err != nil {
			device.borrowOpenPreparedPoolResultsLocked(pool, inputBase, ciphertexts, results, err)
			return err
		}
	}
	device.borrowOpenPreparedPoolResultsLocked(pool, inputBase, ciphertexts, results, nil)
	return nil
}

func isKernelCryptoPrepareRunUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.ENOSYS)
}

func (device *kernelCryptoDevice) copyOpenPreparedPoolResultsLocked(pool []byte, inputBase int, ciphertexts [][]byte, results []kernelCryptoDeviceOpenResult, err error) {
	var opResults []int32
	var havePartial bool
	if err != nil {
		opResults, havePartial = kernelmodule.AEADPoolBatchResults(err)
		if !havePartial || len(opResults) != len(results) {
			return
		}
	}
	inputOff := inputBase
	for i := range results {
		plainLen := len(results[i].Plain)
		if err == nil || opResults[i] == 0 {
			copy(results[i].Plain, pool[inputOff:inputOff+plainLen])
		}
		inputOff += len(ciphertexts[i])
	}
}

func (device *kernelCryptoDevice) borrowOpenPreparedPoolResultsLocked(pool []byte, inputBase int, ciphertexts [][]byte, results []kernelCryptoDeviceOpenResult, err error) {
	var opResults []int32
	var havePartial bool
	if err != nil {
		opResults, havePartial = kernelmodule.AEADPoolBatchResults(err)
		if !havePartial || len(opResults) != len(results) {
			return
		}
	}
	inputOff := inputBase
	for i := range results {
		plainLen := len(results[i].Plain)
		if err == nil || opResults[i] == 0 {
			results[i].Plain = pool[inputOff : inputOff+plainLen]
		}
		inputOff += len(ciphertexts[i])
	}
}

func kernelCryptoDeviceOpenPoolLayout(open [][]byte) (int, int, int, int) {
	count := len(open)
	opsOff := 0
	nonceBase := kernelCryptoDeviceAlignUp(kernelmodule.AEADPoolOpSize()*count, kernelCryptoDevicePoolAlignment)
	inputBase := kernelCryptoDeviceAlignUp(nonceBase+count*kernelCryptoAESGCMIVLen, kernelCryptoDevicePoolAlignment)
	inputEnd := inputBase
	for _, ciphertext := range open {
		inputEnd += len(ciphertext)
	}
	need := kernelCryptoDeviceAlignUp(inputEnd, kernelCryptoDevicePoolPageSize)
	return opsOff, nonceBase, inputBase, need
}

func kernelCryptoDeviceSealPoolLayout(seal []kernelCryptoDeviceSealRequest) (int, int, int, int) {
	count := len(seal)
	opsOff := 0
	nonceBase := kernelCryptoDeviceAlignUp(kernelmodule.AEADPoolOpSize()*count, kernelCryptoDevicePoolAlignment)
	outputBase := kernelCryptoDeviceAlignUp(nonceBase+count*kernelCryptoAESGCMIVLen, kernelCryptoDevicePoolAlignment)
	outputLen := 0
	for _, request := range seal {
		outputLen += kernelCryptoSecureHeaderLen + len(request.Plain) + kernelCryptoFrameTagLen
	}
	need := kernelCryptoDeviceAlignUp(outputBase+outputLen, kernelCryptoDevicePoolPageSize)
	return opsOff, nonceBase, outputBase, need
}

func (device *kernelCryptoDevice) ensureSealPoolLocked(need int) ([]byte, error) {
	if len(device.sealPool) >= need {
		return device.sealPool, nil
	}
	pool, err := device.seal.MmapPool(need)
	if err != nil {
		return nil, err
	}
	device.sealPool = pool
	return pool, nil
}

func (device *kernelCryptoDevice) ensureOpenPoolLocked(need int) ([]byte, error) {
	if len(device.openPool) >= need {
		return device.openPool, nil
	}
	pool, err := device.open.MmapPool(need)
	if err != nil {
		return nil, err
	}
	device.openPool = pool
	return pool, nil
}

func (device *kernelCryptoDevice) sealPoolOpsForLocked(count int) []kernelmodule.AEADPoolBatchOp {
	if cap(device.sealPoolOps) < count {
		device.sealPoolOps = make([]kernelmodule.AEADPoolBatchOp, count)
	} else {
		device.sealPoolOps = device.sealPoolOps[:count]
	}
	return device.sealPoolOps
}

func (device *kernelCryptoDevice) openPoolOpsForLocked(count int) []kernelmodule.AEADPoolBatchOp {
	if cap(device.openPoolOps) < count {
		device.openPoolOps = make([]kernelmodule.AEADPoolBatchOp, count)
	} else {
		device.openPoolOps = device.openPoolOps[:count]
	}
	return device.openPoolOps
}

func kernelCryptoDeviceAlignUp(value, alignment int) int {
	if alignment <= 0 {
		return value
	}
	remainder := value % alignment
	if remainder == 0 {
		return value
	}
	return value + alignment - remainder
}

func (device *kernelCryptoDevice) checkRecvSequenceLocked(sequence uint64) error {
	if device.recvNoReplayLocked() {
		if sequence == 0 {
			return fmt.Errorf("kernel_udp AEAD device frame open returned -22")
		}
		return nil
	}
	if sequence == 0 {
		return fmt.Errorf("kernel_udp AEAD device frame open returned -22")
	}
	if sequence > device.recvLast {
		return nil
	}
	delta := device.recvLast - sequence
	if delta >= uint64(device.recvWindow) {
		return fmt.Errorf("kernel AEAD device frame open returned -114")
	}
	if device.recvSequenceSeenLocked(delta) {
		return fmt.Errorf("kernel AEAD device frame open returned -114")
	}
	return nil
}

func (device *kernelCryptoDevice) recvReplayStateForValidationLocked() kernelCryptoDeviceReplayState {
	if cap(device.recvScratch) < len(device.recvSeen) {
		device.recvScratch = make([]uint64, len(device.recvSeen))
	} else {
		device.recvScratch = device.recvScratch[:len(device.recvSeen)]
	}
	copy(device.recvScratch, device.recvSeen)
	return kernelCryptoDeviceReplayState{
		last: device.recvLast,
		seen: device.recvScratch,
	}
}

func (state *kernelCryptoDeviceReplayState) acceptOpenSequence(window uint32, sequence uint64) error {
	if sequence == 0 {
		return fmt.Errorf("kernel_udp AEAD device frame open returned -22")
	}
	if sequence == state.last+1 {
		state.last = sequence
		state.pendingAdvance++
		return nil
	}
	state.flush(window)
	if sequence > state.last {
		shift := sequence - state.last
		if shift >= uint64(window) {
			clear(state.seen)
		} else {
			kernelCryptoDeviceReplayShift(state.seen, uint(shift))
		}
		state.last = sequence
		kernelCryptoDeviceReplayMark(state.seen, 0)
		return nil
	}
	delta := state.last - sequence
	if delta >= uint64(window) || kernelCryptoDeviceReplaySeen(state.seen, delta) {
		return fmt.Errorf("kernel AEAD device frame open returned -114")
	}
	kernelCryptoDeviceReplayMark(state.seen, delta)
	return nil
}

func (state *kernelCryptoDeviceReplayState) flush(window uint32) {
	if state.pendingAdvance == 0 {
		return
	}
	advance := state.pendingAdvance
	if advance >= uint64(window) {
		clear(state.seen)
	} else {
		kernelCryptoDeviceReplayShift(state.seen, uint(advance))
	}
	kernelCryptoDeviceReplayMarkRange(state.seen, advance)
	state.pendingAdvance = 0
}

func (device *kernelCryptoDevice) commitRecvReplayStateLocked(replay kernelCryptoDeviceReplayState) {
	if device.recvNoReplayLocked() {
		return
	}
	replay.flush(device.recvWindow)
	device.recvLast = replay.last
	if len(replay.seen) != len(device.recvSeen) {
		if cap(device.recvSeen) < len(replay.seen) {
			device.recvSeen = make([]uint64, len(replay.seen))
		} else {
			device.recvSeen = device.recvSeen[:len(replay.seen)]
		}
		copy(device.recvSeen, replay.seen)
		return
	}
	oldSeen := device.recvSeen
	device.recvSeen = replay.seen
	device.recvScratch = oldSeen
}

func (device *kernelCryptoDevice) commitRecvSequenceLocked(sequence uint64) {
	if device.recvNoReplayLocked() {
		return
	}
	if sequence == 0 {
		return
	}
	if sequence > device.recvLast {
		shift := sequence - device.recvLast
		if shift >= uint64(device.recvWindow) {
			clear(device.recvSeen)
		} else {
			device.shiftRecvSeenLocked(uint(shift))
		}
		device.recvLast = sequence
		device.markRecvSequenceSeenLocked(0)
		return
	}
	delta := device.recvLast - sequence
	if delta < uint64(device.recvWindow) {
		device.markRecvSequenceSeenLocked(delta)
	}
}

func kernelCryptoDeviceReplayWindow(configured uint32) uint32 {
	window := configured
	if window < 1024 {
		window = 8192
	}
	if window > 65536 {
		window = 65536
	}
	if rem := window % 64; rem != 0 {
		window += 64 - rem
	}
	return window
}

func (device *kernelCryptoDevice) recvSequenceSeenLocked(delta uint64) bool {
	return kernelCryptoDeviceReplaySeen(device.recvSeen, delta)
}

func (device *kernelCryptoDevice) markRecvSequenceSeenLocked(delta uint64) {
	kernelCryptoDeviceReplayMark(device.recvSeen, delta)
}

func (device *kernelCryptoDevice) shiftRecvSeenLocked(shift uint) {
	kernelCryptoDeviceReplayShift(device.recvSeen, shift)
}

func (device *kernelCryptoDevice) recvNoReplayLocked() bool {
	return device != nil && device.flow.RecvFlags&kernelCryptoFlowFlagNoReplay != 0
}

func kernelCryptoDeviceReplaySeen(seen []uint64, delta uint64) bool {
	word := int(delta / 64)
	bit := uint(delta % 64)
	return word >= 0 && word < len(seen) && seen[word]&(uint64(1)<<bit) != 0
}

func kernelCryptoDeviceReplayMark(seen []uint64, delta uint64) {
	word := int(delta / 64)
	bit := uint(delta % 64)
	if word < 0 || word >= len(seen) {
		return
	}
	seen[word] |= uint64(1) << bit
}

func kernelCryptoDeviceReplayMarkRange(seen []uint64, count uint64) {
	if count == 0 || len(seen) == 0 {
		return
	}
	if count >= uint64(len(seen))*64 {
		for i := range seen {
			seen[i] = ^uint64(0)
		}
		return
	}
	fullWords := int(count / 64)
	for i := 0; i < fullWords; i++ {
		seen[i] = ^uint64(0)
	}
	if rem := uint(count % 64); rem != 0 {
		seen[fullWords] |= (uint64(1) << rem) - 1
	}
}

func kernelCryptoDeviceReplayShift(seen []uint64, shift uint) {
	if shift == 0 || len(seen) == 0 {
		return
	}
	wordShift := int(shift / 64)
	bitShift := shift % 64
	if wordShift >= len(seen) {
		clear(seen)
		return
	}
	for i := len(seen) - 1; i >= 0; i-- {
		var value uint64
		source := i - wordShift
		if source >= 0 {
			value = seen[source] << bitShift
			if bitShift != 0 && source > 0 {
				value |= seen[source-1] >> (64 - bitShift)
			}
		}
		seen[i] = value
	}
}

func kernelCryptoNonce(iv [kernelCryptoAESGCMIVLen]byte, sequence uint64) [kernelCryptoAESGCMIVLen]byte {
	nonce := iv
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func kernelCryptoSuiteName(suiteID uint16) string {
	switch suiteID {
	case kernelCryptoSuiteIDTrustIXAES256GCMX25519:
		return kernelCryptoSuiteAES256GCMX25519
	case kernelCryptoSuiteIDTrustIXAES128GCMX25519:
		return kernelCryptoSuiteAES128GCMX25519
	default:
		return ""
	}
}
