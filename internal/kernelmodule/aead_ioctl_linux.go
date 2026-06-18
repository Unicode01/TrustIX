//go:build linux

package kernelmodule

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	TrustIXAEADDevicePath            = "/dev/trustix_crypto"
	TrustIXDatapathDevicePath        = "/dev/trustix_datapath"
	TrustIXDatapathHelpersDevicePath = "/dev/trustix_datapath_helpers"

	trustIXAEADIOCMagic              = uintptr('T')
	trustIXAEADIOCVersion            = uint32(1)
	TrustIXDatapathHelpersIOCVersion = uint32(1)
	trustIXAEADIOCFlagDecrypt        = uint32(1)
	TrustIXAEADTagLen                = 16
	TrustIXAEADNonceLen              = 12
	TrustIXAEADInputMax              = 512 * 1024
	trustIXAEADIOCTagLen             = TrustIXAEADTagLen
	trustIXAEADIOCNonceLen           = TrustIXAEADNonceLen
	trustIXAEADIOCInputMax           = TrustIXAEADInputMax
	trustIXAEADIOCBatchMaxOps        = 4096
	TrustIXAEADDirectMaxSlots        = 16384
	TrustIXAEADDirectAnySlot         = ^uint32(0)
	trustIXAEADDirectFlagOpen        = uint32(1)

	TrustIXDatapathHelpersFlagTIXTSelftestOK = uint32(1 << 0)
	TrustIXDatapathHelpersFlagFeaturesActive = uint32(1 << 1)
	TrustIXDatapathHelpersSelftestTIXTFrame  = uint64(1 << 0)
	TrustIXDatapathHelpersSelftestTIXTStream = uint64(1 << 1)
	TrustIXDatapathSelftestStateTable        = uint64(1 << 2)
	TrustIXDatapathSelftestClassify          = uint64(1 << 3)
	TrustIXDatapathSelftestPacketClassify    = uint64(1 << 4)
	TrustIXDatapathSelftestTIXTEncap         = uint64(1 << 5)
	TrustIXDatapathSelftestTIXTDecap         = uint64(1 << 6)
	TrustIXDatapathSelftestSessionWire       = uint64(1 << 7)
	TrustIXDatapathSelftestOuterBuild        = uint64(1 << 8)
	TrustIXDatapathSelftestOuterParse        = uint64(1 << 9)
	TrustIXDatapathHelpersSelftestAll        = TrustIXDatapathHelpersSelftestTIXTFrame | TrustIXDatapathHelpersSelftestTIXTStream
	TrustIXDatapathSelftestAll               = TrustIXDatapathHelpersSelftestAll | TrustIXDatapathSelftestStateTable | TrustIXDatapathSelftestClassify | TrustIXDatapathSelftestPacketClassify | TrustIXDatapathSelftestTIXTEncap | TrustIXDatapathSelftestTIXTDecap | TrustIXDatapathSelftestSessionWire | TrustIXDatapathSelftestOuterBuild | TrustIXDatapathSelftestOuterParse

	TrustIXDatapathStateKindRoute       = uint32(1)
	TrustIXDatapathStateKindSession     = uint32(2)
	TrustIXDatapathStateKindFlow        = uint32(3)
	TrustIXDatapathStateKindSessionWire = uint32(4)
	TrustIXDatapathStateOpUpsert        = uint32(1)
	TrustIXDatapathStateOpGet           = uint32(2)
	TrustIXDatapathStateOpDelete        = uint32(3)
	TrustIXDatapathStateOpClear         = uint32(4)
	TrustIXDatapathStateBatchMax        = 4096
	TrustIXDatapathPacketMaxLen         = 65535
	TrustIXDatapathHookOpAttach         = uint32(1)
	TrustIXDatapathHookOpDetach         = uint32(2)
	TrustIXDatapathHookOpQuery          = uint32(3)
	TrustIXDatapathHookFlagRXPreview    = uint32(1 << 0)
	TrustIXDatapathHookFlagRXStage      = uint32(1 << 1)
	TrustIXDatapathHookFlagRXWorker     = uint32(1 << 2)
	TrustIXDatapathHookFlagTXPlaintext  = uint32(1 << 3)
	TrustIXDatapathRXStageOpQuery       = uint32(1)
	TrustIXDatapathRXStageOpPeek        = uint32(2)
	TrustIXDatapathRXStageOpPop         = uint32(3)
	TrustIXDatapathRXStageOpClear       = uint32(4)
	TrustIXDatapathRouteFlagUnicast     = uint32(1)
	TrustIXDatapathRouteFlagLocal       = uint32(2)
	TrustIXDatapathRouteFlagDrop        = uint32(3)
	TrustIXDatapathRouteFlagReject      = uint32(4)
)

type AEADBatchOp struct {
	Nonce []byte
	In    []byte
	Out   []byte
}

type AEADPoolBatchOp struct {
	NonceOff uint64
	InOff    uint64
	OutOff   uint64
	NonceLen uint32
	InLen    uint32
	OutLen   uint32
	Result   int32
}

type AEADDevice struct {
	mu   sync.Mutex
	file *os.File
	pool []byte
}

type DatapathDevice struct {
	mu   sync.Mutex
	file *os.File
}

type DatapathQuery struct {
	ModuleABIVersion   uint32
	DatapathABIVersion uint32
	Features           []string
	SafeFeatures       []string
	UnsafeFeatures     []string
	MaxDirectSlots     uint32
	MaxBatchOps        uint32
	MaxInputLen        uint32
	Flags              uint32
	Selftests          uint64
	SelftestFailures   uint64
}

func (query DatapathQuery) TIXTSelftestOK() bool {
	return query.Flags&TrustIXDatapathHelpersFlagTIXTSelftestOK != 0 &&
		query.Selftests&TrustIXDatapathHelpersSelftestAll == TrustIXDatapathHelpersSelftestAll &&
		query.SelftestFailures&TrustIXDatapathHelpersSelftestAll == 0
}

func (query DatapathQuery) FeaturesActive() bool {
	return query.Flags&TrustIXDatapathHelpersFlagFeaturesActive != 0
}

func (query DatapathQuery) SafeActiveFeature(feature string) bool {
	return query.DatapathABIVersion > 0 &&
		query.TIXTSelftestOK() &&
		query.FeaturesActive() &&
		featureListContains(query.Features, feature) &&
		featureListContains(query.SafeFeatures, feature)
}

type DatapathSelftest struct {
	Requested uint64
	Passed    uint64
	Failed    uint64
	Features  []string
	Flags     uint32
}

type DatapathStateRecord struct {
	Kind  uint32
	Op    uint32
	Flags uint32
	Key   [4]uint64
	Value [8]uint64
}

type DatapathStateStats struct {
	MaxRoutes       uint32
	Routes          uint32
	MaxSessions     uint32
	Sessions        uint32
	MaxFlows        uint32
	Flows           uint32
	MaxSessionWires uint32
	SessionWires    uint32
	Upserts         uint64
	Deletes         uint64
	Clears          uint64
	GetHits         uint64
	GetMisses       uint64
	TableFull       uint64
}

type DatapathClassifyRequest struct {
	SourceIPv4      uint32
	DestinationIPv4 uint32
	SourcePort      uint16
	DestinationPort uint16
	Protocol        uint8
}

type DatapathClassifyResult struct {
	RouteFlags   uint32
	PrefixLen    uint32
	FlowID       uint64
	SessionFlags uint64
}

type DatapathPacketClassifyResult struct {
	SourceIPv4      uint32
	DestinationIPv4 uint32
	SourcePort      uint16
	DestinationPort uint16
	Protocol        uint8
	IPHeaderLen     uint8
	L4HeaderLen     uint8
	RouteFlags      uint32
	PrefixLen       uint32
	FlowID          uint64
	SessionFlags    uint64
	PacketsSeen     uint64
	BytesSeen       uint64
}

type DatapathPacketStats struct {
	Packets         uint64
	Bytes           uint64
	ParseErrors     uint64
	RouteMisses     uint64
	SessionMisses   uint64
	UnicastRoutes   uint64
	LocalRoutes     uint64
	BlackholeRoutes uint64
	RejectRoutes    uint64
}

type DatapathHookRequest struct {
	Op            uint32
	Flags         uint32
	IfName        string
	TargetIfName  string
	IfIndex       int32
	TargetIfIndex int32
}

type DatapathHookStatus struct {
	Attached           bool
	Flags              uint32
	IfName             string
	TargetIfName       string
	IfIndex            int32
	TargetIfIndex      int32
	Seen               uint64
	Classified         uint64
	ParseErrors        uint64
	RouteMisses        uint64
	SessionMisses      uint64
	Pass               uint64
	Drop               uint64
	OuterSeen          uint64
	OuterParsed        uint64
	OuterParseErrors   uint64
	OuterSessionMisses uint64
	RXPreview          uint64
	RXPreviewErrors    uint64
	RXStage            uint64
	RXStageErrors      uint64
	RXWorker           uint64
	RXWorkerErrors     uint64
	RXWorkerInjected   uint64
	RXWorkerDropped    uint64
}

type DatapathTIXTEncapResult struct {
	Wire         []byte
	WrittenLen   uint32
	FlowID       uint64
	Epoch        uint64
	RouteFlags   uint32
	PrefixLen    uint32
	SessionFlags uint64
}

type DatapathTIXTDecapResult struct {
	Inner        []byte
	WrittenLen   uint32
	FlowID       uint64
	Epoch        uint64
	Sequence     uint64
	PayloadLen   uint32
	TIXTFlags    uint32
	SessionFlags uint64
}

type DatapathOuterBuildResult struct {
	Outer         []byte
	WrittenLen    uint32
	FlowID        uint64
	Epoch         uint64
	RouteFlags    uint32
	PrefixLen     uint32
	SessionFlags  uint64
	LocalIPv4     uint32
	RemoteIPv4    uint32
	LocalPort     uint16
	RemotePort    uint16
	OuterProtocol uint8
	TIXTLen       uint32
}

type DatapathOuterParseResult struct {
	Inner         []byte
	WrittenLen    uint32
	Flags         uint32
	FlowID        uint64
	Epoch         uint64
	Sequence      uint64
	PayloadLen    uint32
	TIXTFlags     uint32
	SessionFlags  uint64
	LocalIPv4     uint32
	RemoteIPv4    uint32
	LocalPort     uint16
	RemotePort    uint16
	OuterProtocol uint8
	TIXTLen       uint32
}

type DatapathRXStageResult struct {
	Inner            []byte
	WrittenLen       uint32
	ID               uint64
	FlowID           uint64
	Epoch            uint64
	Sequence         uint64
	PayloadLen       uint32
	TIXTFlags        uint32
	SessionFlags     uint64
	OuterSourceIPv4  uint32
	OuterDestIPv4    uint32
	OuterSourcePort  uint16
	OuterDestPort    uint16
	OuterProtocol    uint8
	InnerProtocol    uint8
	InnerSourceIPv4  uint32
	InnerDestIPv4    uint32
	InnerSourcePort  uint16
	InnerDestPort    uint16
	InnerIPHeaderLen uint8
	InnerL4HeaderLen uint8
	QueueLen         uint32
	Capacity         uint32
	SlotLen          uint32
	Staged           uint64
	Popped           uint64
	Dropped          uint64
	Overwritten      uint64
}

type AEADPoolBatchError struct {
	OpResults []int32
	Err       error
}

func (err *AEADPoolBatchError) Error() string {
	if err == nil {
		return ""
	}
	if err.Err != nil {
		return err.Err.Error()
	}
	return "trustix AEAD pool batch failed"
}

func (err *AEADPoolBatchError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func AEADPoolBatchResults(err error) ([]int32, bool) {
	var batchErr *AEADPoolBatchError
	if errors.As(err, &batchErr) && batchErr != nil && len(batchErr.OpResults) > 0 {
		return batchErr.OpResults, true
	}
	return nil, false
}

func newAEADPoolBatchError(message string, result int32, rawOps []trustIXAEADIOCPoolOp) error {
	results := make([]int32, len(rawOps))
	for i := range rawOps {
		results[i] = rawOps[i].Result
	}
	return &AEADPoolBatchError{
		OpResults: results,
		Err:       fmt.Errorf("%s %d", message, result),
	}
}

type trustIXAEADIOCCrypt struct {
	Version  uint32
	Flags    uint32
	KeyLen   uint32
	NonceLen uint32
	InLen    uint32
	OutLen   uint32
	Result   int32
	Reserved uint32
	KeyPtr   uint64
	NoncePtr uint64
	InPtr    uint64
	OutPtr   uint64
}

type trustIXAEADIOCOp struct {
	NoncePtr uint64
	InPtr    uint64
	OutPtr   uint64
	NonceLen uint32
	InLen    uint32
	OutLen   uint32
	Result   int32
}

type trustIXAEADIOCBatch struct {
	Version  uint32
	Flags    uint32
	KeyLen   uint32
	OpCount  uint32
	Result   int32
	Reserved uint32
	KeyPtr   uint64
	OpsPtr   uint64
}

type trustIXAEADIOCKey struct {
	Version uint32
	Flags   uint32
	KeyLen  uint32
	Result  int32
	KeyPtr  uint64
}

type trustIXAEADIOCPool struct {
	Version  uint32
	Flags    uint32
	Size     uint64
	Result   int32
	Reserved uint32
}

type trustIXAEADIOCPoolOp struct {
	NonceOff uint64
	InOff    uint64
	OutOff   uint64
	NonceLen uint32
	InLen    uint32
	OutLen   uint32
	Result   int32
}

type trustIXAEADIOCPoolBatch struct {
	Version uint32
	Flags   uint32
	OpCount uint32
	Result  int32
	OpsOff  uint64
}

type trustIXAEADIOCPoolPreparedBatch struct {
	Version  uint32
	Flags    uint32
	OpCount  uint32
	Result   int32
	Start    uint32
	Reserved uint32
}

type trustIXAEADIOCDirectKey struct {
	Version  uint32
	Flags    uint32
	Slot     uint32
	KeyLen   uint32
	Result   int32
	Reserved uint32
	KeyPtr   uint64
}

type TrustIXDatapathHelpersIOCQuery struct {
	Version            uint32
	Result             int32
	ModuleABIVersion   uint32
	DatapathABIVersion uint32
	Features           uint64
	SafeFeatures       uint64
	UnsafeFeatures     uint64
	MaxDirectSlots     uint32
	MaxBatchOps        uint32
	MaxInputLen        uint32
	Flags              uint32
	Reserved0          uint64
	Reserved1          uint64
}

type TrustIXDatapathHelpersIOCSelftest struct {
	Version   uint32
	Result    int32
	Requested uint64
	Passed    uint64
	Failed    uint64
	Features  uint64
	Flags     uint32
	Reserved  uint32
}

type TrustIXDatapathIOCState struct {
	Version   uint32
	Result    int32
	Kind      uint32
	Op        uint32
	Flags     uint32
	Reserved0 uint32
	Key       [4]uint64
	Value     [8]uint64
}

type TrustIXDatapathIOCStateStats struct {
	Version         uint32
	Result          int32
	MaxRoutes       uint32
	Routes          uint32
	MaxSessions     uint32
	Sessions        uint32
	MaxFlows        uint32
	Flows           uint32
	MaxSessionWires uint32
	SessionWires    uint32
	Upserts         uint64
	Deletes         uint64
	Clears          uint64
	GetHits         uint64
	GetMisses       uint64
	TableFull       uint64
	Reserved        [3]uint64
}

type TrustIXDatapathIOCStateBatch struct {
	Version    uint32
	Result     int32
	Count      uint32
	Applied    uint32
	RecordsPtr uint64
	Reserved   [4]uint64
}

type TrustIXDatapathIOCClassify struct {
	Version         uint32
	Result          int32
	SourceIPv4      uint32
	DestinationIPv4 uint32
	SourcePort      uint16
	DestinationPort uint16
	Protocol        uint8
	Reserved0       uint8
	Reserved1       uint16
	RouteFlags      uint32
	PrefixLen       uint32
	FlowID          uint64
	SessionFlags    uint64
	Reserved        [4]uint64
}

type TrustIXDatapathIOCPacketClassify struct {
	Version         uint32
	Result          int32
	Flags           uint32
	PacketLen       uint32
	PacketPtr       uint64
	SourceIPv4      uint32
	DestinationIPv4 uint32
	SourcePort      uint16
	DestinationPort uint16
	Protocol        uint8
	IPHeaderLen     uint8
	L4HeaderLen     uint8
	Reserved0       uint8
	RouteFlags      uint32
	PrefixLen       uint32
	FlowID          uint64
	SessionFlags    uint64
	PacketsSeen     uint64
	BytesSeen       uint64
	Reserved        [4]uint64
}

type TrustIXDatapathIOCPacketStats struct {
	Version         uint32
	Result          int32
	Packets         uint64
	Bytes           uint64
	ParseErrors     uint64
	RouteMisses     uint64
	SessionMisses   uint64
	UnicastRoutes   uint64
	LocalRoutes     uint64
	BlackholeRoutes uint64
	RejectRoutes    uint64
	Reserved        [8]uint64
}

type TrustIXDatapathIOCHook struct {
	Version            uint32
	Result             int32
	Op                 uint32
	Flags              uint32
	IfName             [16]byte
	TargetIfName       [16]byte
	IfIndex            int32
	TargetIfIndex      int32
	Attached           uint32
	Reserved0          uint32
	Seen               uint64
	Classified         uint64
	ParseErrors        uint64
	RouteMisses        uint64
	SessionMisses      uint64
	Pass               uint64
	Drop               uint64
	OuterSeen          uint64
	OuterParsed        uint64
	OuterParseErrors   uint64
	OuterSessionMisses uint64
	RXPreview          uint64
	RXPreviewErrors    uint64
	RXStage            uint64
	RXStageErrors      uint64
	RXWorker           uint64
	RXWorkerErrors     uint64
	RXWorkerInjected   uint64
	RXWorkerDropped    uint64
}

type TrustIXDatapathIOCTIXTEncap struct {
	Version      uint32
	Result       int32
	Flags        uint32
	InnerLen     uint32
	InnerPtr     uint64
	OutLen       uint32
	WrittenLen   uint32
	OutPtr       uint64
	Sequence     uint64
	FlowID       uint64
	Epoch        uint64
	RouteFlags   uint32
	PrefixLen    uint32
	SessionFlags uint64
	Reserved     [6]uint64
}

type TrustIXDatapathIOCTIXTDecap struct {
	Version      uint32
	Result       int32
	Flags        uint32
	WireLen      uint32
	WirePtr      uint64
	OutLen       uint32
	WrittenLen   uint32
	OutPtr       uint64
	FlowID       uint64
	Epoch        uint64
	Sequence     uint64
	PayloadLen   uint32
	TIXTFlags    uint32
	SessionFlags uint64
	Reserved     [6]uint64
}

type TrustIXDatapathIOCOuterBuild struct {
	Version       uint32
	Result        int32
	Flags         uint32
	InnerLen      uint32
	InnerPtr      uint64
	OutLen        uint32
	WrittenLen    uint32
	OutPtr        uint64
	Sequence      uint64
	FlowID        uint64
	Epoch         uint64
	RouteFlags    uint32
	PrefixLen     uint32
	SessionFlags  uint64
	LocalIPv4     uint32
	RemoteIPv4    uint32
	LocalPort     uint16
	RemotePort    uint16
	OuterProtocol uint8
	Reserved0     uint8
	Reserved1     uint16
	TIXTLen       uint32
	Reserved2     uint32
	Reserved      [4]uint64
}

type TrustIXDatapathIOCOuterParse struct {
	Version       uint32
	Result        int32
	Flags         uint32
	OuterLen      uint32
	OuterPtr      uint64
	OutLen        uint32
	WrittenLen    uint32
	OutPtr        uint64
	FlowID        uint64
	Epoch         uint64
	Sequence      uint64
	PayloadLen    uint32
	TIXTFlags     uint32
	SessionFlags  uint64
	LocalIPv4     uint32
	RemoteIPv4    uint32
	LocalPort     uint16
	RemotePort    uint16
	OuterProtocol uint8
	Reserved0     uint8
	Reserved1     uint16
	TIXTLen       uint32
	Reserved2     uint32
	Reserved      [4]uint64
}

type TrustIXDatapathIOCRXStage struct {
	Version          uint32
	Result           int32
	Op               uint32
	Flags            uint32
	OutLen           uint32
	WrittenLen       uint32
	OutPtr           uint64
	ID               uint64
	FlowID           uint64
	Epoch            uint64
	Sequence         uint64
	PayloadLen       uint32
	TIXTFlags        uint32
	SessionFlags     uint64
	OuterSourceIPv4  uint32
	OuterDestIPv4    uint32
	OuterSourcePort  uint16
	OuterDestPort    uint16
	OuterProtocol    uint8
	InnerProtocol    uint8
	Reserved0        uint16
	InnerSourceIPv4  uint32
	InnerDestIPv4    uint32
	InnerSourcePort  uint16
	InnerDestPort    uint16
	InnerIPHeaderLen uint8
	InnerL4HeaderLen uint8
	Reserved1        uint16
	QueueLen         uint32
	Capacity         uint32
	SlotLen          uint32
	Reserved2        uint32
	Staged           uint64
	Popped           uint64
	Dropped          uint64
	Overwritten      uint64
	Reserved         [4]uint64
}

func AEADDeviceAvailable(path string) bool {
	if path == "" {
		path = TrustIXAEADDevicePath
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func ProbeDatapath(path string) (DatapathQuery, error) {
	if path == "" {
		path = TrustIXDatapathHelpersDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathQuery{}, err
	}
	defer file.Close()
	req := TrustIXDatapathHelpersIOCQuery{Version: TrustIXDatapathHelpersIOCVersion}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathHelpersIOCQueryCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return DatapathQuery{}, err
	}
	if req.Result != 0 {
		return DatapathQuery{}, fmt.Errorf("trustix datapath query returned %d", req.Result)
	}
	query := DatapathQuery{
		ModuleABIVersion:   req.ModuleABIVersion,
		DatapathABIVersion: req.DatapathABIVersion,
		Features:           moduleFeatureMaskToNames(req.Features),
		SafeFeatures:       moduleFeatureMaskToNames(req.SafeFeatures),
		UnsafeFeatures:     moduleFeatureMaskToNames(req.UnsafeFeatures),
		MaxDirectSlots:     req.MaxDirectSlots,
		MaxBatchOps:        req.MaxBatchOps,
		MaxInputLen:        req.MaxInputLen,
		Flags:              req.Flags,
		Selftests:          req.Reserved0,
		SelftestFailures:   req.Reserved1,
	}
	if datapathQueryModuleName(path) != "" {
		query.Features, _ = filterModuleFeaturesByRuntimeBTF(datapathQueryModuleName(path), query.Features)
		query.SafeFeatures, _ = filterModuleFeaturesByRuntimeBTF(datapathQueryModuleName(path), query.SafeFeatures)
		query.UnsafeFeatures, _ = filterModuleFeaturesByRuntimeBTF(datapathQueryModuleName(path), query.UnsafeFeatures)
	}
	return query, nil
}

func datapathQueryModuleName(path string) string {
	switch path {
	case "", TrustIXDatapathHelpersDevicePath:
		return "trustix_datapath_helpers"
	case TrustIXDatapathDevicePath:
		return "trustix_datapath"
	default:
		return ""
	}
}

func RunDatapathSelftest(path string, requested uint64) (DatapathSelftest, error) {
	if path == "" {
		path = TrustIXDatapathHelpersDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathSelftest{}, err
	}
	defer file.Close()
	req := TrustIXDatapathHelpersIOCSelftest{
		Version:   TrustIXDatapathHelpersIOCVersion,
		Requested: requested,
	}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathHelpersIOCSelftestCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return DatapathSelftest{}, err
	}
	if req.Result != 0 {
		if req.Result < 0 {
			return DatapathSelftest{}, fmt.Errorf("trustix datapath selftest returned %d: %w", req.Result, syscall.Errno(-req.Result))
		}
		return DatapathSelftest{}, fmt.Errorf("trustix datapath selftest returned %d", req.Result)
	}
	return DatapathSelftest{
		Requested: req.Requested,
		Passed:    req.Passed,
		Failed:    req.Failed,
		Features:  moduleFeatureMaskToNames(req.Features),
		Flags:     req.Flags,
	}, nil
}

func DatapathApplyState(path string, record DatapathStateRecord) (DatapathStateRecord, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathStateRecord{}, err
	}
	defer file.Close()
	req := TrustIXDatapathIOCState{
		Version: TrustIXDatapathHelpersIOCVersion,
		Kind:    record.Kind,
		Op:      record.Op,
		Flags:   record.Flags,
		Key:     record.Key,
		Value:   record.Value,
	}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCStateCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return DatapathStateRecord{}, err
	}
	out := DatapathStateRecord{
		Kind:  req.Kind,
		Op:    req.Op,
		Flags: req.Flags,
		Key:   req.Key,
		Value: req.Value,
	}
	if req.Result != 0 {
		return out, syscall.Errno(-req.Result)
	}
	return out, nil
}

func DatapathApplyStateBatch(path string, records []DatapathStateRecord) (uint32, []DatapathStateRecord, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	if len(records) == 0 {
		return 0, nil, nil
	}
	if len(records) > TrustIXDatapathStateBatchMax {
		return 0, nil, fmt.Errorf("trustix datapath state batch record count %d exceeds max %d", len(records), TrustIXDatapathStateBatchMax)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, nil, err
	}
	defer file.Close()
	return datapathApplyStateBatchFD(uintptr(file.Fd()), records)
}

func datapathApplyStateBatchFD(fd uintptr, records []DatapathStateRecord) (uint32, []DatapathStateRecord, error) {
	if len(records) == 0 {
		return 0, nil, nil
	}
	if len(records) > TrustIXDatapathStateBatchMax {
		return 0, nil, fmt.Errorf("trustix datapath state batch record count %d exceeds max %d", len(records), TrustIXDatapathStateBatchMax)
	}
	rawRecords := make([]TrustIXDatapathIOCState, len(records))
	for i, record := range records {
		rawRecords[i] = TrustIXDatapathIOCState{
			Version: TrustIXDatapathHelpersIOCVersion,
			Kind:    record.Kind,
			Op:      record.Op,
			Flags:   record.Flags,
			Key:     record.Key,
			Value:   record.Value,
		}
	}
	req := TrustIXDatapathIOCStateBatch{
		Version:    TrustIXDatapathHelpersIOCVersion,
		Count:      uint32(len(rawRecords)),
		RecordsPtr: sliceDataPtr(rawRecords),
	}
	if err := ioctl(fd, TrustIXDatapathIOCStateBatchCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(rawRecords)
		return 0, nil, err
	}
	runtime.KeepAlive(rawRecords)
	out := make([]DatapathStateRecord, len(rawRecords))
	for i := range rawRecords {
		out[i] = DatapathStateRecord{
			Kind:  rawRecords[i].Kind,
			Op:    rawRecords[i].Op,
			Flags: rawRecords[i].Flags,
			Key:   rawRecords[i].Key,
			Value: rawRecords[i].Value,
		}
	}
	if req.Result != 0 {
		return req.Applied, out, syscall.Errno(-req.Result)
	}
	return req.Applied, out, nil
}

func DatapathStateStatsQuery(path string) (DatapathStateStats, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathStateStats{}, err
	}
	defer file.Close()
	req := TrustIXDatapathIOCStateStats{Version: TrustIXDatapathHelpersIOCVersion}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCStateStatsCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return DatapathStateStats{}, err
	}
	if req.Result != 0 {
		return DatapathStateStats{}, syscall.Errno(-req.Result)
	}
	return DatapathStateStats{
		MaxRoutes:       req.MaxRoutes,
		Routes:          req.Routes,
		MaxSessions:     req.MaxSessions,
		Sessions:        req.Sessions,
		MaxFlows:        req.MaxFlows,
		Flows:           req.Flows,
		MaxSessionWires: req.MaxSessionWires,
		SessionWires:    req.SessionWires,
		Upserts:         req.Upserts,
		Deletes:         req.Deletes,
		Clears:          req.Clears,
		GetHits:         req.GetHits,
		GetMisses:       req.GetMisses,
		TableFull:       req.TableFull,
	}, nil
}

func DatapathClassify(path string, request DatapathClassifyRequest) (DatapathClassifyResult, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathClassifyResult{}, err
	}
	defer file.Close()
	req := TrustIXDatapathIOCClassify{
		Version:         TrustIXDatapathHelpersIOCVersion,
		SourceIPv4:      request.SourceIPv4,
		DestinationIPv4: request.DestinationIPv4,
		SourcePort:      request.SourcePort,
		DestinationPort: request.DestinationPort,
		Protocol:        request.Protocol,
	}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCClassifyCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return DatapathClassifyResult{}, err
	}
	out := DatapathClassifyResult{
		RouteFlags:   req.RouteFlags,
		PrefixLen:    req.PrefixLen,
		FlowID:       req.FlowID,
		SessionFlags: req.SessionFlags,
	}
	if req.Result != 0 {
		return out, syscall.Errno(-req.Result)
	}
	return out, nil
}

func DatapathPacketClassify(path string, packet []byte) (DatapathPacketClassifyResult, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	if len(packet) == 0 {
		return DatapathPacketClassifyResult{}, fmt.Errorf("trustix datapath packet classify input is empty")
	}
	if len(packet) > TrustIXDatapathPacketMaxLen {
		return DatapathPacketClassifyResult{}, fmt.Errorf("trustix datapath packet length %d exceeds max %d", len(packet), TrustIXDatapathPacketMaxLen)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathPacketClassifyResult{}, err
	}
	defer file.Close()
	req := TrustIXDatapathIOCPacketClassify{
		Version:   TrustIXDatapathHelpersIOCVersion,
		PacketLen: uint32(len(packet)),
		PacketPtr: sliceDataPtr(packet),
	}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCPacketClassifyCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(packet)
		return DatapathPacketClassifyResult{}, err
	}
	runtime.KeepAlive(packet)
	out := DatapathPacketClassifyResult{
		SourceIPv4:      req.SourceIPv4,
		DestinationIPv4: req.DestinationIPv4,
		SourcePort:      req.SourcePort,
		DestinationPort: req.DestinationPort,
		Protocol:        req.Protocol,
		IPHeaderLen:     req.IPHeaderLen,
		L4HeaderLen:     req.L4HeaderLen,
		RouteFlags:      req.RouteFlags,
		PrefixLen:       req.PrefixLen,
		FlowID:          req.FlowID,
		SessionFlags:    req.SessionFlags,
		PacketsSeen:     req.PacketsSeen,
		BytesSeen:       req.BytesSeen,
	}
	if req.Result != 0 {
		return out, syscall.Errno(-req.Result)
	}
	return out, nil
}

func DatapathPacketStatsQuery(path string) (DatapathPacketStats, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathPacketStats{}, err
	}
	defer file.Close()
	req := TrustIXDatapathIOCPacketStats{Version: TrustIXDatapathHelpersIOCVersion}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCPacketStatsCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return DatapathPacketStats{}, err
	}
	if req.Result != 0 {
		return DatapathPacketStats{}, syscall.Errno(-req.Result)
	}
	return DatapathPacketStats{
		Packets:         req.Packets,
		Bytes:           req.Bytes,
		ParseErrors:     req.ParseErrors,
		RouteMisses:     req.RouteMisses,
		SessionMisses:   req.SessionMisses,
		UnicastRoutes:   req.UnicastRoutes,
		LocalRoutes:     req.LocalRoutes,
		BlackholeRoutes: req.BlackholeRoutes,
		RejectRoutes:    req.RejectRoutes,
	}, nil
}

func DatapathHook(path string, request DatapathHookRequest) (DatapathHookStatus, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathHookStatus{}, err
	}
	defer file.Close()
	return datapathHookFD(uintptr(file.Fd()), request)
}

func datapathHookFD(fd uintptr, request DatapathHookRequest) (DatapathHookStatus, error) {
	req := TrustIXDatapathIOCHook{
		Version:       TrustIXDatapathHelpersIOCVersion,
		Op:            request.Op,
		Flags:         request.Flags,
		IfIndex:       request.IfIndex,
		TargetIfIndex: request.TargetIfIndex,
	}
	copy(req.IfName[:], []byte(request.IfName))
	copy(req.TargetIfName[:], []byte(request.TargetIfName))
	if err := ioctl(fd, TrustIXDatapathIOCHookCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return DatapathHookStatus{}, err
	}
	out := DatapathHookStatus{
		Attached:           req.Attached != 0,
		Flags:              req.Flags,
		IfName:             nullTerminatedString(req.IfName[:]),
		TargetIfName:       nullTerminatedString(req.TargetIfName[:]),
		IfIndex:            req.IfIndex,
		TargetIfIndex:      req.TargetIfIndex,
		Seen:               req.Seen,
		Classified:         req.Classified,
		ParseErrors:        req.ParseErrors,
		RouteMisses:        req.RouteMisses,
		SessionMisses:      req.SessionMisses,
		Pass:               req.Pass,
		Drop:               req.Drop,
		OuterSeen:          req.OuterSeen,
		OuterParsed:        req.OuterParsed,
		OuterParseErrors:   req.OuterParseErrors,
		OuterSessionMisses: req.OuterSessionMisses,
		RXPreview:          req.RXPreview,
		RXPreviewErrors:    req.RXPreviewErrors,
		RXStage:            req.RXStage,
		RXStageErrors:      req.RXStageErrors,
		RXWorker:           req.RXWorker,
		RXWorkerErrors:     req.RXWorkerErrors,
		RXWorkerInjected:   req.RXWorkerInjected,
		RXWorkerDropped:    req.RXWorkerDropped,
	}
	if req.Result != 0 {
		return out, syscall.Errno(-req.Result)
	}
	return out, nil
}

func DatapathHookQuery(path string) (DatapathHookStatus, error) {
	return DatapathHook(path, DatapathHookRequest{Op: TrustIXDatapathHookOpQuery})
}

func DatapathHookDetach(path string) (DatapathHookStatus, error) {
	return DatapathHook(path, DatapathHookRequest{Op: TrustIXDatapathHookOpDetach})
}

func OpenDatapathDevice(path string) (*DatapathDevice, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &DatapathDevice{file: file}, nil
}

func (device *DatapathDevice) Close() error {
	if device == nil || device.file == nil {
		return nil
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return nil
	}
	err := device.file.Close()
	device.file = nil
	return err
}

func (device *DatapathDevice) Hook(request DatapathHookRequest) (DatapathHookStatus, error) {
	if device == nil {
		return DatapathHookStatus{}, fmt.Errorf("trustix datapath device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return DatapathHookStatus{}, fmt.Errorf("trustix datapath device is closed")
	}
	return datapathHookFD(uintptr(device.file.Fd()), request)
}

func (device *DatapathDevice) HookQuery() (DatapathHookStatus, error) {
	return device.Hook(DatapathHookRequest{Op: TrustIXDatapathHookOpQuery})
}

func (device *DatapathDevice) HookDetach() (DatapathHookStatus, error) {
	return device.Hook(DatapathHookRequest{Op: TrustIXDatapathHookOpDetach})
}

func DatapathTIXTEncap(path string, inner []byte, sequence uint64) (DatapathTIXTEncapResult, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	if len(inner) == 0 {
		return DatapathTIXTEncapResult{}, fmt.Errorf("trustix datapath TIXT encap input is empty")
	}
	if len(inner) > TrustIXDatapathPacketMaxLen {
		return DatapathTIXTEncapResult{}, fmt.Errorf("trustix datapath TIXT encap input length %d exceeds max %d", len(inner), TrustIXDatapathPacketMaxLen)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathTIXTEncapResult{}, err
	}
	defer file.Close()
	wire := make([]byte, 40+len(inner))
	req := TrustIXDatapathIOCTIXTEncap{
		Version:  TrustIXDatapathHelpersIOCVersion,
		InnerLen: uint32(len(inner)),
		InnerPtr: sliceDataPtr(inner),
		OutLen:   uint32(len(wire)),
		OutPtr:   sliceDataPtr(wire),
		Sequence: sequence,
	}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCTIXTEncapCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(inner)
		runtime.KeepAlive(wire)
		return DatapathTIXTEncapResult{}, err
	}
	runtime.KeepAlive(inner)
	runtime.KeepAlive(wire)
	if req.Result != 0 {
		return DatapathTIXTEncapResult{
			Wire:         wire[:0],
			WrittenLen:   req.WrittenLen,
			FlowID:       req.FlowID,
			Epoch:        req.Epoch,
			RouteFlags:   req.RouteFlags,
			PrefixLen:    req.PrefixLen,
			SessionFlags: req.SessionFlags,
		}, syscall.Errno(-req.Result)
	}
	if int(req.WrittenLen) > len(wire) {
		return DatapathTIXTEncapResult{}, fmt.Errorf("trustix datapath TIXT encap wrote %d > output %d", req.WrittenLen, len(wire))
	}
	return DatapathTIXTEncapResult{
		Wire:         wire[:req.WrittenLen],
		WrittenLen:   req.WrittenLen,
		FlowID:       req.FlowID,
		Epoch:        req.Epoch,
		RouteFlags:   req.RouteFlags,
		PrefixLen:    req.PrefixLen,
		SessionFlags: req.SessionFlags,
	}, nil
}

func DatapathTIXTDecap(path string, wire []byte) (DatapathTIXTDecapResult, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	if len(wire) == 0 {
		return DatapathTIXTDecapResult{}, fmt.Errorf("trustix datapath TIXT decap input is empty")
	}
	if len(wire) > 40+TrustIXDatapathPacketMaxLen {
		return DatapathTIXTDecapResult{}, fmt.Errorf("trustix datapath TIXT decap input length %d exceeds max %d", len(wire), 40+TrustIXDatapathPacketMaxLen)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathTIXTDecapResult{}, err
	}
	defer file.Close()
	inner := make([]byte, TrustIXDatapathPacketMaxLen)
	req := TrustIXDatapathIOCTIXTDecap{
		Version: TrustIXDatapathHelpersIOCVersion,
		WireLen: uint32(len(wire)),
		WirePtr: sliceDataPtr(wire),
		OutLen:  uint32(len(inner)),
		OutPtr:  sliceDataPtr(inner),
	}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCTIXTDecapCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(wire)
		runtime.KeepAlive(inner)
		return DatapathTIXTDecapResult{}, err
	}
	runtime.KeepAlive(wire)
	runtime.KeepAlive(inner)
	if req.Result != 0 {
		return DatapathTIXTDecapResult{
			Inner:        inner[:0],
			WrittenLen:   req.WrittenLen,
			FlowID:       req.FlowID,
			Epoch:        req.Epoch,
			Sequence:     req.Sequence,
			PayloadLen:   req.PayloadLen,
			TIXTFlags:    req.TIXTFlags,
			SessionFlags: req.SessionFlags,
		}, syscall.Errno(-req.Result)
	}
	if int(req.WrittenLen) > len(inner) {
		return DatapathTIXTDecapResult{}, fmt.Errorf("trustix datapath TIXT decap wrote %d > output %d", req.WrittenLen, len(inner))
	}
	return DatapathTIXTDecapResult{
		Inner:        inner[:req.WrittenLen],
		WrittenLen:   req.WrittenLen,
		FlowID:       req.FlowID,
		Epoch:        req.Epoch,
		Sequence:     req.Sequence,
		PayloadLen:   req.PayloadLen,
		TIXTFlags:    req.TIXTFlags,
		SessionFlags: req.SessionFlags,
	}, nil
}

func DatapathOuterBuild(path string, inner []byte, sequence uint64) (DatapathOuterBuildResult, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	if len(inner) == 0 {
		return DatapathOuterBuildResult{}, fmt.Errorf("trustix datapath outer build input is empty")
	}
	if len(inner) > TrustIXDatapathPacketMaxLen {
		return DatapathOuterBuildResult{}, fmt.Errorf("trustix datapath outer build input length %d exceeds max %d", len(inner), TrustIXDatapathPacketMaxLen)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathOuterBuildResult{}, err
	}
	defer file.Close()
	outer := make([]byte, 20+20+40+len(inner))
	req := TrustIXDatapathIOCOuterBuild{
		Version:  TrustIXDatapathHelpersIOCVersion,
		InnerLen: uint32(len(inner)),
		InnerPtr: sliceDataPtr(inner),
		OutLen:   uint32(len(outer)),
		OutPtr:   sliceDataPtr(outer),
		Sequence: sequence,
	}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCOuterBuildCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(inner)
		runtime.KeepAlive(outer)
		return DatapathOuterBuildResult{}, err
	}
	runtime.KeepAlive(inner)
	runtime.KeepAlive(outer)
	if req.Result != 0 {
		return DatapathOuterBuildResult{
			Outer:         outer[:0],
			WrittenLen:    req.WrittenLen,
			FlowID:        req.FlowID,
			Epoch:         req.Epoch,
			RouteFlags:    req.RouteFlags,
			PrefixLen:     req.PrefixLen,
			SessionFlags:  req.SessionFlags,
			LocalIPv4:     req.LocalIPv4,
			RemoteIPv4:    req.RemoteIPv4,
			LocalPort:     req.LocalPort,
			RemotePort:    req.RemotePort,
			OuterProtocol: req.OuterProtocol,
			TIXTLen:       req.TIXTLen,
		}, syscall.Errno(-req.Result)
	}
	if int(req.WrittenLen) > len(outer) {
		return DatapathOuterBuildResult{}, fmt.Errorf("trustix datapath outer build wrote %d > output %d", req.WrittenLen, len(outer))
	}
	return DatapathOuterBuildResult{
		Outer:         outer[:req.WrittenLen],
		WrittenLen:    req.WrittenLen,
		FlowID:        req.FlowID,
		Epoch:         req.Epoch,
		RouteFlags:    req.RouteFlags,
		PrefixLen:     req.PrefixLen,
		SessionFlags:  req.SessionFlags,
		LocalIPv4:     req.LocalIPv4,
		RemoteIPv4:    req.RemoteIPv4,
		LocalPort:     req.LocalPort,
		RemotePort:    req.RemotePort,
		OuterProtocol: req.OuterProtocol,
		TIXTLen:       req.TIXTLen,
	}, nil
}

func DatapathOuterParse(path string, outer []byte) (DatapathOuterParseResult, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	if len(outer) == 0 {
		return DatapathOuterParseResult{}, fmt.Errorf("trustix datapath outer parse input is empty")
	}
	if len(outer) > TrustIXDatapathPacketMaxLen {
		return DatapathOuterParseResult{}, fmt.Errorf("trustix datapath outer parse input length %d exceeds max %d", len(outer), TrustIXDatapathPacketMaxLen)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathOuterParseResult{}, err
	}
	defer file.Close()
	inner := make([]byte, TrustIXDatapathPacketMaxLen)
	req := TrustIXDatapathIOCOuterParse{
		Version:  TrustIXDatapathHelpersIOCVersion,
		OuterLen: uint32(len(outer)),
		OuterPtr: sliceDataPtr(outer),
		OutLen:   uint32(len(inner)),
		OutPtr:   sliceDataPtr(inner),
	}
	if err := ioctl(uintptr(file.Fd()), TrustIXDatapathIOCOuterParseCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(outer)
		runtime.KeepAlive(inner)
		return DatapathOuterParseResult{}, err
	}
	runtime.KeepAlive(outer)
	runtime.KeepAlive(inner)
	result := DatapathOuterParseResult{
		WrittenLen:    req.WrittenLen,
		Flags:         req.Flags,
		FlowID:        req.FlowID,
		Epoch:         req.Epoch,
		Sequence:      req.Sequence,
		PayloadLen:    req.PayloadLen,
		TIXTFlags:     req.TIXTFlags,
		SessionFlags:  req.SessionFlags,
		LocalIPv4:     req.LocalIPv4,
		RemoteIPv4:    req.RemoteIPv4,
		LocalPort:     req.LocalPort,
		RemotePort:    req.RemotePort,
		OuterProtocol: req.OuterProtocol,
		TIXTLen:       req.TIXTLen,
	}
	if req.Result != 0 {
		result.Inner = inner[:0]
		return result, syscall.Errno(-req.Result)
	}
	if int(req.WrittenLen) > len(inner) {
		return DatapathOuterParseResult{}, fmt.Errorf("trustix datapath outer parse wrote %d > output %d", req.WrittenLen, len(inner))
	}
	result.Inner = inner[:req.WrittenLen]
	return result, nil
}

func DatapathRXStageQuery(path string) (DatapathRXStageResult, error) {
	return datapathRXStage(path, TrustIXDatapathRXStageOpQuery, nil)
}

func DatapathRXStagePeek(path string) (DatapathRXStageResult, error) {
	out := make([]byte, TrustIXDatapathPacketMaxLen)
	return datapathRXStage(path, TrustIXDatapathRXStageOpPeek, out)
}

func DatapathRXStagePop(path string) (DatapathRXStageResult, error) {
	out := make([]byte, TrustIXDatapathPacketMaxLen)
	return datapathRXStage(path, TrustIXDatapathRXStageOpPop, out)
}

func DatapathRXStageClear(path string) (DatapathRXStageResult, error) {
	return datapathRXStage(path, TrustIXDatapathRXStageOpClear, nil)
}

func (device *DatapathDevice) RXStageQuery() (DatapathRXStageResult, error) {
	return device.rxStage(TrustIXDatapathRXStageOpQuery, nil)
}

func (device *DatapathDevice) RXStagePeekInto(out []byte) (DatapathRXStageResult, error) {
	if len(out) == 0 {
		return DatapathRXStageResult{}, fmt.Errorf("trustix datapath RX stage output buffer is empty")
	}
	return device.rxStage(TrustIXDatapathRXStageOpPeek, out)
}

func (device *DatapathDevice) RXStagePopInto(out []byte) (DatapathRXStageResult, error) {
	if len(out) == 0 {
		return DatapathRXStageResult{}, fmt.Errorf("trustix datapath RX stage output buffer is empty")
	}
	return device.rxStage(TrustIXDatapathRXStageOpPop, out)
}

func (device *DatapathDevice) RXStageClear() (DatapathRXStageResult, error) {
	return device.rxStage(TrustIXDatapathRXStageOpClear, nil)
}

func (device *DatapathDevice) rxStage(op uint32, out []byte) (DatapathRXStageResult, error) {
	if device == nil {
		return DatapathRXStageResult{}, fmt.Errorf("trustix datapath device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return DatapathRXStageResult{}, fmt.Errorf("trustix datapath device is closed")
	}
	return datapathRXStageFD(uintptr(device.file.Fd()), op, out)
}

func datapathRXStage(path string, op uint32, out []byte) (DatapathRXStageResult, error) {
	if path == "" {
		path = TrustIXDatapathDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return DatapathRXStageResult{}, err
	}
	defer file.Close()
	return datapathRXStageFD(uintptr(file.Fd()), op, out)
}

func datapathRXStageFD(fd uintptr, op uint32, out []byte) (DatapathRXStageResult, error) {
	req := TrustIXDatapathIOCRXStage{
		Version: TrustIXDatapathHelpersIOCVersion,
		Op:      op,
	}
	if len(out) > 0 {
		req.OutLen = uint32(len(out))
		req.OutPtr = sliceDataPtr(out)
	}
	if err := ioctl(fd, TrustIXDatapathIOCRXStageCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(out)
		return DatapathRXStageResult{}, err
	}
	runtime.KeepAlive(out)
	result := DatapathRXStageResult{
		WrittenLen:       req.WrittenLen,
		ID:               req.ID,
		FlowID:           req.FlowID,
		Epoch:            req.Epoch,
		Sequence:         req.Sequence,
		PayloadLen:       req.PayloadLen,
		TIXTFlags:        req.TIXTFlags,
		SessionFlags:     req.SessionFlags,
		OuterSourceIPv4:  req.OuterSourceIPv4,
		OuterDestIPv4:    req.OuterDestIPv4,
		OuterSourcePort:  req.OuterSourcePort,
		OuterDestPort:    req.OuterDestPort,
		OuterProtocol:    req.OuterProtocol,
		InnerProtocol:    req.InnerProtocol,
		InnerSourceIPv4:  req.InnerSourceIPv4,
		InnerDestIPv4:    req.InnerDestIPv4,
		InnerSourcePort:  req.InnerSourcePort,
		InnerDestPort:    req.InnerDestPort,
		InnerIPHeaderLen: req.InnerIPHeaderLen,
		InnerL4HeaderLen: req.InnerL4HeaderLen,
		QueueLen:         req.QueueLen,
		Capacity:         req.Capacity,
		SlotLen:          req.SlotLen,
		Staged:           req.Staged,
		Popped:           req.Popped,
		Dropped:          req.Dropped,
		Overwritten:      req.Overwritten,
	}
	if req.Result != 0 {
		result.Inner = out[:0]
		return result, syscall.Errno(-req.Result)
	}
	if int(req.WrittenLen) > len(out) {
		return DatapathRXStageResult{}, fmt.Errorf("trustix datapath RX stage wrote %d > output %d", req.WrittenLen, len(out))
	}
	result.Inner = out[:req.WrittenLen]
	return result, nil
}

func AEADDirectSetKey(path string, slot uint32, key []byte, open bool) error {
	_, err := AEADDirectSetKeyAlloc(path, slot, key, open)
	return err
}

func AEADDirectSetKeyAlloc(path string, slot uint32, key []byte, open bool) (uint32, error) {
	if err := validateAEADKey(key); err != nil {
		return 0, err
	}
	if slot != TrustIXAEADDirectAnySlot && slot >= TrustIXAEADDirectMaxSlots {
		return 0, fmt.Errorf("trustix AEAD direct slot %d exceeds max %d", slot, TrustIXAEADDirectMaxSlots)
	}
	if path == "" {
		path = TrustIXAEADDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	var flags uint32
	if open {
		flags = trustIXAEADDirectFlagOpen
	}
	req := trustIXAEADIOCDirectKey{
		Version: trustIXAEADIOCVersion,
		Flags:   flags,
		Slot:    slot,
		KeyLen:  uint32(len(key)),
		KeyPtr:  sliceDataPtr(key),
	}
	if err := ioctl(uintptr(file.Fd()), trustIXAEADIOCDirectSetKeyCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(key)
		return 0, err
	}
	runtime.KeepAlive(key)
	if req.Result != 0 {
		return 0, fmt.Errorf("trustix AEAD direct set key returned %d", req.Result)
	}
	return req.Slot, nil
}

func AEADDirectClearKey(path string, slot uint32) error {
	if slot >= TrustIXAEADDirectMaxSlots {
		return fmt.Errorf("trustix AEAD direct slot %d exceeds max %d", slot, TrustIXAEADDirectMaxSlots)
	}
	if path == "" {
		path = TrustIXAEADDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	req := trustIXAEADIOCDirectKey{
		Version: trustIXAEADIOCVersion,
		Slot:    slot,
	}
	if err := ioctl(uintptr(file.Fd()), trustIXAEADIOCDirectClearKeyCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return err
	}
	if req.Result != 0 {
		return fmt.Errorf("trustix AEAD direct clear key returned %d", req.Result)
	}
	return nil
}

func AEADPoolOpSize() int {
	return int(unsafe.Sizeof(trustIXAEADIOCPoolOp{}))
}

func AEADSealBatch(path string, key []byte, ops []AEADBatchOp) error {
	return aeadBatch(path, 0, key, ops)
}

func AEADOpenBatch(path string, key []byte, ops []AEADBatchOp) error {
	return aeadBatch(path, trustIXAEADIOCFlagDecrypt, key, ops)
}

func OpenAEADDevice(path string) (*AEADDevice, error) {
	if path == "" {
		path = TrustIXAEADDevicePath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &AEADDevice{file: file}, nil
}

func (device *AEADDevice) Close() error {
	if device == nil || device.file == nil {
		return nil
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	var err error
	if device.pool != nil {
		err = unix.Munmap(device.pool)
		device.pool = nil
	}
	closeErr := device.file.Close()
	device.file = nil
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return err
}

func (device *AEADDevice) SetKey(key []byte) error {
	if err := validateAEADKey(key); err != nil {
		return err
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return fmt.Errorf("trustix AEAD device is closed")
	}
	req := trustIXAEADIOCKey{
		Version: trustIXAEADIOCVersion,
		KeyLen:  uint32(len(key)),
		KeyPtr:  sliceDataPtr(key),
	}
	if err := ioctl(uintptr(device.file.Fd()), trustIXAEADIOCSetKeyCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		runtime.KeepAlive(key)
		return err
	}
	runtime.KeepAlive(key)
	if req.Result != 0 {
		return fmt.Errorf("trustix AEAD set key returned %d", req.Result)
	}
	return nil
}

func (device *AEADDevice) ClearKey() error {
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return fmt.Errorf("trustix AEAD device is closed")
	}
	return ioctl(uintptr(device.file.Fd()), trustIXAEADIOCClearKeyCmd(), 0)
}

func (device *AEADDevice) MmapPool(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("trustix AEAD pool size %d is invalid", size)
	}
	if device == nil {
		return nil, fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return nil, fmt.Errorf("trustix AEAD device is closed")
	}
	if device.pool != nil {
		if err := unix.Munmap(device.pool); err != nil {
			return nil, err
		}
		device.pool = nil
	}
	req := trustIXAEADIOCPool{
		Version: trustIXAEADIOCVersion,
		Size:    uint64(size),
	}
	if err := ioctl(uintptr(device.file.Fd()), trustIXAEADIOCConfigPoolCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return nil, err
	}
	if req.Result != 0 {
		return nil, fmt.Errorf("trustix AEAD config pool returned %d", req.Result)
	}
	pool, err := unix.Mmap(int(device.file.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	device.pool = pool
	return pool, nil
}

func (device *AEADDevice) MunmapPool() error {
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.pool == nil {
		return nil
	}
	err := unix.Munmap(device.pool)
	device.pool = nil
	return err
}

func (device *AEADDevice) Pool() []byte {
	if device == nil {
		return nil
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	return device.pool
}

func (device *AEADDevice) PreparePoolBatchOps(opsOffset int, ops []AEADPoolBatchOp) error {
	if len(ops) == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	rawOps, err := device.rawPoolOpsLocked(opsOffset, len(ops))
	if err != nil {
		return err
	}
	for i := range ops {
		rawOps[i] = trustIXAEADIOCPoolOp{
			NonceOff: ops[i].NonceOff,
			InOff:    ops[i].InOff,
			OutOff:   ops[i].OutOff,
			NonceLen: ops[i].NonceLen,
			InLen:    ops[i].InLen,
			OutLen:   ops[i].OutLen,
		}
	}
	return nil
}

func (device *AEADDevice) PrepareRunPoolBatchOps(opsOffset int, ops []AEADPoolBatchOp, decrypt bool) error {
	var flags uint32
	if decrypt {
		flags = trustIXAEADIOCFlagDecrypt
	}
	if len(ops) == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	rawOps, err := device.rawPoolOpsLocked(opsOffset, len(ops))
	if err != nil {
		return err
	}
	for i := range ops {
		rawOps[i] = trustIXAEADIOCPoolOp{
			NonceOff: ops[i].NonceOff,
			InOff:    ops[i].InOff,
			OutOff:   ops[i].OutOff,
			NonceLen: ops[i].NonceLen,
			InLen:    ops[i].InLen,
			OutLen:   ops[i].OutLen,
		}
	}
	return device.poolPrepareRunBatchRawLocked(flags, opsOffset, len(ops), rawOps)
}

func (device *AEADDevice) PrepareKernelPoolBatch(opsOffset int, opCount int, decrypt bool) error {
	var flags uint32
	if decrypt {
		flags = trustIXAEADIOCFlagDecrypt
	}
	if opCount == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if _, err := device.rawPoolOpsLocked(opsOffset, opCount); err != nil {
		return err
	}
	req := trustIXAEADIOCPoolBatch{
		Version: trustIXAEADIOCVersion,
		Flags:   flags,
		OpCount: uint32(opCount),
		OpsOff:  uint64(opsOffset),
	}
	if err := ioctl(uintptr(device.file.Fd()), trustIXAEADIOCPreparePoolBatchCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return err
	}
	if req.Result < 0 {
		return fmt.Errorf("trustix AEAD prepare pool batch returned %d", req.Result)
	}
	return nil
}

func (device *AEADDevice) PrepareRunKernelPoolBatch(opsOffset int, opCount int, decrypt bool) error {
	var flags uint32
	if decrypt {
		flags = trustIXAEADIOCFlagDecrypt
	}
	if opCount == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	rawOps, err := device.rawPoolOpsLocked(opsOffset, opCount)
	if err != nil {
		return err
	}
	if err := device.poolPrepareRunBatchRawLocked(flags, opsOffset, opCount, rawOps); err != nil {
		if results, ok := AEADPoolBatchResults(err); ok && len(results) == len(rawOps) {
			return err
		}
		return err
	}
	return nil
}

func (device *AEADDevice) SealPoolBatch(opsOffset int, ops []AEADPoolBatchOp) error {
	return device.poolBatch(0, opsOffset, ops)
}

func (device *AEADDevice) OpenPoolBatch(opsOffset int, ops []AEADPoolBatchOp) error {
	return device.poolBatch(trustIXAEADIOCFlagDecrypt, opsOffset, ops)
}

func (device *AEADDevice) SealPreparedPoolBatch(opsOffset int, opCount int) error {
	return device.preparedPoolBatch(0, opsOffset, opCount)
}

func (device *AEADDevice) OpenPreparedPoolBatch(opsOffset int, opCount int) error {
	return device.preparedPoolBatch(trustIXAEADIOCFlagDecrypt, opsOffset, opCount)
}

func (device *AEADDevice) SealPreparedPoolBatchFast(opsOffset int, opCount int) error {
	return device.preparedPoolBatchFast(0, opsOffset, opCount)
}

func (device *AEADDevice) OpenPreparedPoolBatchFast(opsOffset int, opCount int) error {
	return device.preparedPoolBatchFast(trustIXAEADIOCFlagDecrypt, opsOffset, opCount)
}

func (device *AEADDevice) SealKernelPreparedPoolBatch(start int, opCount int) error {
	return device.kernelPreparedPoolBatch(0, start, opCount)
}

func (device *AEADDevice) OpenKernelPreparedPoolBatch(start int, opCount int) error {
	return device.kernelPreparedPoolBatch(trustIXAEADIOCFlagDecrypt, start, opCount)
}

func (device *AEADDevice) poolBatch(flags uint32, opsOffset int, ops []AEADPoolBatchOp) error {
	if len(ops) == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	rawOps, err := device.rawPoolOpsLocked(opsOffset, len(ops))
	if err != nil {
		return err
	}
	for i := range ops {
		rawOps[i] = trustIXAEADIOCPoolOp{
			NonceOff: ops[i].NonceOff,
			InOff:    ops[i].InOff,
			OutOff:   ops[i].OutOff,
			NonceLen: ops[i].NonceLen,
			InLen:    ops[i].InLen,
			OutLen:   ops[i].OutLen,
		}
	}
	if err := device.poolBatchLocked(flags, opsOffset, len(ops)); err != nil {
		return err
	}
	for i := range ops {
		ops[i].OutLen = rawOps[i].OutLen
		ops[i].Result = rawOps[i].Result
		if rawOps[i].Result != 0 {
			return fmt.Errorf("trustix AEAD pool op %d returned %d", i, rawOps[i].Result)
		}
	}
	return nil
}

func (device *AEADDevice) preparedPoolBatch(flags uint32, opsOffset int, opCount int) error {
	if opCount == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	rawOps, err := device.rawPoolOpsLocked(opsOffset, opCount)
	if err != nil {
		return err
	}
	if err := device.poolBatchLocked(flags, opsOffset, opCount); err != nil {
		return err
	}
	for i := range rawOps {
		if rawOps[i].Result != 0 {
			return fmt.Errorf("trustix AEAD pool op %d returned %d", i, rawOps[i].Result)
		}
	}
	return nil
}

func (device *AEADDevice) preparedPoolBatchFast(flags uint32, opsOffset int, opCount int) error {
	if opCount == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if _, err := device.rawPoolOpsLocked(opsOffset, opCount); err != nil {
		return err
	}
	return device.poolBatchLocked(flags, opsOffset, opCount)
}

func (device *AEADDevice) kernelPreparedPoolBatch(flags uint32, start int, opCount int) error {
	if opCount == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return fmt.Errorf("trustix AEAD device is closed")
	}
	if start < 0 || opCount < 0 {
		return fmt.Errorf("trustix AEAD prepared pool start/count is invalid")
	}
	if opCount > trustIXAEADIOCBatchMaxOps {
		return fmt.Errorf("trustix AEAD prepared pool op count %d exceeds max %d", opCount, trustIXAEADIOCBatchMaxOps)
	}
	req := trustIXAEADIOCPoolPreparedBatch{
		Version: trustIXAEADIOCVersion,
		Flags:   flags,
		OpCount: uint32(opCount),
		Start:   uint32(start),
	}
	rawOps, rawErr := device.rawPoolOpsLocked(start*int(unsafe.Sizeof(trustIXAEADIOCPoolOp{})), opCount)
	if rawErr != nil {
		return rawErr
	}
	if err := ioctl(uintptr(device.file.Fd()), trustIXAEADIOCPoolPreparedBatchCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return err
	}
	if req.Result < 0 {
		return newAEADPoolBatchError("trustix AEAD prepared pool batch returned", req.Result, rawOps)
	}
	return nil
}

func (device *AEADDevice) poolBatchLocked(flags uint32, opsOffset int, opCount int) error {
	if device.file == nil {
		return fmt.Errorf("trustix AEAD device is closed")
	}
	rawOps, err := device.rawPoolOpsLocked(opsOffset, opCount)
	if err != nil {
		return err
	}
	req := trustIXAEADIOCPoolBatch{
		Version: trustIXAEADIOCVersion,
		Flags:   flags,
		OpCount: uint32(opCount),
		OpsOff:  uint64(opsOffset),
	}
	if err := ioctl(uintptr(device.file.Fd()), trustIXAEADIOCPoolBatchCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return err
	}
	if req.Result < 0 {
		return newAEADPoolBatchError("trustix AEAD pool batch returned", req.Result, rawOps)
	}
	return nil
}

func (device *AEADDevice) poolPrepareRunBatchLocked(flags uint32, opsOffset int, opCount int) error {
	if device.file == nil {
		return fmt.Errorf("trustix AEAD device is closed")
	}
	rawOps, err := device.rawPoolOpsLocked(opsOffset, opCount)
	if err != nil {
		return err
	}
	return device.poolPrepareRunBatchRawLocked(flags, opsOffset, opCount, rawOps)
}

func (device *AEADDevice) poolPrepareRunBatchRawLocked(flags uint32, opsOffset int, opCount int, rawOps []trustIXAEADIOCPoolOp) error {
	if device.file == nil {
		return fmt.Errorf("trustix AEAD device is closed")
	}
	req := trustIXAEADIOCPoolBatch{
		Version: trustIXAEADIOCVersion,
		Flags:   flags,
		OpCount: uint32(opCount),
		OpsOff:  uint64(opsOffset),
	}
	if err := ioctl(uintptr(device.file.Fd()), trustIXAEADIOCPoolPrepareRunBatchCmd(), uintptr(unsafe.Pointer(&req))); err != nil {
		return err
	}
	if req.Result < 0 {
		return newAEADPoolBatchError("trustix AEAD pool prepare-run batch returned", req.Result, rawOps)
	}
	return nil
}

func (device *AEADDevice) rawPoolOpsLocked(opsOffset int, opCount int) ([]trustIXAEADIOCPoolOp, error) {
	if device.file == nil {
		return nil, fmt.Errorf("trustix AEAD device is closed")
	}
	if device.pool == nil {
		return nil, fmt.Errorf("trustix AEAD pool is not mapped")
	}
	if opsOffset < 0 || opCount < 0 {
		return nil, fmt.Errorf("trustix AEAD pool ops offset/count is invalid")
	}
	if opsOffset%8 != 0 {
		return nil, fmt.Errorf("trustix AEAD pool ops offset %d is not 8-byte aligned", opsOffset)
	}
	if opCount > trustIXAEADIOCBatchMaxOps {
		return nil, fmt.Errorf("trustix AEAD pool op count %d exceeds max %d", opCount, trustIXAEADIOCBatchMaxOps)
	}
	opSize := int(unsafe.Sizeof(trustIXAEADIOCPoolOp{}))
	if opCount > len(device.pool)/opSize {
		return nil, fmt.Errorf("trustix AEAD pool op count %d exceeds pool capacity", opCount)
	}
	opsLen := opCount * opSize
	if opsOffset > len(device.pool) || opsLen > len(device.pool)-opsOffset {
		return nil, fmt.Errorf("trustix AEAD pool ops range offset=%d len=%d exceeds pool %d", opsOffset, opsLen, len(device.pool))
	}
	if opCount == 0 {
		return nil, nil
	}
	return unsafe.Slice((*trustIXAEADIOCPoolOp)(unsafe.Pointer(&device.pool[opsOffset])), opCount), nil
}

func (device *AEADDevice) SealBatch(ops []AEADBatchOp) error {
	return device.batch(0, ops)
}

func (device *AEADDevice) OpenBatch(ops []AEADBatchOp) error {
	return device.batch(trustIXAEADIOCFlagDecrypt, ops)
}

func (device *AEADDevice) batch(flags uint32, ops []AEADBatchOp) error {
	if len(ops) == 0 {
		return nil
	}
	if device == nil {
		return fmt.Errorf("trustix AEAD device is nil")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return fmt.Errorf("trustix AEAD device is closed")
	}
	return aeadBatchFD(uintptr(device.file.Fd()), flags, nil, ops)
}

func aeadBatch(path string, flags uint32, key []byte, ops []AEADBatchOp) error {
	if path == "" {
		path = TrustIXAEADDevicePath
	}
	if len(ops) == 0 {
		return nil
	}
	if err := validateAEADKey(key); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return aeadBatchFD(uintptr(file.Fd()), flags, key, ops)
}

func aeadBatchFD(fd uintptr, flags uint32, key []byte, ops []AEADBatchOp) error {
	if len(ops) == 0 {
		return nil
	}
	if key != nil {
		if err := validateAEADKey(key); err != nil {
			return err
		}
	}
	if len(ops) > trustIXAEADIOCBatchMaxOps {
		return fmt.Errorf("trustix AEAD batch op count %d exceeds max %d", len(ops), trustIXAEADIOCBatchMaxOps)
	}
	rawOps := make([]trustIXAEADIOCOp, len(ops))
	for i := range ops {
		if len(ops[i].Nonce) != TrustIXAEADNonceLen {
			return fmt.Errorf("trustix AEAD op %d nonce length %d is invalid", i, len(ops[i].Nonce))
		}
		if len(ops[i].In) == 0 {
			return fmt.Errorf("trustix AEAD op %d input is empty", i)
		}
		if len(ops[i].In) > TrustIXAEADInputMax {
			return fmt.Errorf("trustix AEAD op %d input length %d exceeds max %d", i, len(ops[i].In), TrustIXAEADInputMax)
		}
		if len(ops[i].Out) == 0 {
			return fmt.Errorf("trustix AEAD op %d output buffer is empty", i)
		}
		rawOps[i] = trustIXAEADIOCOp{
			NoncePtr: sliceDataPtr(ops[i].Nonce),
			InPtr:    sliceDataPtr(ops[i].In),
			OutPtr:   sliceDataPtr(ops[i].Out),
			NonceLen: uint32(len(ops[i].Nonce)),
			InLen:    uint32(len(ops[i].In)),
			OutLen:   uint32(len(ops[i].Out)),
		}
	}
	batch := trustIXAEADIOCBatch{
		Version: trustIXAEADIOCVersion,
		Flags:   flags,
		OpCount: uint32(len(rawOps)),
		OpsPtr:  sliceDataPtr(rawOps),
	}
	if key != nil {
		batch.KeyLen = uint32(len(key))
		batch.KeyPtr = sliceDataPtr(key)
	}
	if err := ioctl(fd, trustIXAEADIOCBatchCmd(), uintptr(unsafe.Pointer(&batch))); err != nil {
		runtime.KeepAlive(key)
		runtime.KeepAlive(rawOps)
		for i := range ops {
			runtime.KeepAlive(ops[i].Nonce)
			runtime.KeepAlive(ops[i].In)
			runtime.KeepAlive(ops[i].Out)
		}
		return err
	}
	runtime.KeepAlive(key)
	runtime.KeepAlive(rawOps)
	for i := range ops {
		runtime.KeepAlive(ops[i].Nonce)
		runtime.KeepAlive(ops[i].In)
		runtime.KeepAlive(ops[i].Out)
		if rawOps[i].Result != 0 {
			return fmt.Errorf("trustix AEAD op %d returned %d", i, rawOps[i].Result)
		}
		if int(rawOps[i].OutLen) > len(ops[i].Out) {
			return fmt.Errorf("trustix AEAD op %d returned output length %d > buffer %d", i, rawOps[i].OutLen, len(ops[i].Out))
		}
		ops[i].Out = ops[i].Out[:rawOps[i].OutLen]
	}
	if batch.Result < 0 {
		return fmt.Errorf("trustix AEAD batch returned %d", batch.Result)
	}
	return nil
}

func validateAEADKey(key []byte) error {
	if len(key) != 16 && len(key) != 32 {
		return fmt.Errorf("trustix AEAD key length %d is invalid", len(key))
	}
	return nil
}

func ioctl(fd uintptr, request uintptr, arg uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, request, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func trustIXAEADIOCBatchCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 2, unsafe.Sizeof(trustIXAEADIOCBatch{}))
}

func trustIXAEADIOCSetKeyCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 3, unsafe.Sizeof(trustIXAEADIOCKey{}))
}

func trustIXAEADIOCClearKeyCmd() uintptr {
	return ioctlIO(trustIXAEADIOCMagic, 4)
}

func trustIXAEADIOCConfigPoolCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 5, unsafe.Sizeof(trustIXAEADIOCPool{}))
}

func trustIXAEADIOCPoolBatchCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 6, unsafe.Sizeof(trustIXAEADIOCPoolBatch{}))
}

func trustIXAEADIOCPreparePoolBatchCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 7, unsafe.Sizeof(trustIXAEADIOCPoolBatch{}))
}

func trustIXAEADIOCPoolPreparedBatchCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 8, unsafe.Sizeof(trustIXAEADIOCPoolPreparedBatch{}))
}

func trustIXAEADIOCPoolPrepareRunBatchCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 9, unsafe.Sizeof(trustIXAEADIOCPoolBatch{}))
}

func trustIXAEADIOCDirectSetKeyCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 10, unsafe.Sizeof(trustIXAEADIOCDirectKey{}))
}

func trustIXAEADIOCDirectClearKeyCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 11, unsafe.Sizeof(trustIXAEADIOCDirectKey{}))
}

func TrustIXDatapathHelpersIOCQueryCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 12, unsafe.Sizeof(TrustIXDatapathHelpersIOCQuery{}))
}

func TrustIXDatapathHelpersIOCSelftestCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 13, unsafe.Sizeof(TrustIXDatapathHelpersIOCSelftest{}))
}

func TrustIXDatapathIOCStateCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 14, unsafe.Sizeof(TrustIXDatapathIOCState{}))
}

func TrustIXDatapathIOCStateStatsCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 15, unsafe.Sizeof(TrustIXDatapathIOCStateStats{}))
}

func TrustIXDatapathIOCStateBatchCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 16, unsafe.Sizeof(TrustIXDatapathIOCStateBatch{}))
}

func TrustIXDatapathIOCClassifyCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 17, unsafe.Sizeof(TrustIXDatapathIOCClassify{}))
}

func TrustIXDatapathIOCPacketClassifyCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 18, unsafe.Sizeof(TrustIXDatapathIOCPacketClassify{}))
}

func TrustIXDatapathIOCPacketStatsCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 19, unsafe.Sizeof(TrustIXDatapathIOCPacketStats{}))
}

func TrustIXDatapathIOCHookCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 20, unsafe.Sizeof(TrustIXDatapathIOCHook{}))
}

func TrustIXDatapathIOCTIXTEncapCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 21, unsafe.Sizeof(TrustIXDatapathIOCTIXTEncap{}))
}

func TrustIXDatapathIOCTIXTDecapCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 22, unsafe.Sizeof(TrustIXDatapathIOCTIXTDecap{}))
}

func TrustIXDatapathIOCOuterBuildCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 23, unsafe.Sizeof(TrustIXDatapathIOCOuterBuild{}))
}

func TrustIXDatapathIOCOuterParseCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 24, unsafe.Sizeof(TrustIXDatapathIOCOuterParse{}))
}

func TrustIXDatapathIOCRXStageCmd() uintptr {
	return ioctlIOWR(trustIXAEADIOCMagic, 25, unsafe.Sizeof(TrustIXDatapathIOCRXStage{}))
}

func featureListContains(features []string, feature string) bool {
	for _, candidate := range features {
		if candidate == feature {
			return true
		}
	}
	return false
}

func nullTerminatedString(raw []byte) string {
	for i, value := range raw {
		if value == 0 {
			return string(raw[:i])
		}
	}
	return string(raw)
}

func ioctlIOWR(typ uintptr, nr uintptr, size uintptr) uintptr {
	const (
		iocNRBits    = 8
		iocTypeBits  = 8
		iocSizeBits  = 14
		iocNRShift   = 0
		iocTypeShift = iocNRShift + iocNRBits
		iocSizeShift = iocTypeShift + iocTypeBits
		iocDirShift  = iocSizeShift + iocSizeBits
		iocWrite     = 1
		iocRead      = 2
	)
	return ((iocRead | iocWrite) << iocDirShift) |
		(typ << iocTypeShift) |
		(nr << iocNRShift) |
		(size << iocSizeShift)
}

func ioctlIO(typ uintptr, nr uintptr) uintptr {
	const (
		iocNRBits    = 8
		iocTypeBits  = 8
		iocNRShift   = 0
		iocTypeShift = iocNRShift + iocNRBits
	)
	return (typ << iocTypeShift) | (nr << iocNRShift)
}

func sliceDataPtr[T any](slice []T) uint64 {
	if len(slice) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&slice[0])))
}
