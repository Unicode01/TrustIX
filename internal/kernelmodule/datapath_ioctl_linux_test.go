//go:build linux

package kernelmodule

import (
	"reflect"
	"testing"
	"unsafe"
)

func TestDatapathQueryIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathHelpersIOCQuery{}), uintptr(72); got != want {
		t.Fatalf("TrustIXDatapathHelpersIOCQuery size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathHelpersIOCQueryCmd(), ioctlIOWR(trustIXAEADIOCMagic, 12, unsafe.Sizeof(TrustIXDatapathHelpersIOCQuery{})); got != want {
		t.Fatalf("datapath query ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathSelftestIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathHelpersIOCSelftest{}), uintptr(48); got != want {
		t.Fatalf("TrustIXDatapathHelpersIOCSelftest size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathHelpersIOCSelftestCmd(), ioctlIOWR(trustIXAEADIOCMagic, 13, unsafe.Sizeof(TrustIXDatapathHelpersIOCSelftest{})); got != want {
		t.Fatalf("datapath selftest ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathStateIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCState{}), uintptr(120); got != want {
		t.Fatalf("TrustIXDatapathIOCState size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCStateCmd(), ioctlIOWR(trustIXAEADIOCMagic, 14, unsafe.Sizeof(TrustIXDatapathIOCState{})); got != want {
		t.Fatalf("datapath state ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathStateStatsIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCStateStats{}), uintptr(112); got != want {
		t.Fatalf("TrustIXDatapathIOCStateStats size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCStateStatsCmd(), ioctlIOWR(trustIXAEADIOCMagic, 15, unsafe.Sizeof(TrustIXDatapathIOCStateStats{})); got != want {
		t.Fatalf("datapath state stats ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathStateBatchIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCStateBatch{}), uintptr(56); got != want {
		t.Fatalf("TrustIXDatapathIOCStateBatch size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCStateBatchCmd(), ioctlIOWR(trustIXAEADIOCMagic, 16, unsafe.Sizeof(TrustIXDatapathIOCStateBatch{})); got != want {
		t.Fatalf("datapath state batch ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathClassifyIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCClassify{}), uintptr(80); got != want {
		t.Fatalf("TrustIXDatapathIOCClassify size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCClassifyCmd(), ioctlIOWR(trustIXAEADIOCMagic, 17, unsafe.Sizeof(TrustIXDatapathIOCClassify{})); got != want {
		t.Fatalf("datapath classify ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathPacketClassifyIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCPacketClassify{}), uintptr(112); got != want {
		t.Fatalf("TrustIXDatapathIOCPacketClassify size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCPacketClassifyCmd(), ioctlIOWR(trustIXAEADIOCMagic, 18, unsafe.Sizeof(TrustIXDatapathIOCPacketClassify{})); got != want {
		t.Fatalf("datapath packet classify ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathPacketStatsIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCPacketStats{}), uintptr(136); got != want {
		t.Fatalf("TrustIXDatapathIOCPacketStats size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCPacketStatsCmd(), ioctlIOWR(trustIXAEADIOCMagic, 19, unsafe.Sizeof(TrustIXDatapathIOCPacketStats{})); got != want {
		t.Fatalf("datapath packet stats ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathHookIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCHook{}), uintptr(216); got != want {
		t.Fatalf("TrustIXDatapathIOCHook size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCHookCmd(), ioctlIOWR(trustIXAEADIOCMagic, 20, unsafe.Sizeof(TrustIXDatapathIOCHook{})); got != want {
		t.Fatalf("datapath hook ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathTIXTEncapIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCTIXTEncap{}), uintptr(120); got != want {
		t.Fatalf("TrustIXDatapathIOCTIXTEncap size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCTIXTEncapCmd(), ioctlIOWR(trustIXAEADIOCMagic, 21, unsafe.Sizeof(TrustIXDatapathIOCTIXTEncap{})); got != want {
		t.Fatalf("datapath TIXT encap ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathTIXTDecapIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCTIXTDecap{}), uintptr(120); got != want {
		t.Fatalf("TrustIXDatapathIOCTIXTDecap size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCTIXTDecapCmd(), ioctlIOWR(trustIXAEADIOCMagic, 22, unsafe.Sizeof(TrustIXDatapathIOCTIXTDecap{})); got != want {
		t.Fatalf("datapath TIXT decap ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathOuterBuildIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCOuterBuild{}), uintptr(136); got != want {
		t.Fatalf("TrustIXDatapathIOCOuterBuild size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCOuterBuildCmd(), ioctlIOWR(trustIXAEADIOCMagic, 23, unsafe.Sizeof(TrustIXDatapathIOCOuterBuild{})); got != want {
		t.Fatalf("datapath outer build ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathOuterParseIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCOuterParse{}), uintptr(136); got != want {
		t.Fatalf("TrustIXDatapathIOCOuterParse size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCOuterParseCmd(), ioctlIOWR(trustIXAEADIOCMagic, 24, unsafe.Sizeof(TrustIXDatapathIOCOuterParse{})); got != want {
		t.Fatalf("datapath outer parse ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathRXStageIOCABIMatchesKernelLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(TrustIXDatapathIOCRXStage{}), uintptr(192); got != want {
		t.Fatalf("TrustIXDatapathIOCRXStage size = %d, want %d", got, want)
	}
	if got, want := TrustIXDatapathIOCRXStageCmd(), ioctlIOWR(trustIXAEADIOCMagic, 25, unsafe.Sizeof(TrustIXDatapathIOCRXStage{})); got != want {
		t.Fatalf("datapath RX stage ioctl = %#x, want %#x", got, want)
	}
}

func TestDatapathQueryFeatureMasksUseModuleFeatureNames(t *testing.T) {
	query := TrustIXDatapathHelpersIOCQuery{
		Features:       trustIXKernelFeatureCryptoAEADBit | trustIXKernelFeatureDeviceAEADBit | trustIXKernelFeatureGSOSKBBit | trustIXKernelFeatureRouteTCPKfuncBit,
		SafeFeatures:   trustIXKernelFeatureCryptoAEADBit | trustIXKernelFeatureDeviceAEADBit | trustIXKernelFeatureGSOSKBBit,
		UnsafeFeatures: trustIXKernelFeatureRouteTCPXmitBit,
	}
	got := DatapathQuery{
		Features:       moduleFeatureMaskToNames(query.Features),
		SafeFeatures:   moduleFeatureMaskToNames(query.SafeFeatures),
		UnsafeFeatures: moduleFeatureMaskToNames(query.UnsafeFeatures),
	}
	if want := []string{FeatureCryptoAEAD, FeatureDeviceAEAD, FeatureGSOSKB, FeatureRouteTCPKfunc}; !reflect.DeepEqual(got.Features, want) {
		t.Fatalf("features = %#v, want %#v", got.Features, want)
	}
	if want := []string{FeatureCryptoAEAD, FeatureDeviceAEAD, FeatureGSOSKB}; !reflect.DeepEqual(got.SafeFeatures, want) {
		t.Fatalf("safe features = %#v, want %#v", got.SafeFeatures, want)
	}
	if want := []string{FeatureRouteTCPXmit}; !reflect.DeepEqual(got.UnsafeFeatures, want) {
		t.Fatalf("unsafe features = %#v, want %#v", got.UnsafeFeatures, want)
	}
}

func TestDatapathQuerySafeActiveFeatureRequiresSelftestAndActiveFlag(t *testing.T) {
	query := DatapathQuery{
		DatapathABIVersion: 1,
		Features:           []string{FeatureGSOSKB},
		SafeFeatures:       []string{FeatureGSOSKB},
		Flags:              TrustIXDatapathHelpersFlagTIXTSelftestOK | TrustIXDatapathHelpersFlagFeaturesActive,
		Selftests:          TrustIXDatapathHelpersSelftestAll,
	}
	if !query.SafeActiveFeature(FeatureGSOSKB) {
		t.Fatal("expected gso_skb to be active after selftest and active feature flags")
	}
	query.Flags &^= TrustIXDatapathHelpersFlagFeaturesActive
	if query.SafeActiveFeature(FeatureGSOSKB) {
		t.Fatal("feature reported active without active feature flag")
	}
	query.Flags |= TrustIXDatapathHelpersFlagFeaturesActive
	query.SelftestFailures = TrustIXDatapathHelpersSelftestTIXTStream
	if query.SafeActiveFeature(FeatureGSOSKB) {
		t.Fatal("feature reported active with selftest failure")
	}
}

func TestDatapathTIXTSelftestAllowsAdditionalFullDatapathSelftests(t *testing.T) {
	query := DatapathQuery{
		DatapathABIVersion: 1,
		Flags:              TrustIXDatapathHelpersFlagTIXTSelftestOK,
		Selftests:          TrustIXDatapathSelftestAll,
	}
	if !query.TIXTSelftestOK() {
		t.Fatal("TIXT selftest should pass when full datapath reports additional state-table selftest")
	}
	query.SelftestFailures = TrustIXDatapathSelftestStateTable
	if !query.TIXTSelftestOK() {
		t.Fatal("TIXT selftest should not fail just because a non-TIXT selftest failed")
	}
	query.SelftestFailures = TrustIXDatapathHelpersSelftestTIXTFrame
	if query.TIXTSelftestOK() {
		t.Fatal("TIXT selftest should fail when a TIXT selftest bit failed")
	}
}
