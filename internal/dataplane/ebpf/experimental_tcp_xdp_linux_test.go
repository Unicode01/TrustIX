//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"

	cebpf "github.com/cilium/ebpf"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport/experimentaltcp"
	"trustix.local/trustix/internal/transport/kerneludp"
)

func TestExperimentalTCPKernelCryptoXDPObjectLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto XDP object load requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			if _, ok := cause.(fmt.Formatter); ok {
				t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", cause)
			}
		}
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
}

func TestExperimentalTCPKernelCryptoXDPOpensFrameAndRejectsReplay(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto XDP program run requires root")
	}
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "1")
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9201
		sequence        = 1
		destinationPort = 9443
		xdpDrop         = 1
	)
	spec := validKernelCryptoSpec(flowID)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install kernel crypto contexts: %v", err)
	}

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen | experimentalTCPConfigHotPathStats
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable XDP TIXT kernel open: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}

	plaintext := []byte("trustix attached xdp kernel open")
	sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence, plaintext)
	if err != nil {
		t.Fatalf("seal frame: %v", err)
	}
	packet := mustExperimentalTCPXDPEthernetFrame(t, experimentaltcp.Frame{
		Flags:    experimentaltcp.FlagEncrypted,
		FlowID:   flowID,
		Epoch:    spec.Epoch,
		Sequence: sequence,
		Payload:  sealed,
	}, destinationPort)

	first := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(first)
	if err != nil {
		t.Fatalf("run XDP open: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP open return = %d, want redirect fallback/drop", ret)
	}
	openedPacket, err := experimentaltcp.ParseTCPShapedIPv4(first.DataOut[14:])
	if err != nil {
		got, want := tcpChecksumForTest(first.DataOut[14:])
		t.Fatalf("parse opened TCP-shaped packet: %v (tcp checksum got=%#04x want=%#04x)", err, got, want)
	}
	openedFrame, err := experimentaltcp.ParseFrame(openedPacket.Payload)
	if err != nil {
		t.Fatalf("parse opened TIXT frame: %v", err)
	}
	if openedFrame.Flags&experimentaltcp.FlagEncrypted != 0 || openedFrame.Flags&experimentaltcp.FlagKernelOpened == 0 {
		t.Fatalf("opened frame flags = %#x, want kernel-opened plaintext", openedFrame.Flags)
	}
	if !bytes.Equal(openedFrame.Payload, plaintext) {
		t.Fatalf("opened payload = %q, want %q", openedFrame.Payload, plaintext)
	}

	replay := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err = object.program.Run(replay)
	if err != nil {
		t.Fatalf("run XDP replay: %v", err)
	}
	if ret != xdpDrop {
		t.Fatalf("XDP replay return = %d, want XDP_DROP", ret)
	}
	assertXDPStat(t, object, 4, 2)
	assertXDPStat(t, object, 5, 1)
	assertXDPStat(t, object, 6, 0)
	assertXDPStat(t, object, 7, 1)
}

func TestExperimentalTCPKernelCryptoXDPDirectOpenObjectOpensFrame(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto XDP direct-open program run requires root")
	}
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "1")
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}
	if !manager.kernelCryptoTCDirectReadyLocked() {
		t.Skipf("kernel crypto direct provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 92011
		sequence        = 7
		destinationPort = 9447
	)
	spec := validKernelCryptoSpec(flowID)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install kernel crypto contexts: %v", err)
	}

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_direct_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP direct-open object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen | experimentalTCPConfigHotPathStats
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable XDP TIXT kernel direct open: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}

	plaintext := []byte("trustix attached xdp direct open")
	sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence, plaintext)
	if err != nil {
		t.Fatalf("seal frame: %v", err)
	}
	packet := mustExperimentalTCPXDPEthernetFrame(t, experimentaltcp.Frame{
		Flags:    experimentaltcp.FlagEncrypted,
		FlowID:   flowID,
		Epoch:    spec.Epoch,
		Sequence: sequence,
		Payload:  sealed,
	}, destinationPort)

	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP direct open: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP direct open return = %d, want redirect fallback/drop", ret)
	}
	openedPacket, err := experimentaltcp.ParseTCPShapedIPv4(run.DataOut[14:])
	if err != nil {
		got, want := tcpChecksumForTest(run.DataOut[14:])
		t.Fatalf("parse direct-opened TCP-shaped packet: %v (tcp checksum got=%#04x want=%#04x)", err, got, want)
	}
	openedFrame, err := experimentaltcp.ParseFrame(openedPacket.Payload)
	if err != nil {
		t.Fatalf("parse direct-opened TIXT frame: %v", err)
	}
	if openedFrame.Flags&experimentaltcp.FlagEncrypted != 0 || openedFrame.Flags&experimentaltcp.FlagKernelOpened == 0 {
		t.Fatalf("direct-opened frame flags = %#x, want kernel-opened plaintext", openedFrame.Flags)
	}
	if !bytes.Equal(openedFrame.Payload, plaintext) {
		t.Fatalf("direct-opened payload = %q, want %q", openedFrame.Payload, plaintext)
	}
	assertXDPStat(t, object, 4, 1)
	assertXDPStat(t, object, 5, 1)
	assertXDPStat(t, object, 31, 1)
	assertXDPStat(t, object, 33, 0)
}

func TestExperimentalTCPKernelCryptoXDPRedirectsEncryptedTIXTByDefault(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto XDP program run requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9206
		sequence        = 12
		destinationPort = 9456
	)
	spec := validKernelCryptoSpec(flowID)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install kernel crypto contexts: %v", err)
	}

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValue(object.configMap, 1, false); err != nil {
		t.Fatalf("configure XDP kernel open off: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}

	plaintext := []byte("trustix encrypted tixt redirect")
	sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence, plaintext)
	if err != nil {
		t.Fatalf("seal frame: %v", err)
	}
	packet := mustExperimentalTCPXDPEthernetFrame(t, experimentaltcp.Frame{
		Flags:    experimentaltcp.FlagEncrypted,
		FlowID:   flowID,
		Epoch:    spec.Epoch,
		Sequence: sequence,
		Payload:  sealed,
	}, destinationPort)

	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run encrypted TIXT redirect: %v", err)
	}
	if ret == 0 {
		t.Fatalf("encrypted TIXT redirect return = %d, want redirect fallback/drop", ret)
	}
	tcpPacket, err := experimentaltcp.ParseTCPShapedIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse redirected TCP-shaped packet: %v", err)
	}
	frame, err := experimentaltcp.ParseFrame(tcpPacket.Payload)
	if err != nil {
		t.Fatalf("parse redirected TIXT frame: %v", err)
	}
	if frame.Flags&experimentaltcp.FlagEncrypted == 0 || frame.Flags&experimentaltcp.FlagKernelOpened != 0 {
		t.Fatalf("redirected encrypted frame flags = %#x", frame.Flags)
	}
	if !bytes.Equal(frame.Payload, sealed) {
		t.Fatalf("redirected encrypted payload was modified")
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 4, 0)
	assertXDPStat(t, object, 5, 0)
}

func TestExperimentalTCPKernelCryptoXDPDefersNoContextToUserspace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto XDP program run requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9301
		epoch           = 99
		sequence        = 7
		destinationPort = 9445
		xdpDrop         = 1
	)
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable XDP TIXT kernel open: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}

	securePayload := make([]byte, kernelCryptoSecureHeaderLen+kernelCryptoFrameTagLen)
	kernelCryptoPutSecureHeader(securePayload[:kernelCryptoSecureHeaderLen], byte(kernelCryptoSuiteIDTrustIXAES256GCMX25519), epoch, sequence)
	packet := mustExperimentalTCPXDPEthernetFrame(t, experimentaltcp.Frame{
		Flags:    experimentaltcp.FlagEncrypted,
		FlowID:   flowID,
		Epoch:    epoch,
		Sequence: sequence,
		Payload:  securePayload,
	}, destinationPort)

	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP no-context deferral: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP no-context return = %d, want redirect fallback/drop", ret)
	}
	if !bytes.Equal(run.DataOut[:len(packet)], packet) {
		t.Fatalf("no-context deferred packet was unexpectedly modified")
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 4, 1)
	assertXDPStat(t, object, 6, 0)
	assertXDPStat(t, object, 8, 0)
	assertXDPStat(t, object, 10, 1)
}

func TestExperimentalTCPKernelCryptoXDPRedirectsKernelUDP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP program run requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const destinationPort = 9443
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable attached XDP TIXT kernel open: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}

	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		FlowID:   991,
		Sequence: 2,
		Payload:  []byte("udp fast path"),
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP redirect: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP redirect return = %d, want redirect fallback/drop", ret)
	}
	udpPacket, err := kerneludp.ParseUDPIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse redirected UDP packet: %v", err)
	}
	frame, err := kerneludp.ParseFrame(udpPacket.Payload)
	if err != nil {
		t.Fatalf("parse redirected TIXU frame: %v", err)
	}
	if frame.FlowID != 991 || frame.Sequence != 2 || !bytes.Equal(frame.Payload, []byte("udp fast path")) {
		t.Fatalf("redirected frame = %#v, want flow 991 sequence 2", frame)
	}
	assertXDPStat(t, object, 0, 1)
}

func TestExperimentalTCPXDPAllowsKernelUDPSourcePort(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP program run requires root")
	}
	const (
		sourcePort      = 9443
		destinationPort = 43000
	)
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(sourcePort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow source port in XDP map: %v", err)
	}

	packet := mustKernelUDPXDPEthernetFramePorts(t, kerneludp.Frame{
		FlowID:   991,
		Sequence: 2,
		Payload:  []byte("udp reverse source-port path"),
	}, sourcePort, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP source-port redirect: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP source-port return = %d, want redirect fallback/drop", ret)
	}
	if !bytes.Equal(run.DataOut[:len(packet)], packet) {
		t.Fatalf("source-port allowed packet was unexpectedly modified")
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 1, 0)
}

func TestExperimentalTCPXDPPassesAllowedTCPControlPacket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp XDP program run requires root")
	}
	const destinationPort = 9443
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	packet, err := experimentaltcp.MarshalTCPShapedIPv4(experimentaltcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: destinationPort,
		Sequence:        1234,
		Acknowledgment:  1,
	})
	if err != nil {
		t.Fatalf("marshal TCP control packet: %v", err)
	}
	ethernet := mustEthernetIPv4ForXDPTest(packet)
	run := &cebpf.RunOptions{Data: append([]byte(nil), ethernet...), DataOut: make([]byte, len(ethernet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP TCP control pass: %v", err)
	}
	if ret != 2 {
		t.Fatalf("XDP TCP control return = %d, want XDP_PASS", ret)
	}
	assertXDPStat(t, object, 0, 0)
	assertXDPStat(t, object, 1, 0)
}

func TestExperimentalTCPKernelCryptoXDPPassesAllowedTCPControlPacket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto XDP program run requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}
	const destinationPort = 9443
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	packet, err := experimentaltcp.MarshalTCPShapedIPv4(experimentaltcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: destinationPort,
		Sequence:        1234,
		Acknowledgment:  1,
	})
	if err != nil {
		t.Fatalf("marshal TCP control packet: %v", err)
	}
	ethernet := mustEthernetIPv4ForXDPTest(packet)
	run := &cebpf.RunOptions{Data: append([]byte(nil), ethernet...), DataOut: make([]byte, len(ethernet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run kernel crypto XDP TCP control pass: %v", err)
	}
	if ret != 2 {
		t.Fatalf("kernel crypto XDP TCP control return = %d, want XDP_PASS", ret)
	}
	assertXDPStat(t, object, 0, 0)
	assertXDPStat(t, object, 1, 0)
}

func TestExperimentalTCPXDPDirectsPlainKernelUDPToLAN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP RX direct program run requires root")
	}
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "1")
	const destinationPort = 9443
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_neigh_xdp_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_devmap_xdp_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_config_xdp_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValueFor(object.configMap, 1, true, true, false); err != nil {
		t.Fatalf("enable XDP UDP RX direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	neighborKey := binary.LittleEndian.Uint32([]byte{10, 0, 1, 2})
	neighbor := kernelUDPRXNeighValue{
		Ifindex:         1,
		DestinationMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x10, 0x11, 0x12}),
		DestinationMAC1: binary.LittleEndian.Uint16([]byte{0x13, 0x14}),
		SourceMAC0:      binary.LittleEndian.Uint32([]byte{0x02, 0x20, 0x21, 0x22}),
		SourceMAC1:      binary.LittleEndian.Uint16([]byte{0x23, 0x24}),
	}
	if err := neighMap.Update(neighborKey, neighbor, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP RX direct neighbor: %v", err)
	}
	devKey := uint32(0)
	devIfindex := uint32(1)
	if err := devMap.Update(devKey, devIfindex, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP RX direct devmap: %v", err)
	}
	config := kernelUDPRXConfigValue{
		SourceMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x20, 0x21, 0x22}),
		SourceMAC1: binary.LittleEndian.Uint16([]byte{0x23, 0x24}),
		Ifindex:    1,
	}
	if err := configMap.Update(devKey, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP RX direct config: %v", err)
	}

	inner := ipv4PacketForXDPTCRXDirectTest()
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagInnerIPv4,
		FlowID:   991,
		Sequence: 2,
		Payload:  inner,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP RX direct: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP RX direct return = %d, want redirect/drop from devmap helper", ret)
	}
	if len(run.DataOut) != len(packet)-kernelUDPTXOuterOverhead {
		t.Fatalf("XDP UDP RX direct data out len = %d, want %d", len(run.DataOut), len(packet)-kernelUDPTXOuterOverhead)
	}
	if !bytes.Equal(run.DataOut[:14], []byte{0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x02, 0x20, 0x21, 0x22, 0x23, 0x24, 0x08, 0x00}) {
		t.Fatalf("XDP UDP RX direct ethernet header = %x", run.DataOut[:14])
	}
	if !bytes.Equal(run.DataOut[14:], inner) {
		t.Fatalf("XDP UDP RX direct inner packet mismatch")
	}

	missInner := append([]byte(nil), inner...)
	copy(missInner[16:20], []byte{10, 0, 1, 99})
	missPacket := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagInnerIPv4,
		FlowID:   992,
		Sequence: 3,
		Payload:  missInner,
	}, destinationPort)
	missRun := &cebpf.RunOptions{Data: append([]byte(nil), missPacket...), DataOut: make([]byte, len(missPacket))}
	ret, err = object.program.Run(missRun)
	if err != nil {
		t.Fatalf("run XDP UDP RX direct neighbor-miss fallback: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP RX direct neighbor-miss return = %d, want AF_XDP redirect/drop", ret)
	}
	if len(missRun.DataOut) != len(missPacket) {
		t.Fatalf("XDP UDP RX direct neighbor-miss data out len = %d, want unchanged %d", len(missRun.DataOut), len(missPacket))
	}
	if !bytes.Equal(missRun.DataOut, missPacket) {
		t.Fatalf("XDP UDP RX direct neighbor-miss packet was unexpectedly rewritten")
	}
	assertXDPStat(t, object, 18, 1)
	assertXDPStat(t, object, 21, 2)
	assertXDPStat(t, object, 22, 1)
	assertXDPStat(t, object, 23, 0)
}

func TestExperimentalTCPXDPDirectsPlainKernelUDPWithFixedL2(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP RX direct fixed L2 program run requires root")
	}
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2", "1")
	const destinationPort = 9452
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_neigh_xdp_fixed_l2_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_devmap_xdp_fixed_l2_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_config_xdp_fixed_l2_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValueFor(object.configMap, 1, true, true, false); err != nil {
		t.Fatalf("enable XDP UDP RX fixed L2 direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	devKey := uint32(0)
	devIfindex := uint32(1)
	if err := devMap.Update(devKey, devIfindex, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP RX direct devmap: %v", err)
	}
	config := kernelUDPRXConfigValue{
		SourceMAC0:      binary.LittleEndian.Uint32([]byte{0x02, 0x90, 0x91, 0x92}),
		SourceMAC1:      binary.LittleEndian.Uint16([]byte{0x93, 0x94}),
		Ifindex:         1,
		DestinationMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0xa0, 0xa1, 0xa2}),
		DestinationMAC1: binary.LittleEndian.Uint16([]byte{0xa3, 0xa4}),
	}
	if err := configMap.Update(devKey, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP RX direct fixed L2 config: %v", err)
	}

	inner := ipv4PacketForXDPTCRXDirectTest()
	missInner := append([]byte(nil), inner...)
	copy(missInner[16:20], []byte{10, 0, 1, 99})
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagInnerIPv4,
		FlowID:   997,
		Sequence: 8,
		Payload:  missInner,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP RX direct fixed L2: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP RX direct fixed L2 return = %d, want redirect/drop from helper", ret)
	}
	if len(run.DataOut) != len(packet)-kernelUDPTXOuterOverhead {
		t.Fatalf("XDP UDP RX direct fixed L2 data out len = %d, want %d", len(run.DataOut), len(packet)-kernelUDPTXOuterOverhead)
	}
	if !bytes.Equal(run.DataOut[:14], []byte{0x02, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0x02, 0x90, 0x91, 0x92, 0x93, 0x94, 0x08, 0x00}) {
		t.Fatalf("XDP UDP RX direct fixed L2 ethernet header = %x", run.DataOut[:14])
	}
	if !bytes.Equal(run.DataOut[14:], missInner) {
		t.Fatalf("XDP UDP RX direct fixed L2 inner packet mismatch")
	}
	assertXDPStat(t, object, 18, 1)
	assertXDPStat(t, object, 19, 0)
	assertXDPStat(t, object, 21, 1)
	assertXDPStat(t, object, 22, 0)
	assertXDPStat(t, object, 23, 1)
	assertXDPStat(t, object, 30, 0)
}

func TestExperimentalTCPXDPDoesNotDirectPlainKernelUDPWithoutInnerIPv4Flag(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP RX direct program run requires root")
	}
	const destinationPort = 9448
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_neigh_xdp_noflag_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_devmap_xdp_noflag_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_config_xdp_noflag_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValueFor(object.configMap, 1, true, true, false); err != nil {
		t.Fatalf("enable XDP UDP RX direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	inner := ipv4PacketForXDPTCRXDirectTest()
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		FlowID:   993,
		Sequence: 4,
		Payload:  inner,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP RX direct without inner flag: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP no-flag return = %d, want AF_XDP redirect/drop", ret)
	}
	if len(run.DataOut) != len(packet) {
		t.Fatalf("XDP UDP no-flag data out len = %d, want unchanged %d", len(run.DataOut), len(packet))
	}
	udpPacket, err := kerneludp.ParseUDPIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse redirected UDP packet: %v", err)
	}
	frame, err := kerneludp.ParseFrame(udpPacket.Payload)
	if err != nil {
		t.Fatalf("parse redirected TIXU frame: %v", err)
	}
	if frame.Flags != 0 || !bytes.Equal(frame.Payload, inner) {
		t.Fatalf("redirected no-flag frame = %#v", frame)
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 18, 0)
}

func TestExperimentalTCPXDPDirectIfindexModeCountsRedirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP RX direct ifindex program run requires root")
	}
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX", "1")
	const destinationPort = 9451
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_neigh_xdp_ifindex_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_devmap_xdp_ifindex_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_config_xdp_ifindex_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValueFor(object.configMap, 1, true, true, false); err != nil {
		t.Fatalf("enable XDP UDP RX direct ifindex: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	neighborKey := binary.LittleEndian.Uint32([]byte{10, 0, 1, 2})
	neighbor := kernelUDPRXNeighValue{
		Ifindex:         1,
		DestinationMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x50, 0x51, 0x52}),
		DestinationMAC1: binary.LittleEndian.Uint16([]byte{0x53, 0x54}),
		SourceMAC0:      binary.LittleEndian.Uint32([]byte{0x02, 0x60, 0x61, 0x62}),
		SourceMAC1:      binary.LittleEndian.Uint16([]byte{0x63, 0x64}),
	}
	if err := neighMap.Update(neighborKey, neighbor, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP RX direct ifindex neighbor: %v", err)
	}

	inner := ipv4PacketForXDPTCRXDirectTest()
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagInnerIPv4,
		FlowID:   996,
		Sequence: 7,
		Payload:  inner,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP RX direct ifindex: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP RX direct ifindex return = %d, want redirect/drop from helper", ret)
	}
	if len(run.DataOut) != len(packet)-kernelUDPTXOuterOverhead {
		t.Fatalf("XDP UDP RX direct ifindex data out len = %d, want %d", len(run.DataOut), len(packet)-kernelUDPTXOuterOverhead)
	}
	if !bytes.Equal(run.DataOut[:14], []byte{0x02, 0x50, 0x51, 0x52, 0x53, 0x54, 0x02, 0x60, 0x61, 0x62, 0x63, 0x64, 0x08, 0x00}) {
		t.Fatalf("XDP UDP RX direct ifindex ethernet header = %x", run.DataOut[:14])
	}
	assertXDPStat(t, object, 21, 1)
	assertXDPStat(t, object, 22, 1)
	assertXDPStat(t, object, 28, 1)
	assertXDPStat(t, object, 29, 0)
}

func TestExperimentalTCPXDPDirectsPlainTIXTToLAN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp XDP RX direct program run requires root")
	}
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "1")
	const destinationPort = 9449
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_rx_neigh_xdp_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_rx_devmap_xdp_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_rx_config_xdp_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValueFor(object.configMap, 1, true, true, false); err != nil {
		t.Fatalf("enable XDP TIXT RX direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	neighborKey := binary.LittleEndian.Uint32([]byte{10, 0, 1, 2})
	neighbor := kernelUDPRXNeighValue{
		Ifindex:         1,
		DestinationMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x30, 0x31, 0x32}),
		DestinationMAC1: binary.LittleEndian.Uint16([]byte{0x33, 0x34}),
		SourceMAC0:      binary.LittleEndian.Uint32([]byte{0x02, 0x40, 0x41, 0x42}),
		SourceMAC1:      binary.LittleEndian.Uint16([]byte{0x43, 0x44}),
	}
	if err := neighMap.Update(neighborKey, neighbor, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP TIXT RX direct neighbor: %v", err)
	}
	devKey := uint32(0)
	devIfindex := uint32(1)
	if err := devMap.Update(devKey, devIfindex, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP TIXT RX direct devmap: %v", err)
	}
	config := kernelUDPRXConfigValue{
		SourceMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x40, 0x41, 0x42}),
		SourceMAC1: binary.LittleEndian.Uint16([]byte{0x43, 0x44}),
		Ifindex:    1,
	}
	if err := configMap.Update(devKey, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed XDP TIXT RX direct config: %v", err)
	}

	inner := ipv4PacketForXDPTCRXDirectTest()
	packet := mustExperimentalTCPXDPEthernetFrame(t, experimentaltcp.Frame{
		Flags:    experimentaltcp.FlagInnerIPv4,
		FlowID:   994,
		Sequence: 5,
		Payload:  inner,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP TIXT RX direct: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP TIXT RX direct return = %d, want redirect/drop from devmap helper", ret)
	}
	if len(run.DataOut) != len(packet)-80 {
		t.Fatalf("XDP TIXT RX direct data out len = %d, want %d", len(run.DataOut), len(packet)-80)
	}
	if !bytes.Equal(run.DataOut[:14], []byte{0x02, 0x30, 0x31, 0x32, 0x33, 0x34, 0x02, 0x40, 0x41, 0x42, 0x43, 0x44, 0x08, 0x00}) {
		t.Fatalf("XDP TIXT RX direct ethernet header = %x", run.DataOut[:14])
	}
	if !bytes.Equal(run.DataOut[14:], inner) {
		t.Fatalf("XDP TIXT RX direct inner packet mismatch")
	}
	assertXDPStat(t, object, 18, 1)
	assertXDPStat(t, object, 21, 1)
	assertXDPStat(t, object, 22, 1)
}

func TestExperimentalTCPXDPPassesPlainTIXTStreamToTCRXDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp XDP stream TC handoff requires root")
	}
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "1")
	const (
		destinationPort = 9459
		xdpPass         = 2
	)
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValueFor(object.configMap, 1, true, true, false); err != nil {
		t.Fatalf("enable XDP and TC RX direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	first := ipv4PacketForXDPTCRXDirectTest()
	second := append([]byte(nil), first...)
	copy(second[16:20], []byte{10, 0, 1, 3})
	packet := mustExperimentalTCPXDPStreamEthernetFrame(t, []experimentaltcp.Frame{
		{Flags: experimentaltcp.FlagInnerIPv4, FlowID: 996, Sequence: 1, Payload: first},
		{Flags: experimentaltcp.FlagInnerIPv4, FlowID: 996, Sequence: 2, Payload: second},
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP TIXT stream TC handoff: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("XDP TIXT stream return = %d, want XDP_PASS", ret)
	}
	if !bytes.Equal(run.DataOut, packet) {
		t.Fatalf("XDP TIXT stream packet was unexpectedly modified")
	}
	assertXDPStat(t, object, 0, 0)
	assertXDPStat(t, object, 14, 1)
	assertXDPStat(t, object, 15, 1)
	assertXDPStat(t, object, 16, 0)
	assertXDPStat(t, object, 18, 0)
}

func TestExperimentalTCPXDPDoesNotDirectPlainTIXTWithoutInnerIPv4Flag(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp XDP RX direct program run requires root")
	}
	const destinationPort = 9450
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_rx_neigh_xdp_noflag_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_rx_devmap_xdp_noflag_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_rx_config_xdp_noflag_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()

	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValueFor(object.configMap, 1, true, true, false); err != nil {
		t.Fatalf("enable XDP TIXT RX direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	inner := ipv4PacketForXDPTCRXDirectTest()
	packet := mustExperimentalTCPXDPEthernetFrame(t, experimentaltcp.Frame{
		FlowID:   995,
		Sequence: 6,
		Payload:  inner,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP TIXT RX direct without inner flag: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP TIXT no-flag return = %d, want AF_XDP redirect/drop", ret)
	}
	if len(run.DataOut) != len(packet) {
		t.Fatalf("XDP TIXT no-flag data out len = %d, want unchanged %d", len(run.DataOut), len(packet))
	}
	tcpPacket, err := experimentaltcp.ParseTCPShapedIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse redirected TCP-shaped packet: %v", err)
	}
	frame, err := experimentaltcp.ParseFrame(tcpPacket.Payload)
	if err != nil {
		t.Fatalf("parse redirected TIXT frame: %v", err)
	}
	if frame.Flags != 0 || !bytes.Equal(frame.Payload, inner) {
		t.Fatalf("redirected no-flag frame = %#v", frame)
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 18, 0)
}

func TestExperimentalTCPKernelCryptoXDPRedirectsEncryptedKernelUDPByDefault(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP program run requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const destinationPort = 9443
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValue(object.configMap, 1, false); err != nil {
		t.Fatalf("configure XDP UDP open off: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagEncrypted,
		FlowID:   991,
		Sequence: 2,
		Payload:  bytesOf(0xee, kernelCryptoSecureHeaderLen+kernelCryptoFrameTagLen),
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP encrypted UDP redirect: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP encrypted UDP redirect return = %d, want redirect fallback/drop", ret)
	}
	udpPacket, err := kerneludp.ParseUDPIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse redirected UDP packet: %v", err)
	}
	frame, err := kerneludp.ParseFrame(udpPacket.Payload)
	if err != nil {
		t.Fatalf("parse redirected encrypted TIXU frame: %v", err)
	}
	if frame.Flags&kerneludp.FlagEncrypted == 0 || frame.Flags&kerneludp.FlagKernelOpened != 0 {
		t.Fatalf("redirected encrypted frame flags = %#x", frame.Flags)
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 4, 0)
}

func TestExperimentalTCPKernelCryptoXDPEncryptedKernelUDPPassesToTCSecureDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp encrypted XDP to TC secure direct handoff requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		destinationPort = 9448
		xdpPass         = 2
	)
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPTCRXSecureDirect | experimentalTCPConfigKernelUDPXDPRXDirect | experimentalTCPConfigHotPathStats
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable XDP UDP TC secure direct handoff: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagEncrypted | kerneludp.FlagInnerIPv4,
		FlowID:   992,
		Sequence: 3,
		Payload:  bytesOf(0xee, kernelCryptoSecureHeaderLen+kernelCryptoFrameTagLen+20),
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP encrypted UDP TC secure direct handoff: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("XDP encrypted UDP TC secure direct handoff return = %d, want XDP_PASS", ret)
	}
	udpPacket, err := kerneludp.ParseUDPIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse passed UDP packet: %v", err)
	}
	frame, err := kerneludp.ParseFrame(udpPacket.Payload)
	if err != nil {
		t.Fatalf("parse passed encrypted TIXU frame: %v", err)
	}
	if frame.Flags&(kerneludp.FlagEncrypted|kerneludp.FlagInnerIPv4) != kerneludp.FlagEncrypted|kerneludp.FlagInnerIPv4 {
		t.Fatalf("passed encrypted frame flags = %#x", frame.Flags)
	}
	assertXDPStat(t, object, 0, 0)
	assertXDPStat(t, object, 2, 1)
	assertXDPStat(t, object, 14, 1)
}

func TestExperimentalTCPKernelCryptoXDPOpensKernelUDP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP kernel-open program run requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9911
		epoch           = 17
		sequence        = 9
		destinationPort = 9446
	)
	spec := validKernelCryptoSpec(flowID)
	spec.Epoch = epoch
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	udpSpec := dataplane.KernelUDPCryptoSpec{
		FlowID:       spec.FlowID,
		Suite:        spec.Suite,
		WireFormat:   spec.WireFormat,
		Epoch:        spec.Epoch,
		SendKey:      spec.SendKey,
		SendIV:       spec.SendIV,
		RecvKey:      spec.RecvKey,
		RecvIV:       spec.RecvIV,
		ReplayWindow: spec.ReplayWindow,
	}
	if err := manager.InstallKernelUDPCrypto(context.Background(), []dataplane.KernelUDPCryptoSpec{udpSpec}); err != nil {
		t.Fatalf("install kernel_udp crypto contexts: %v", err)
	}
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable XDP UDP kernel open: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	suiteID, err := kernelCryptoSuiteID(spec.Suite)
	if err != nil {
		t.Fatalf("suite id: %v", err)
	}
	plain := []byte("kernel udp opened in xdp")
	sealed, err := manager.kernelCryptoProvider.SealFrame(
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, flowID, kernelCryptoDirectionSend),
		suiteID,
		epoch,
		sequence,
		plain,
	)
	if err != nil {
		t.Fatalf("seal kernel_udp payload for XDP: %v", err)
	}
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagEncrypted | kerneludp.FlagInnerIPv4,
		FlowID:   flowID,
		Sequence: sequence,
		Payload:  sealed,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP kernel open: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP kernel open return = %d, want redirect fallback/drop", ret)
	}
	udpPacket, err := kerneludp.ParseUDPIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse opened UDP packet: %v", err)
	}
	frame, err := kerneludp.ParseFrame(udpPacket.Payload)
	if err != nil {
		t.Fatalf("parse opened TIXU frame: %v", err)
	}
	if frame.Flags&kerneludp.FlagKernelOpened == 0 || frame.Flags&kerneludp.FlagEncrypted != 0 {
		t.Fatalf("opened frame flags = %#x", frame.Flags)
	}
	if frame.FlowID != flowID || frame.Sequence != sequence || !bytes.Equal(frame.Payload, plain) {
		t.Fatalf("opened frame = %#v, want flow %d sequence %d payload %q", frame, flowID, sequence, plain)
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 4, 1)
	assertXDPStat(t, object, 5, 1)
}

func TestExperimentalTCPKernelCryptoXDPPlainKernelUDPDoesNotPassToTCRXDirectWithoutConfig(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP plaintext TC direct handoff requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const destinationPort = 9452
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	if _, err := configureExperimentalTCPBPFConfigValueFor(object.configMap, 1, false, false, false); err != nil {
		t.Fatalf("disable TC RX direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	inner := ipv4PacketForXDPTCRXDirectTest()
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagInnerIPv4,
		FlowID:   9914,
		Sequence: 12,
		Payload:  inner,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP plaintext without TC direct: %v", err)
	}
	if ret == 2 {
		t.Fatalf("XDP UDP plaintext returned XDP_PASS without TC RX direct config")
	}
	if len(run.DataOut) != len(packet) {
		t.Fatalf("XDP UDP plaintext data out len = %d, want unchanged %d", len(run.DataOut), len(packet))
	}
	udpPacket, err := kerneludp.ParseUDPIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse redirected UDP packet: %v", err)
	}
	frame, err := kerneludp.ParseFrame(udpPacket.Payload)
	if err != nil {
		t.Fatalf("parse redirected TIXU frame: %v", err)
	}
	if frame.Flags != kerneludp.FlagInnerIPv4 || !bytes.Equal(frame.Payload, inner) {
		t.Fatalf("redirected plaintext frame flags=%#x payload_len=%d", frame.Flags, len(frame.Payload))
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 14, 0)
}

func TestExperimentalTCPKernelCryptoXDPOpensKernelUDPAndPassesToTCRXDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP kernel-open TC direct handoff requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9912
		epoch           = 18
		sequence        = 10
		destinationPort = 9447
		xdpPass         = 2
	)
	spec := validKernelCryptoSpec(flowID)
	spec.Epoch = epoch
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	udpSpec := dataplane.KernelUDPCryptoSpec{
		FlowID:       spec.FlowID,
		Suite:        spec.Suite,
		WireFormat:   spec.WireFormat,
		Epoch:        spec.Epoch,
		SendKey:      spec.SendKey,
		SendIV:       spec.SendIV,
		RecvKey:      spec.RecvKey,
		RecvIV:       spec.RecvIV,
		ReplayWindow: spec.ReplayWindow,
	}
	if err := manager.InstallKernelUDPCrypto(context.Background(), []dataplane.KernelUDPCryptoSpec{udpSpec}); err != nil {
		t.Fatalf("install kernel_udp crypto contexts: %v", err)
	}
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen | experimentalTCPConfigKernelUDPXDPPassOpened
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable XDP UDP kernel open TC direct handoff: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	suiteID, err := kernelCryptoSuiteID(spec.Suite)
	if err != nil {
		t.Fatalf("suite id: %v", err)
	}
	plain := ipv4PacketForXDPTCRXDirectTest()
	sealed, err := manager.kernelCryptoProvider.SealFrame(
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, flowID, kernelCryptoDirectionSend),
		suiteID,
		epoch,
		sequence,
		plain,
	)
	if err != nil {
		t.Fatalf("seal kernel_udp payload for XDP: %v", err)
	}
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagEncrypted,
		FlowID:   flowID,
		Sequence: sequence,
		Payload:  sealed,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP kernel open TC direct handoff: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("XDP UDP kernel open TC direct handoff return = %d, want XDP_PASS", ret)
	}
	udpPacket, err := kerneludp.ParseUDPIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse opened UDP packet: %v", err)
	}
	frame, err := kerneludp.ParseFrame(udpPacket.Payload)
	if err != nil {
		t.Fatalf("parse opened TIXU frame: %v", err)
	}
	if frame.Flags&kerneludp.FlagKernelOpened == 0 || frame.Flags&kerneludp.FlagEncrypted != 0 {
		t.Fatalf("opened frame flags = %#x", frame.Flags)
	}
	if frame.Flags&kerneludp.FlagInnerIPv4 == 0 {
		t.Fatalf("opened frame flags = %#x, want inner IPv4 direct flag preserved", frame.Flags)
	}
	if frame.FlowID != flowID || frame.Sequence != sequence || !bytes.Equal(frame.Payload, plain) {
		t.Fatalf("opened frame = %#v, want flow %d sequence %d payload len %d", frame, flowID, sequence, len(plain))
	}
	assertXDPStat(t, object, 0, 0)
	assertXDPStat(t, object, 2, 1)
	assertXDPStat(t, object, 4, 1)
	assertXDPStat(t, object, 5, 1)
	assertXDPStat(t, object, 14, 1)
}

func TestExperimentalTCPKernelCryptoXDPEncryptedKernelUDPSecureXDPDirectOptIn(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp encrypted XDP secure direct opt-in requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9916
		epoch           = 19
		sequence        = 11
		destinationPort = 9453
	)
	spec := validKernelCryptoSpec(flowID)
	spec.Epoch = epoch
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	udpSpec := dataplane.KernelUDPCryptoSpec{
		FlowID:       spec.FlowID,
		Suite:        spec.Suite,
		WireFormat:   spec.WireFormat,
		Epoch:        spec.Epoch,
		SendKey:      spec.SendKey,
		SendIV:       spec.SendIV,
		RecvKey:      spec.RecvKey,
		RecvIV:       spec.RecvIV,
		ReplayWindow: spec.ReplayWindow,
	}
	if err := manager.InstallKernelUDPCrypto(context.Background(), []dataplane.KernelUDPCryptoSpec{udpSpec}); err != nil {
		t.Fatalf("install kernel_udp crypto contexts: %v", err)
	}
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixu_secure_xdp_rx_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixu_secure_xdp_rx_devmap_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixu_secure_xdp_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelCryptoProvider: manager.kernelCryptoProvider,
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen |
		experimentalTCPConfigKernelUDPTCRXSecureDirect |
		experimentalTCPConfigKernelUDPXDPRXDirect |
		experimentalTCPConfigKernelUDPXDPRXSecureDirect |
		experimentalTCPConfigHotPathStats
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable encrypted TIXU secure XDP RX direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	neighborKey := binary.LittleEndian.Uint32([]byte{10, 0, 1, 2})
	neighbor := kernelUDPRXNeighValue{
		Ifindex:         1,
		DestinationMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x71, 0x72, 0x73}),
		DestinationMAC1: binary.LittleEndian.Uint16([]byte{0x74, 0x75}),
		SourceMAC0:      binary.LittleEndian.Uint32([]byte{0x02, 0x81, 0x82, 0x83}),
		SourceMAC1:      binary.LittleEndian.Uint16([]byte{0x84, 0x85}),
	}
	if err := neighMap.Update(neighborKey, neighbor, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXU secure XDP RX direct neighbor: %v", err)
	}
	devKey := uint32(0)
	devIfindex := uint32(1)
	if err := devMap.Update(devKey, devIfindex, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXU secure XDP RX direct devmap: %v", err)
	}
	rxConfig := kernelUDPRXConfigValue{
		SourceMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x81, 0x82, 0x83}),
		SourceMAC1: binary.LittleEndian.Uint16([]byte{0x84, 0x85}),
		Ifindex:    1,
	}
	if err := configMap.Update(devKey, rxConfig, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXU secure XDP RX direct config: %v", err)
	}
	suiteID, err := kernelCryptoSuiteID(spec.Suite)
	if err != nil {
		t.Fatalf("suite id: %v", err)
	}
	inner := ipv4PacketForXDPTCRXDirectTest()
	sealed, err := manager.kernelCryptoProvider.SealFrame(
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, flowID, kernelCryptoDirectionSend),
		suiteID,
		epoch,
		sequence,
		inner,
	)
	if err != nil {
		t.Fatalf("seal kernel_udp payload for secure XDP: %v", err)
	}
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagEncrypted | kerneludp.FlagInnerIPv4,
		FlowID:   flowID,
		Sequence: sequence,
		Payload:  sealed,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run encrypted TIXU secure XDP RX direct: %v", err)
	}
	if ret == 0 {
		t.Fatalf("encrypted TIXU secure XDP RX direct return = %d, want redirect/drop from devmap helper", ret)
	}
	if len(run.DataOut) != 14+len(inner) {
		t.Fatalf("encrypted TIXU secure XDP RX direct data out len = %d, want %d", len(run.DataOut), 14+len(inner))
	}
	if !bytes.Equal(run.DataOut[:14], []byte{0x02, 0x71, 0x72, 0x73, 0x74, 0x75, 0x02, 0x81, 0x82, 0x83, 0x84, 0x85, 0x08, 0x00}) {
		t.Fatalf("encrypted TIXU secure XDP RX direct ethernet header = %x", run.DataOut[:14])
	}
	if !bytes.Equal(run.DataOut[14:], inner) {
		t.Fatalf("encrypted TIXU secure XDP RX direct inner packet mismatch")
	}
	assertXDPStat(t, object, 0, 0)
	assertXDPStat(t, object, 2, 0)
	assertXDPStat(t, object, 4, 1)
	assertXDPStat(t, object, 5, 1)
	assertXDPStat(t, object, 18, 1)
	assertXDPStat(t, object, 21, 1)
	assertXDPStat(t, object, 22, 1)
}

func TestExperimentalTCPKernelCryptoXDPEncryptedKernelUDPSecureXDPDirectsControlPackets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp encrypted XDP secure direct control packet opt-in requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9917
		epoch           = 20
		sequence        = 12
		destinationPort = 9454
	)
	spec := validKernelCryptoSpec(flowID)
	spec.Epoch = epoch
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	udpSpec := dataplane.KernelUDPCryptoSpec{
		FlowID:       spec.FlowID,
		Suite:        spec.Suite,
		WireFormat:   spec.WireFormat,
		Epoch:        spec.Epoch,
		SendKey:      spec.SendKey,
		SendIV:       spec.SendIV,
		RecvKey:      spec.RecvKey,
		RecvIV:       spec.RecvIV,
		ReplayWindow: spec.ReplayWindow,
	}
	if err := manager.InstallKernelUDPCrypto(context.Background(), []dataplane.KernelUDPCryptoSpec{udpSpec}); err != nil {
		t.Fatalf("install kernel_udp crypto contexts: %v", err)
	}
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixu_secure_xdp_rx_control_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixu_secure_xdp_rx_control_devmap_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixu_secure_xdp_rx_control_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelCryptoProvider: manager.kernelCryptoProvider,
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen |
		experimentalTCPConfigKernelUDPTCRXSecureDirect |
		experimentalTCPConfigKernelUDPXDPRXDirect |
		experimentalTCPConfigKernelUDPXDPRXSecureDirect |
		experimentalTCPConfigHotPathStats
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable encrypted TIXU secure XDP RX direct control: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	neighborKey := binary.LittleEndian.Uint32([]byte{10, 0, 1, 2})
	neighbor := kernelUDPRXNeighValue{
		Ifindex:         1,
		DestinationMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x72, 0x73, 0x74}),
		DestinationMAC1: binary.LittleEndian.Uint16([]byte{0x75, 0x76}),
		SourceMAC0:      binary.LittleEndian.Uint32([]byte{0x02, 0x82, 0x83, 0x84}),
		SourceMAC1:      binary.LittleEndian.Uint16([]byte{0x85, 0x86}),
	}
	if err := neighMap.Update(neighborKey, neighbor, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXU secure XDP RX direct control neighbor: %v", err)
	}
	devKey := uint32(0)
	devIfindex := uint32(1)
	if err := devMap.Update(devKey, devIfindex, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXU secure XDP RX direct control devmap: %v", err)
	}
	rxConfig := kernelUDPRXConfigValue{
		SourceMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x82, 0x83, 0x84}),
		SourceMAC1: binary.LittleEndian.Uint16([]byte{0x85, 0x86}),
		Ifindex:    1,
	}
	if err := configMap.Update(devKey, rxConfig, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXU secure XDP RX direct control config: %v", err)
	}
	suiteID, err := kernelCryptoSuiteID(spec.Suite)
	if err != nil {
		t.Fatalf("suite id: %v", err)
	}
	inner := ipv4PacketForXDPTCRXDirectTest()
	inner[33] = 0x02
	sealed, err := manager.kernelCryptoProvider.SealFrame(
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, flowID, kernelCryptoDirectionSend),
		suiteID,
		epoch,
		sequence,
		inner,
	)
	if err != nil {
		t.Fatalf("seal kernel_udp control payload for secure XDP: %v", err)
	}
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagEncrypted | kerneludp.FlagInnerIPv4,
		FlowID:   flowID,
		Sequence: sequence,
		Payload:  sealed,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run encrypted TIXU secure XDP RX direct control: %v", err)
	}
	if ret == 0 {
		t.Fatalf("encrypted TIXU secure XDP RX direct control return = %d, want redirect/drop from devmap helper", ret)
	}
	if len(run.DataOut) != 14+len(inner) {
		t.Fatalf("encrypted TIXU secure XDP RX direct control data out len = %d, want %d", len(run.DataOut), 14+len(inner))
	}
	if !bytes.Equal(run.DataOut[14:], inner) {
		t.Fatalf("encrypted TIXU secure XDP RX direct control inner packet mismatch")
	}
	assertXDPStat(t, object, 0, 0)
	assertXDPStat(t, object, 2, 0)
	assertXDPStat(t, object, 4, 1)
	assertXDPStat(t, object, 5, 1)
	assertXDPStat(t, object, 18, 1)
	assertXDPStat(t, object, 21, 1)
}

func TestExperimentalTCPKernelCryptoXDPOpensKernelUDPControlWithoutTCRXDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp XDP kernel-open control redirect requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9913
		epoch           = 19
		sequence        = 11
		destinationPort = 9449
	)
	spec := validKernelCryptoSpec(flowID)
	spec.Epoch = epoch
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	udpSpec := dataplane.KernelUDPCryptoSpec{
		FlowID:       spec.FlowID,
		Suite:        spec.Suite,
		WireFormat:   spec.WireFormat,
		Epoch:        spec.Epoch,
		SendKey:      spec.SendKey,
		SendIV:       spec.SendIV,
		RecvKey:      spec.RecvKey,
		RecvIV:       spec.RecvIV,
		ReplayWindow: spec.ReplayWindow,
	}
	if err := manager.InstallKernelUDPCrypto(context.Background(), []dataplane.KernelUDPCryptoSpec{udpSpec}); err != nil {
		t.Fatalf("install kernel_udp crypto contexts: %v", err)
	}
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen | experimentalTCPConfigKernelUDPXDPPassOpened
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable XDP UDP kernel open TC direct handoff: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	suiteID, err := kernelCryptoSuiteID(spec.Suite)
	if err != nil {
		t.Fatalf("suite id: %v", err)
	}
	plain := []byte{'T', 'I', 'X', 'C', 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}
	sealed, err := manager.kernelCryptoProvider.SealFrame(
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, flowID, kernelCryptoDirectionSend),
		suiteID,
		epoch,
		sequence,
		plain,
	)
	if err != nil {
		t.Fatalf("seal kernel_udp control payload for XDP: %v", err)
	}
	packet := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagEncrypted,
		FlowID:   flowID,
		Sequence: sequence,
		Payload:  sealed,
	}, destinationPort)
	run := &cebpf.RunOptions{Data: append([]byte(nil), packet...), DataOut: make([]byte, len(packet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run XDP UDP kernel open control redirect: %v", err)
	}
	if ret == 0 {
		t.Fatalf("XDP UDP kernel open control return = %d, want AF_XDP redirect/drop", ret)
	}
	udpPacket, err := kerneludp.ParseUDPIPv4(run.DataOut[14:])
	if err != nil {
		t.Fatalf("parse opened control UDP packet: %v", err)
	}
	frame, err := kerneludp.ParseFrame(udpPacket.Payload)
	if err != nil {
		t.Fatalf("parse opened control TIXU frame: %v", err)
	}
	if frame.Flags&(kerneludp.FlagKernelOpened|kerneludp.FlagInnerIPv4) != kerneludp.FlagKernelOpened || frame.Flags&kerneludp.FlagEncrypted != 0 {
		t.Fatalf("opened control frame flags = %#x", frame.Flags)
	}
	if !bytes.Equal(frame.Payload, plain) {
		t.Fatalf("opened control payload = %x, want %x", frame.Payload, plain)
	}
	assertXDPStat(t, object, 0, 1)
	assertXDPStat(t, object, 4, 1)
	assertXDPStat(t, object, 5, 1)
	assertXDPStat(t, object, 14, 0)
}

func TestExperimentalTCPKernelCryptoTXSealXDPSealsPacket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto TX seal XDP program run requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9202
		sequence        = 3
		destinationPort = 9444
	)
	spec := validKernelCryptoSpec(flowID)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install kernel crypto contexts: %v", err)
	}
	sealer, err := loadExperimentalTCPTXSealObject(manager.kernelCryptoProvider)
	if err != nil {
		t.Fatalf("load experimental_tcp TX seal XDP object: %-v", err)
	}
	defer sealer.Close()

	plaintext := []byte("trustix tx packet seal")
	frameWire, err := experimentaltcp.Frame{
		FlowID:   flowID,
		Epoch:    spec.Epoch,
		Sequence: sequence,
		Payload:  plaintext,
	}.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal plaintext TIXT frame: %v", err)
	}
	packet, err := experimentaltcp.MarshalTCPShapedIPv4(experimentaltcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: destinationPort,
		Sequence:        1234,
		Acknowledgment:  1,
		Payload:         frameWire,
	})
	if err != nil {
		t.Fatalf("marshal plaintext TCP-shaped packet: %v", err)
	}
	sealedPacket, err := sealer.SealIPv4(packet)
	if err != nil {
		t.Fatalf("seal TCP-shaped packet: %v", err)
	}
	if _, err := sealer.SealIPv4(packet); err == nil {
		t.Fatalf("duplicate TX packet seal unexpectedly succeeded")
	}
	if bytes.Contains(sealedPacket, plaintext) {
		t.Fatalf("sealed packet still contains plaintext")
	}
	tcpPacket, err := experimentaltcp.ParseTCPShapedIPv4(sealedPacket)
	if err != nil {
		t.Fatalf("parse sealed TCP-shaped packet: %v", err)
	}
	sealedFrame, err := experimentaltcp.ParseFrame(tcpPacket.Payload)
	if err != nil {
		t.Fatalf("parse sealed TIXT frame: %v", err)
	}
	if sealedFrame.Flags&experimentaltcp.FlagEncrypted == 0 || sealedFrame.Flags&experimentaltcp.FlagKernelOpened != 0 {
		t.Fatalf("sealed frame flags = %#x, want encrypted only", sealedFrame.Flags)
	}
	opened, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence, sealedFrame.Payload)
	if err != nil {
		t.Fatalf("open sealed frame: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened payload = %q, want %q", opened, plaintext)
	}
	plaintextInPlace := []byte("trustix tx packet seal in-place")
	frameWireInPlace, err := experimentaltcp.Frame{
		FlowID:   flowID,
		Epoch:    spec.Epoch,
		Sequence: sequence + 1,
		Payload:  plaintextInPlace,
	}.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal in-place plaintext TIXT frame: %v", err)
	}
	packetInPlace, err := experimentaltcp.MarshalTCPShapedIPv4(experimentaltcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: destinationPort,
		Sequence:        1235,
		Acknowledgment:  1,
		Payload:         frameWireInPlace,
	})
	if err != nil {
		t.Fatalf("marshal in-place plaintext TCP-shaped packet: %v", err)
	}
	ethernetInPlace := make([]byte, 14+len(packetInPlace)+experimentalTCPKernelCryptoOverhead)
	copy(ethernetInPlace[0:6], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01})
	copy(ethernetInPlace[6:12], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02})
	ethernetInPlace[12] = 0x08
	ethernetInPlace[13] = 0x00
	copy(ethernetInPlace[14:], packetInPlace)
	sealedLen, err := sealer.SealEthernetInPlace(ethernetInPlace, 14+len(packetInPlace))
	if err != nil {
		t.Fatalf("seal TCP-shaped packet in-place: %v", err)
	}
	if sealedLen != 14+len(packetInPlace)+experimentalTCPKernelCryptoOverhead {
		t.Fatalf("in-place sealed length = %d, want %d", sealedLen, 14+len(packetInPlace)+experimentalTCPKernelCryptoOverhead)
	}
	sealedInPlace := ethernetInPlace[14:sealedLen]
	if bytes.Contains(sealedInPlace, plaintextInPlace) {
		t.Fatalf("in-place sealed packet still contains plaintext")
	}
	tcpPacketInPlace, err := experimentaltcp.ParseTCPShapedIPv4(sealedInPlace)
	if err != nil {
		t.Fatalf("parse in-place sealed TCP-shaped packet: %v", err)
	}
	sealedFrameInPlace, err := experimentaltcp.ParseFrame(tcpPacketInPlace.Payload)
	if err != nil {
		t.Fatalf("parse in-place sealed TIXT frame: %v", err)
	}
	openedInPlace, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence+1, sealedFrameInPlace.Payload)
	if err != nil {
		t.Fatalf("open in-place sealed frame: %v", err)
	}
	if !bytes.Equal(openedInPlace, plaintextInPlace) {
		t.Fatalf("opened in-place payload = %q, want %q", openedInPlace, plaintextInPlace)
	}
	assertTXSealStat(t, sealer, 0, 3)
	assertTXSealStat(t, sealer, 1, 2)
	assertTXSealStat(t, sealer, 2, 1)
	assertTXSealStat(t, sealer, 6, 1)
}

func TestExperimentalTCPKernelCryptoTXSealOutputOpensInAttachedXDP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto TX/RX XDP program run requires root")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "1")
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9203
		destinationPort = 9446
		xdpDrop         = 1
	)
	spec := validKernelCryptoSpec(flowID)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install kernel crypto contexts: %v", err)
	}
	sealer, err := loadExperimentalTCPTXSealObject(manager.kernelCryptoProvider)
	if err != nil {
		t.Fatalf("load experimental_tcp TX seal XDP object: %-v", err)
	}
	defer sealer.Close()
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{kernelCryptoProvider: manager.kernelCryptoProvider})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}

	for idx, payloadLen := range []int{32, 554, 1024} {
		plaintext := bytes.Repeat([]byte{byte(0x41 + idx)}, payloadLen)
		providerSequence := uint64(20 + idx*2)
		sealedFrame := sealTCPShapedEthernetForTest(t, sealer, flowID, spec.Epoch, providerSequence, destinationPort, uint32(1234+idx*2), plaintext)
		sealedPacket, err := experimentaltcp.ParseTCPShapedIPv4(sealedFrame[14:])
		if err != nil {
			t.Fatalf("parse provider-check sealed packet len=%d: %v", payloadLen, err)
		}
		sealedTIXTFrame, err := experimentaltcp.ParseFrame(sealedPacket.Payload)
		if err != nil {
			t.Fatalf("parse provider-check sealed TIXT frame len=%d: %v", payloadLen, err)
		}
		openedByProvider, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, providerSequence, sealedTIXTFrame.Payload)
		if err != nil {
			t.Fatalf("provider open of TX-sealed frame len=%d: %v", payloadLen, err)
		}
		if !bytes.Equal(openedByProvider, plaintext) {
			t.Fatalf("provider-opened payload len=%d differs: got %d bytes", payloadLen, len(openedByProvider))
		}

		sequence := providerSequence + 1
		ethernet := sealTCPShapedEthernetForTest(t, sealer, flowID, spec.Epoch, sequence, destinationPort, uint32(1235+idx*2), plaintext)
		run := &cebpf.RunOptions{Data: append([]byte(nil), ethernet...), DataOut: make([]byte, len(ethernet))}
		ret, err := object.program.Run(run)
		if err != nil {
			t.Fatalf("run attached XDP open len=%d: %v", payloadLen, err)
		}
		if ret == 0 {
			recvState := kernelCryptoCtxStateSnapshotForTest(t, manager.kernelCryptoProvider, kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv))
			t.Fatalf("attached XDP open len=%d returned %d, want redirect fallback/drop; recv_last_sequence=%d stats=%v", payloadLen, ret, recvState.LastSequence, xdpStatsForTest(t, object))
		}
		openedPacket, err := experimentaltcp.ParseTCPShapedIPv4(run.DataOut[14:])
		if err != nil {
			got, want := tcpChecksumForTest(run.DataOut[14:])
			t.Fatalf("parse opened TCP-shaped packet len=%d: %v (tcp checksum got=%#04x want=%#04x)", payloadLen, err, got, want)
		}
		openedFrame, err := experimentaltcp.ParseFrame(openedPacket.Payload)
		if err != nil {
			t.Fatalf("parse opened TIXT frame len=%d: %v", payloadLen, err)
		}
		if openedFrame.Flags&experimentaltcp.FlagEncrypted != 0 || openedFrame.Flags&experimentaltcp.FlagKernelOpened == 0 {
			t.Fatalf("opened frame len=%d flags = %#x, want kernel-opened plaintext", payloadLen, openedFrame.Flags)
		}
		if !bytes.Equal(openedFrame.Payload, plaintext) {
			t.Fatalf("opened payload len=%d differs: got %d bytes", payloadLen, len(openedFrame.Payload))
		}
	}
}

func TestExperimentalTCPKernelCryptoXDPDirectsOpenedTIXTToLAN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("experimental_tcp kernel crypto XDP RX direct program run requires root")
	}
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "1")
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const (
		flowID          = 9204
		destinationPort = 9452
	)
	spec := validKernelCryptoSpec(flowID)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install kernel crypto contexts: %v", err)
	}
	sealer, err := loadExperimentalTCPTXSealObject(manager.kernelCryptoProvider)
	if err != nil {
		t.Fatalf("load experimental_tcp TX seal XDP object: %-v", err)
	}
	defer sealer.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_kernel_crypto_rx_neigh_xdp_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_kernel_crypto_rx_devmap_xdp_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_kernel_crypto_rx_config_xdp_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer configMap.Close()
	object, err := loadExperimentalTCPXDPObjectFile(1, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", experimentalTCPXDPReplacements{
		kernelCryptoProvider: manager.kernelCryptoProvider,
		kernelUDPRXNeighMap:  neighMap,
		kernelUDPRXDevMap:    devMap,
		kernelUDPRXConfigMap: configMap,
	})
	if err != nil {
		t.Fatalf("load experimental_tcp kernel crypto XDP object: %-v", err)
	}
	defer object.Close()
	key := uint32(0)
	config := experimentalTCPConfigKernelUDPXDPOpen |
		experimentalTCPConfigKernelUDPXDPRXDirect |
		experimentalTCPConfigKernelUDPXDPRXSecureDirect |
		experimentalTCPConfigHotPathStats
	if err := object.configMap.Update(key, config, cebpf.UpdateAny); err != nil {
		t.Fatalf("enable encrypted TIXT XDP RX direct: %v", err)
	}
	value := uint8(1)
	if err := object.portMap.Update(experimentalTCPPortMapKey(destinationPort), value, cebpf.UpdateAny); err != nil {
		t.Fatalf("allow destination port in XDP map: %v", err)
	}
	neighborKey := binary.LittleEndian.Uint32([]byte{10, 0, 1, 2})
	neighbor := kernelUDPRXNeighValue{
		Ifindex:         1,
		DestinationMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x70, 0x71, 0x72}),
		DestinationMAC1: binary.LittleEndian.Uint16([]byte{0x73, 0x74}),
		SourceMAC0:      binary.LittleEndian.Uint32([]byte{0x02, 0x80, 0x81, 0x82}),
		SourceMAC1:      binary.LittleEndian.Uint16([]byte{0x83, 0x84}),
	}
	if err := neighMap.Update(neighborKey, neighbor, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXT XDP RX direct neighbor: %v", err)
	}
	devKey := uint32(0)
	devIfindex := uint32(1)
	if err := devMap.Update(devKey, devIfindex, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXT XDP RX direct devmap: %v", err)
	}
	rxConfig := kernelUDPRXConfigValue{
		SourceMAC0: binary.LittleEndian.Uint32([]byte{0x02, 0x80, 0x81, 0x82}),
		SourceMAC1: binary.LittleEndian.Uint16([]byte{0x83, 0x84}),
		Ifindex:    1,
	}
	if err := configMap.Update(devKey, rxConfig, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed encrypted TIXT XDP RX direct config: %v", err)
	}

	inner := ipv4PacketForXDPTCRXDirectTest()
	ethernet := sealTCPShapedEthernetWithFlagsForTest(t, sealer, flowID, spec.Epoch, 31, destinationPort, 1250, inner, experimentaltcp.FlagInnerIPv4)
	run := &cebpf.RunOptions{Data: append([]byte(nil), ethernet...), DataOut: make([]byte, len(ethernet))}
	ret, err := object.program.Run(run)
	if err != nil {
		t.Fatalf("run encrypted TIXT XDP RX direct: %v", err)
	}
	if ret == 0 {
		t.Fatalf("encrypted TIXT XDP RX direct return = %d, want redirect/drop from devmap helper", ret)
	}
	if len(run.DataOut) != 14+len(inner) {
		t.Fatalf("encrypted TIXT XDP RX direct data out len = %d, want %d", len(run.DataOut), 14+len(inner))
	}
	if !bytes.Equal(run.DataOut[:14], []byte{0x02, 0x70, 0x71, 0x72, 0x73, 0x74, 0x02, 0x80, 0x81, 0x82, 0x83, 0x84, 0x08, 0x00}) {
		t.Fatalf("encrypted TIXT XDP RX direct ethernet header = %x", run.DataOut[:14])
	}
	if !bytes.Equal(run.DataOut[14:], inner) {
		t.Fatalf("encrypted TIXT XDP RX direct inner packet mismatch")
	}
	assertXDPStat(t, object, 0, 0)
	assertXDPStat(t, object, 4, 1)
	assertXDPStat(t, object, 5, 1)
	assertXDPStat(t, object, 18, 1)
	assertXDPStat(t, object, 21, 1)
	assertXDPStat(t, object, 22, 1)
}

func sealTCPShapedEthernetForTest(t *testing.T, sealer *experimentalTCPTXSealObject, flowID uint64, epoch uint64, sequence uint64, destinationPort uint16, tcpSequence uint32, plaintext []byte) []byte {
	return sealTCPShapedEthernetWithFlagsForTest(t, sealer, flowID, epoch, sequence, destinationPort, tcpSequence, plaintext, 0)
}

func sealTCPShapedEthernetWithFlagsForTest(t *testing.T, sealer *experimentalTCPTXSealObject, flowID uint64, epoch uint64, sequence uint64, destinationPort uint16, tcpSequence uint32, plaintext []byte, flags uint8) []byte {
	t.Helper()
	frameWire, err := experimentaltcp.Frame{
		FlowID:   flowID,
		Epoch:    epoch,
		Sequence: sequence,
		Flags:    flags,
		Payload:  plaintext,
	}.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal plaintext TIXT frame len=%d: %v", len(plaintext), err)
	}
	packet, err := experimentaltcp.MarshalTCPShapedIPv4(experimentaltcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: destinationPort,
		Sequence:        tcpSequence,
		Acknowledgment:  1,
		Payload:         frameWire,
	})
	if err != nil {
		t.Fatalf("marshal plaintext TCP-shaped packet len=%d: %v", len(plaintext), err)
	}
	ethernet := make([]byte, 14+len(packet)+experimentalTCPKernelCryptoOverhead)
	copy(ethernet[0:6], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01})
	copy(ethernet[6:12], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02})
	ethernet[12] = 0x08
	ethernet[13] = 0x00
	copy(ethernet[14:], packet)
	sealedLen, err := sealer.SealEthernetInPlace(ethernet, 14+len(packet))
	if err != nil {
		t.Fatalf("seal TCP-shaped packet len=%d: %v", len(plaintext), err)
	}
	return append([]byte(nil), ethernet[:sealedLen]...)
}

type kernelCryptoCtxStateForTest struct {
	Ctx           uint64
	Suite         uint16
	WireFormat    uint16
	Flags         uint32
	Epoch         uint64
	IV            [12]byte
	ReplayWindow  uint32
	InstalledUnix int64
	Packets       uint64
	Bytes         uint64
	LastSequence  uint64
	ReplaySeen    [64]uint64
	ReplayBlocks  [64]uint64
}

func kernelCryptoCtxStateSnapshotForTest(t *testing.T, provider *kernelCryptoProviderObject, key kernelCryptoFlowKey) kernelCryptoCtxStateForTest {
	t.Helper()
	var slot uint32
	if err := provider.flowIndexMap.Lookup(key, &slot); err != nil {
		t.Fatalf("lookup kernel crypto slot for %+v: %v", key, err)
	}
	var state kernelCryptoCtxStateForTest
	if err := provider.contextSlots.Lookup(slot, &state); err != nil {
		t.Fatalf("lookup kernel crypto ctx slot %d: %v", slot, err)
	}
	return state
}

func xdpStatsForTest(t *testing.T, object *experimentalTCPXDPObject) map[uint32]uint64 {
	t.Helper()
	stats := make(map[uint32]uint64)
	for key := uint32(0); key <= 10; key++ {
		value, err := bpfCounterValue(object.xdpStatsMap, key)
		if err != nil {
			t.Fatalf("lookup XDP stat %d: %v", key, err)
		}
		stats[key] = value
	}
	return stats
}

func mustExperimentalTCPXDPEthernetFrame(t *testing.T, frame experimentaltcp.Frame, destinationPort uint16) []byte {
	t.Helper()
	payload, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal TIXT frame: %v", err)
	}
	ipPacket, err := experimentaltcp.MarshalTCPShapedIPv4(experimentaltcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: destinationPort,
		Sequence:        1234,
		Acknowledgment:  1,
		Payload:         payload,
	})
	if err != nil {
		t.Fatalf("marshal TCP-shaped packet: %v", err)
	}
	ethernet := make([]byte, 14+len(ipPacket))
	copy(ethernet[0:6], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01})
	copy(ethernet[6:12], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02})
	ethernet[12] = 0x08
	ethernet[13] = 0x00
	copy(ethernet[14:], ipPacket)
	return ethernet
}

func mustExperimentalTCPXDPStreamEthernetFrame(t *testing.T, frames []experimentaltcp.Frame, destinationPort uint16) []byte {
	t.Helper()
	var payload []byte
	for i, frame := range frames {
		wire, err := frame.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal TIXT stream frame %d: %v", i, err)
		}
		payload = append(payload, wire...)
	}
	ipPacket, err := experimentaltcp.MarshalTCPShapedIPv4(experimentaltcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: destinationPort,
		Sequence:        1234,
		Acknowledgment:  1,
		Payload:         payload,
	})
	if err != nil {
		t.Fatalf("marshal TCP-shaped stream packet: %v", err)
	}
	return mustEthernetIPv4ForXDPTest(ipPacket)
}

func mustEthernetIPv4ForXDPTest(ipPacket []byte) []byte {
	ethernet := make([]byte, 14+len(ipPacket))
	copy(ethernet[0:6], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01})
	copy(ethernet[6:12], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02})
	ethernet[12] = 0x08
	ethernet[13] = 0x00
	copy(ethernet[14:], ipPacket)
	return ethernet
}

func mustKernelUDPXDPEthernetFrame(t *testing.T, frame kerneludp.Frame, destinationPort uint16) []byte {
	return mustKernelUDPXDPEthernetFramePorts(t, frame, 43000, destinationPort)
}

func mustKernelUDPXDPEthernetFramePorts(t *testing.T, frame kerneludp.Frame, sourcePort uint16, destinationPort uint16) []byte {
	t.Helper()
	payload, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal TIXU frame: %v", err)
	}
	ipPacket, err := kerneludp.MarshalUDPIPv4(kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      sourcePort,
		DestinationPort: destinationPort,
		Payload:         payload,
	})
	if err != nil {
		t.Fatalf("marshal UDP packet: %v", err)
	}
	ethernet := make([]byte, 14+len(ipPacket))
	copy(ethernet[0:6], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01})
	copy(ethernet[6:12], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02})
	ethernet[12] = 0x08
	ethernet[13] = 0x00
	copy(ethernet[14:], ipPacket)
	return ethernet
}

func ipv4PacketForXDPTCRXDirectTest() []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 0, 0, 2})
	copy(packet[16:20], []byte{10, 0, 1, 2})
	binary.BigEndian.PutUint16(packet[20:22], 12345)
	binary.BigEndian.PutUint16(packet[22:24], 443)
	return packet
}

func ethernetIPv4PacketForXDPTCRXDirectTest(ipv4 []byte) []byte {
	ethernet := make([]byte, 14+len(ipv4))
	copy(ethernet[0:6], []byte{0x02, 0x10, 0x11, 0x12, 0x13, 0x14})
	copy(ethernet[6:12], []byte{0x02, 0x20, 0x21, 0x22, 0x23, 0x24})
	ethernet[12] = 0x08
	ethernet[13] = 0x00
	copy(ethernet[14:], ipv4)
	return ethernet
}

func assertXDPStat(t *testing.T, object *experimentalTCPXDPObject, key uint32, want uint64) {
	t.Helper()
	got, err := bpfCounterValue(object.xdpStatsMap, key)
	if err != nil {
		t.Fatalf("lookup XDP stat %d: %v", key, err)
	}
	if got != want {
		t.Fatalf("XDP stat %d = %d, want %d", key, got, want)
	}
}

func assertTXSealStat(t *testing.T, object *experimentalTCPTXSealObject, key uint32, want uint64) {
	t.Helper()
	got, err := bpfCounterValue(object.statsMap, key)
	if err != nil {
		t.Fatalf("lookup TX seal stat %d: %v", key, err)
	}
	if got != want {
		t.Fatalf("TX seal stat %d = %d, want %d", key, got, want)
	}
}

func tcpChecksumForTest(wire []byte) (uint16, uint16) {
	if len(wire) < 40 {
		return 0, 0
	}
	ihl := int(wire[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(wire[2:4]))
	if ihl < 20 || totalLen < ihl+20 || totalLen > len(wire) {
		return 0, 0
	}
	tcp := wire[ihl:totalLen]
	src := [4]byte{wire[12], wire[13], wire[14], wire[15]}
	dst := [4]byte{wire[16], wire[17], wire[18], wire[19]}
	return binary.BigEndian.Uint16(tcp[16:18]), tcpChecksumBytesForTest(src, dst, tcp)
}

func tcpChecksumBytesForTest(src, dst [4]byte, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	pseudo[28] = 0
	pseudo[29] = 0
	return checksumBytesForTest(pseudo)
}

func checksumBytesForTest(payload []byte) uint16 {
	var sum uint32
	for len(payload) > 1 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
