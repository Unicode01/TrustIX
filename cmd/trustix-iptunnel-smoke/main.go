package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/transport"
	"trustix.local/trustix/internal/transport/iptunnel"
)

type result struct {
	Mode        string                   `json:"mode"`
	Protocol    string                   `json:"protocol"`
	Endpoint    string                   `json:"endpoint"`
	Message     string                   `json:"message,omitempty"`
	Reply       string                   `json:"reply,omitempty"`
	Stats       transport.TransportStats `json:"stats"`
	ElapsedMS   int64                    `json:"elapsed_ms"`
	CarrierOnly bool                     `json:"carrier_only"`
}

func main() {
	var (
		mode        = flag.String("mode", "", "listen or dial")
		protocol    = flag.String("protocol", "gre", "gre, ipip, or vxlan")
		endpoint    = flag.String("endpoint", "", "kernel tunnel carrier endpoint config")
		message     = flag.String("message", "trustix-iptunnel-smoke", "client payload")
		expect      = flag.String("expect", "", "server expected payload")
		reply       = flag.String("reply", "trustix-iptunnel-smoke-ok", "server reply payload")
		expectReply = flag.String("expect-reply", "trustix-iptunnel-smoke-ok", "client expected reply")
		readyFile   = flag.String("ready-file", "", "write this file after listener is ready")
		timeout     = flag.Duration("timeout", 10*time.Second, "operation timeout")
	)
	flag.Parse()

	if err := run(*mode, *protocol, *endpoint, *message, *expect, *reply, *expectReply, *readyFile, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "trustix-iptunnel-smoke: %v\n", err)
		os.Exit(1)
	}
}

func run(mode, protocol, endpoint, message, expect, reply, expectReply, readyFile string, timeout time.Duration) error {
	if endpoint == "" {
		return fmt.Errorf("-endpoint is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	proto := transport.Protocol(protocol)
	tr, err := newTransport(proto)
	if err != nil {
		return err
	}
	start := time.Now()
	switch mode {
	case "listen":
		return runListen(ctx, tr, proto, endpoint, expect, reply, readyFile, start)
	case "dial":
		return runDial(ctx, tr, proto, endpoint, message, expectReply, start)
	default:
		return fmt.Errorf("-mode must be listen or dial")
	}
}

func newTransport(protocol transport.Protocol) (transport.Transport, error) {
	switch protocol {
	case transport.ProtocolGRE:
		return iptunnel.NewGRE(), nil
	case transport.ProtocolIPIP:
		return iptunnel.NewIPIP(), nil
	case transport.ProtocolVXLAN:
		return iptunnel.NewVXLAN(), nil
	default:
		return nil, fmt.Errorf("unsupported iptunnel protocol %q", protocol)
	}
}

func runListen(ctx context.Context, tr transport.Transport, protocol transport.Protocol, endpoint string, expect string, reply string, readyFile string, start time.Time) error {
	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("iptunnel-smoke"),
		Mode:      transport.EndpointPassive,
		Listen:    endpoint,
		Transport: protocol,
		Enabled:   true,
	}, (*tls.Config)(nil))
	if err != nil {
		return err
	}
	defer listener.Close()
	if readyFile != "" {
		if err := os.WriteFile(readyFile, []byte("ready\n"), 0o644); err != nil {
			return fmt.Errorf("write ready file: %w", err)
		}
	}
	session, err := listener.Accept(ctx)
	if err != nil {
		return err
	}
	defer session.Close()
	packet, err := session.RecvPacket()
	if err != nil {
		return err
	}
	if expect != "" && string(packet) != expect {
		return fmt.Errorf("received payload %q, want %q", string(packet), expect)
	}
	if err := session.SendPacket([]byte(reply)); err != nil {
		return err
	}
	return writeResult(result{
		Mode:        "listen",
		Protocol:    string(protocol),
		Endpoint:    endpoint,
		Message:     string(packet),
		Reply:       reply,
		Stats:       session.Stats(),
		ElapsedMS:   time.Since(start).Milliseconds(),
		CarrierOnly: true,
	})
}

func runDial(ctx context.Context, tr transport.Transport, protocol transport.Protocol, endpoint string, message string, expectReply string, start time.Time) error {
	session, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("iptunnel-smoke-peer"),
		DomainID: core.DomainID("smoke"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("iptunnel-smoke"),
			Mode:      transport.EndpointActive,
			Address:   endpoint,
			Transport: protocol,
			Enabled:   true,
		}},
	}, (*tls.Config)(nil))
	if err != nil {
		return err
	}
	defer session.Close()
	if err := session.SendPacket([]byte(message)); err != nil {
		return err
	}
	packet, err := session.RecvPacket()
	if err != nil {
		return err
	}
	if expectReply != "" && string(packet) != expectReply {
		return fmt.Errorf("reply payload %q, want %q", string(packet), expectReply)
	}
	return writeResult(result{
		Mode:        "dial",
		Protocol:    string(protocol),
		Endpoint:    endpoint,
		Message:     message,
		Reply:       string(packet),
		Stats:       session.Stats(),
		ElapsedMS:   time.Since(start).Milliseconds(),
		CarrierOnly: true,
	})
}

func writeResult(value result) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
