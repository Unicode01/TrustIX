// Package iptunnel implements TrustIX packet sessions over Linux GRE/IPIP
// kernel tunnel devices with an inner UDP carrier. It intentionally has no
// userspace raw-socket fallback.
package iptunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"trustix.local/trustix/internal/transport"
)

type Transport struct {
	protocol transport.Protocol
	manager  *Manager
}

func NewGRE() *Transport {
	return &Transport{protocol: transport.ProtocolGRE}
}

func NewGREWithManager(manager *Manager) *Transport {
	return &Transport{protocol: transport.ProtocolGRE, manager: manager}
}

func NewIPIP() *Transport {
	return &Transport{protocol: transport.ProtocolIPIP}
}

func NewIPIPWithManager(manager *Manager) *Transport {
	return &Transport{protocol: transport.ProtocolIPIP, manager: manager}
}

func NewVXLAN() *Transport {
	return &Transport{protocol: transport.ProtocolVXLAN}
}

func NewVXLANWithManager(manager *Manager) *Transport {
	return &Transport{protocol: transport.ProtocolVXLAN, manager: manager}
}

func (transportImpl *Transport) Name() transport.Protocol {
	return transportImpl.protocol
}

func (transportImpl *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	if err := ctx.Err(); err != nil {
		return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
	}
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport == transportImpl.protocol && endpoint.Address != "" {
			if _, err := parseTunnelConfig(endpoint.Address); err != nil {
				return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
			}
			return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
		}
	}
	return transport.ProbeResult{Healthy: false, Error: fmt.Sprintf("no %s endpoint", transportImpl.protocol), CheckedAt: time.Now()}
}

func (transportImpl *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport == transportImpl.protocol && endpoint.Address != "" {
			cfg, err := parseTunnelConfig(endpoint.Address)
			if err != nil {
				return nil, fmt.Errorf("%s endpoint %q carrier config: %w", transportImpl.protocol, endpoint.Name, err)
			}
			cfg.Protocol = transportImpl.protocol
			name, err := transportImpl.acquireTunnel(ctx, string(endpoint.Name), "dial", cfg)
			if err != nil {
				return nil, err
			}
			conn, err := dialUDPOnCarrier(ctx, cfg.LocalCarrier.Addr(), cfg.RemoteCarrier, cfg.CarrierPort)
			if err != nil {
				_ = transportImpl.closeTunnelFunc(name)()
				return nil, fmt.Errorf("dial %s kernel tunnel carrier %s:%d: %w", transportImpl.protocol, cfg.RemoteCarrier, cfg.CarrierPort, err)
			}
			return &carrier{cfg: cfg, closeFunc: transportImpl.closeTunnelFunc(name), conn: conn}, nil
		}
	}
	return nil, fmt.Errorf("peer %q has no dialable %s endpoint", peer.ID, transportImpl.protocol)
}

func (transportImpl *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ep.Transport != transportImpl.protocol {
		return nil, fmt.Errorf("endpoint %q transport is %q, want %s", ep.Name, ep.Transport, transportImpl.protocol)
	}
	raw := ep.Listen
	if raw == "" {
		raw = ep.Address
	}
	cfg, err := parseTunnelConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("%s endpoint %q carrier config: %w", transportImpl.protocol, ep.Name, err)
	}
	cfg.Protocol = transportImpl.protocol
	name, err := transportImpl.acquireTunnel(ctx, string(ep.Name), "listen", cfg)
	if err != nil {
		return nil, err
	}
	conns, err := listenUDPOnCarrierConns(ctx, cfg.LocalCarrier.Addr(), cfg.CarrierPort, carrierListenWorkers())
	if err != nil {
		_ = transportImpl.closeTunnelFunc(name)()
		return nil, fmt.Errorf("listen %s kernel tunnel carrier %s:%d: %w", transportImpl.protocol, cfg.LocalCarrier.Addr(), cfg.CarrierPort, err)
	}
	listener := newPacketListener(ctx, cfg, conns)
	return &tunnelListener{Listener: listener, tunnelName: name, closeFunc: transportImpl.closeTunnelFunc(name)}, nil
}

func (transportImpl *Transport) acquireTunnel(ctx context.Context, endpoint string, role string, cfg tunnelConfig) (string, error) {
	record := TunnelRecord{
		Protocol: string(transportImpl.protocol),
		Endpoint: endpoint,
		Role:     role,
		Config:   NormalizeParsedKernelTunnelConfig(transportImpl.protocol, cfg),
	}
	record.Name = DeterministicTunnelName(record.Protocol, record.Config)
	return transportImpl.manager.Acquire(ctx, record, func() (string, error) {
		return createKernelTunnel(transportImpl.protocol, record.Name, cfg)
	})
}

func (transportImpl *Transport) closeTunnelFunc(name string) func() error {
	return func() error {
		if transportImpl.manager != nil {
			return transportImpl.manager.Release(context.Background(), name)
		}
		return deleteKernelTunnel(name)
	}
}

type tunnelListener struct {
	transport.Listener
	tunnelName string
	closeFunc  func() error
	once       sync.Once
}

func (listener *tunnelListener) Close() error {
	var err error
	listener.once.Do(func() {
		err = listener.Listener.Close()
		if listener.closeFunc != nil {
			if closeErr := listener.closeFunc(); err == nil {
				err = closeErr
			}
		} else {
			_ = deleteKernelTunnel(listener.tunnelName)
		}
	})
	return err
}
