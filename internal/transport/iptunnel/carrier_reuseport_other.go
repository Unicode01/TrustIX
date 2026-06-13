//go:build !linux

package iptunnel

import (
	"context"
	"net"
	"net/netip"
)

func listenUDPOnCarrierConns(ctx context.Context, addr netip.Addr, port uint16, workers int) ([]*net.UDPConn, error) {
	conn, err := listenUDPOnCarrier(ctx, addr, port)
	if err != nil {
		return nil, err
	}
	return []*net.UDPConn{conn}, nil
}
