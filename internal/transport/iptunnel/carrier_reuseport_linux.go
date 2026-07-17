//go:build linux

package iptunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenUDPOnCarrierConns(ctx context.Context, addr netip.Addr, port uint16, workers int) ([]*net.UDPConn, error) {
	if workers <= 1 {
		conn, err := listenUDPOnCarrier(ctx, addr, port)
		if err != nil {
			return nil, err
		}
		return []*net.UDPConn{conn}, nil
	}
	udpAddr := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
	conns := make([]*net.UDPConn, 0, workers)
	closeConns := func() error {
		var errs []error
		for _, conn := range conns {
			if err := conn.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close tunnel carrier listener %s: %w", conn.LocalAddr(), err))
			}
		}
		return errors.Join(errs...)
	}
	listenConfig := net.ListenConfig{
		Control: func(network, address string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = err
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					sockErr = err
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	for i := 0; i < workers; i++ {
		packetConn, err := listenConfig.ListenPacket(ctx, "udp4", udpAddr)
		if err != nil {
			return nil, errors.Join(err, closeConns())
		}
		udpConn, ok := packetConn.(*net.UDPConn)
		if !ok {
			closeErr := packetConn.Close()
			return nil, errors.Join(
				fmt.Errorf("listen tunnel carrier returned %T", packetConn),
				wrapTunnelStateError("close unexpected tunnel carrier listener", closeErr),
				closeConns(),
			)
		}
		conns = append(conns, udpConn)
	}
	return conns, nil
}
