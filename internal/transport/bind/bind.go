package bind

import (
	"context"
	"fmt"
	"net"
	"strings"

	"trustix.local/trustix/internal/transport"
)

func Dialer(endpoint transport.Endpoint, network string) (*net.Dialer, error) {
	dialer := &net.Dialer{}
	sourceIP := strings.TrimSpace(endpoint.LocalBind.SourceIP)
	if sourceIP != "" {
		ip := net.ParseIP(sourceIP)
		if ip == nil {
			return nil, fmt.Errorf("endpoint %q local_bind source_ip %q is not an IP address", endpoint.Name, endpoint.LocalBind.SourceIP)
		}
		switch strings.ToLower(strings.TrimSpace(network)) {
		case "udp", "udp4", "udp6":
			dialer.LocalAddr = &net.UDPAddr{IP: ip}
		case "tcp", "tcp4", "tcp6":
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		default:
			return nil, fmt.Errorf("endpoint %q local_bind source_ip is unsupported for network %q", endpoint.Name, network)
		}
	}
	if iface := strings.TrimSpace(endpoint.LocalBind.Iface); iface != "" {
		if strings.ContainsAny(iface, "/\x00") {
			return nil, fmt.Errorf("endpoint %q local_bind iface must be an interface name", endpoint.Name)
		}
		control, err := bindToDeviceControl(iface)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q local_bind iface %q: %w", endpoint.Name, iface, err)
		}
		dialer.Control = control
	}
	return dialer, nil
}

func DialContext(ctx context.Context, endpoint transport.Endpoint, network string) (net.Conn, error) {
	dialer, err := Dialer(endpoint, network)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, endpoint.Address)
}

func UDPListenAddress(endpoint transport.Endpoint) (*net.UDPAddr, error) {
	sourceIP := strings.TrimSpace(endpoint.LocalBind.SourceIP)
	if sourceIP == "" {
		return &net.UDPAddr{}, nil
	}
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return nil, fmt.Errorf("endpoint %q local_bind source_ip %q is not an IP address", endpoint.Name, endpoint.LocalBind.SourceIP)
	}
	return &net.UDPAddr{IP: ip}, nil
}

func ListenPacket(ctx context.Context, endpoint transport.Endpoint, network string) (net.PacketConn, error) {
	address := ":0"
	sourceIP := strings.TrimSpace(endpoint.LocalBind.SourceIP)
	if sourceIP != "" {
		ip := net.ParseIP(sourceIP)
		if ip == nil {
			return nil, fmt.Errorf("endpoint %q local_bind source_ip %q is not an IP address", endpoint.Name, endpoint.LocalBind.SourceIP)
		}
		address = net.JoinHostPort(sourceIP, "0")
	}
	config := net.ListenConfig{}
	if iface := strings.TrimSpace(endpoint.LocalBind.Iface); iface != "" {
		if strings.ContainsAny(iface, "/\x00") {
			return nil, fmt.Errorf("endpoint %q local_bind iface must be an interface name", endpoint.Name)
		}
		control, err := bindToDeviceControl(iface)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q local_bind iface %q: %w", endpoint.Name, iface, err)
		}
		config.Control = control
	}
	return config.ListenPacket(ctx, network, address)
}
