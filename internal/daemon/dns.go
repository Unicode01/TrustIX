package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/routing"
)

const (
	defaultDNSTTL         = 30 * time.Second
	dnsReadWriteTimeout   = 5 * time.Second
	dnsForwardTimeout     = 3 * time.Second
	dnsDefaultPort        = "53"
	dnsOpenWRTDNSMasqPort = "1053"
	dnsUDPMessageMaxBytes = 1232
)

type dnsResolverConfig struct {
	Enabled   bool
	Listen    string
	Domain    string
	TTL       time.Duration
	Upstreams []string
	Capture   string
}

type dnsServerRuntime struct {
	Listen    string
	Domain    string
	TTL       time.Duration
	Upstreams []string
	Capture   string
	UDP       *mdns.Server
	TCP       *mdns.Server
	closing   atomic.Bool
}

type dnsStatus struct {
	Enabled   bool          `json:"enabled"`
	Running   bool          `json:"running"`
	Listen    string        `json:"listen,omitempty"`
	Domain    string        `json:"domain,omitempty"`
	TTL       string        `json:"ttl,omitempty"`
	Upstreams []string      `json:"upstreams,omitempty"`
	Capture   string        `json:"capture,omitempty"`
	DNSMasq   dnsMasqStatus `json:"dnsmasq,omitempty"`
	Error     string        `json:"error,omitempty"`
}

type trustIXDNSHandler struct {
	daemon *Daemon
	config dnsResolverConfig
}

func (daemon *Daemon) startDNSServer(ctx context.Context) error {
	daemon.dnsMu.Lock()
	defer daemon.dnsMu.Unlock()
	return daemon.startDNSServerLocked(ctx)
}

func (daemon *Daemon) startDNSServerLocked(ctx context.Context) error {
	cfg, err := daemon.dnsResolverConfig()
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	handler := &trustIXDNSHandler{daemon: daemon, config: cfg}
	udpConn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen dns udp %q: %w", cfg.Listen, err)
	}
	tcpListen := dnsTCPListenAddress(cfg.Listen, udpConn.LocalAddr())
	tcpListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", tcpListen)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("listen dns tcp %q: %w", tcpListen, err)
	}
	runtime := &dnsServerRuntime{
		Listen:    cfg.Listen,
		Domain:    cfg.Domain,
		TTL:       cfg.TTL,
		Upstreams: append([]string(nil), cfg.Upstreams...),
		Capture:   cfg.Capture,
		UDP: &mdns.Server{
			PacketConn:   udpConn,
			Handler:      handler,
			UDPSize:      dnsUDPMessageMaxBytes,
			ReadTimeout:  dnsReadWriteTimeout,
			WriteTimeout: dnsReadWriteTimeout,
		},
		TCP: &mdns.Server{
			Listener:     tcpListener,
			Handler:      handler,
			ReadTimeout:  dnsReadWriteTimeout,
			WriteTimeout: dnsReadWriteTimeout,
		},
	}
	daemon.dnsServer = runtime
	go daemon.serveDNSRuntime(runtime, "udp")
	go daemon.serveDNSRuntime(runtime, "tcp")
	return nil
}

func dnsTCPListenAddress(requested string, udpAddr net.Addr) string {
	host, port, err := net.SplitHostPort(requested)
	if err != nil || port != "0" || udpAddr == nil {
		return requested
	}
	_, udpPort, err := net.SplitHostPort(udpAddr.String())
	if err != nil || udpPort == "" {
		return requested
	}
	return net.JoinHostPort(host, udpPort)
}

func (daemon *Daemon) serveDNSRuntime(runtime *dnsServerRuntime, network string) {
	var err error
	switch network {
	case "udp":
		err = runtime.UDP.ActivateAndServe()
	case "tcp":
		err = runtime.TCP.ActivateAndServe()
	default:
		err = fmt.Errorf("unsupported dns network %q", network)
	}
	if err == nil || runtime.closing.Load() || dnsServerClosed(err) {
		return
	}
	daemon.reportDNSServerError(network, runtime.Listen, err)
}

func dnsServerClosed(err error) bool {
	if err == nil {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "use of closed network connection") ||
		strings.Contains(message, "server closed")
}

func (daemon *Daemon) reportDNSServerError(network string, listen string, err error) {
	daemon.apiMu.Lock()
	errc := daemon.apiErr
	daemon.apiMu.Unlock()
	if errc == nil {
		return
	}
	select {
	case errc <- fmt.Errorf("serve dns %s %q: %w", network, listen, err):
	default:
	}
}

func (daemon *Daemon) closeDNSServer(ctx context.Context) error {
	daemon.dnsMu.Lock()
	runtime := daemon.dnsServer
	daemon.dnsServer = nil
	daemon.dnsMu.Unlock()
	return shutdownDNSServerRuntime(ctx, runtime)
}

func (daemon *Daemon) restartDNSServer(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	daemon.dnsMu.Lock()
	runtime := daemon.dnsServer
	daemon.dnsServer = nil
	daemon.dnsMu.Unlock()
	if err := shutdownDNSServerRuntime(ctx, runtime); err != nil {
		return err
	}
	daemon.dnsMu.Lock()
	defer daemon.dnsMu.Unlock()
	return daemon.startDNSServerLocked(ctx)
}

func shutdownDNSServerRuntime(ctx context.Context, runtime *dnsServerRuntime) error {
	if runtime == nil {
		return nil
	}
	runtime.closing.Store(true)
	var errs []error
	if runtime.UDP != nil {
		if err := runtime.UDP.ShutdownContext(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown dns udp %q: %w", runtime.Listen, err))
		}
	}
	if runtime.TCP != nil {
		if err := runtime.TCP.ShutdownContext(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown dns tcp %q: %w", runtime.Listen, err))
		}
	}
	return errors.Join(errs...)
}

func (daemon *Daemon) dnsStatus() dnsStatus {
	status := dnsStatus{}
	cfg, err := daemon.dnsResolverConfig()
	if err != nil {
		status.Enabled = daemon.desired.DNS.Enabled
		status.Error = err.Error()
		return status
	}
	status.Enabled = cfg.Enabled
	status.DNSMasq = daemon.dnsMasqStatus()
	if !cfg.Enabled {
		return status
	}
	status.Listen = cfg.Listen
	status.Domain = cfg.Domain
	status.TTL = cfg.TTL.String()
	status.Upstreams = append([]string(nil), cfg.Upstreams...)
	status.Capture = cfg.Capture
	daemon.dnsMu.Lock()
	status.Running = daemon.dnsServer != nil
	if daemon.dnsServer != nil {
		status.Listen = daemon.dnsServer.Listen
		status.Domain = daemon.dnsServer.Domain
		status.TTL = daemon.dnsServer.TTL.String()
		status.Upstreams = append([]string(nil), daemon.dnsServer.Upstreams...)
		status.Capture = daemon.dnsServer.Capture
	}
	daemon.dnsMu.Unlock()
	return status
}

func (daemon *Daemon) dnsResolverConfig() (dnsResolverConfig, error) {
	desired := daemon.desired
	if !desired.DNS.Enabled {
		return dnsResolverConfig{}, nil
	}
	listen, err := dnsListenAddressForDesired(desired)
	if err != nil {
		return dnsResolverConfig{}, err
	}
	domain := dnsDomainForDesired(desired)
	ttl := defaultDNSTTL
	if strings.TrimSpace(desired.DNS.TTL) != "" {
		ttl, err = time.ParseDuration(strings.TrimSpace(desired.DNS.TTL))
		if err != nil {
			return dnsResolverConfig{}, fmt.Errorf("parse dns ttl %q: %w", desired.DNS.TTL, err)
		}
	}
	upstreams := append([]string(nil), desired.DNS.Upstreams...)
	return dnsResolverConfig{
		Enabled:   true,
		Listen:    listen,
		Domain:    domain,
		TTL:       ttl,
		Upstreams: upstreams,
		Capture:   desired.DNS.Capture,
	}, nil
}

func dnsListenAddressForDesired(desired config.Desired) (string, error) {
	if !desired.DNS.Enabled {
		return "", nil
	}
	if strings.TrimSpace(desired.DNS.Listen) != "" {
		return strings.TrimSpace(desired.DNS.Listen), nil
	}
	if desired.DNS.DNSMasq.Enabled {
		return net.JoinHostPort("127.0.0.1", dnsOpenWRTDNSMasqPort), nil
	}
	lan, ok := config.FirstLANGatewayLAN(desired)
	if !ok {
		return "", fmt.Errorf("dns listen is not configured and lan gateway is empty")
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(lan.Gateway))
	if err != nil {
		return "", fmt.Errorf("parse lan gateway for dns listen: %w", err)
	}
	return net.JoinHostPort(prefix.Addr().String(), dnsDefaultPort), nil
}

func dnsDomainForDesired(desired config.Desired) string {
	if strings.TrimSpace(desired.DNS.Domain) != "" {
		return strings.ToLower(strings.Trim(strings.TrimSpace(desired.DNS.Domain), "."))
	}
	return strings.ToLower(strings.Trim(string(desired.Domain.ID), "."))
}

func dnsResolverNeedsRestart(oldDesired, newDesired config.Desired) bool {
	if !reflect.DeepEqual(oldDesired.DNS, newDesired.DNS) {
		return true
	}
	if !oldDesired.DNS.Enabled && !newDesired.DNS.Enabled {
		return false
	}
	if oldDesired.Domain.ID != newDesired.Domain.ID {
		return true
	}
	if strings.TrimSpace(oldDesired.DNS.Listen) == "" || strings.TrimSpace(newDesired.DNS.Listen) == "" {
		return !reflect.DeepEqual(effectiveLANGateways(oldDesired), effectiveLANGateways(newDesired))
	}
	return false
}

func (handler *trustIXDNSHandler) ServeDNS(writer mdns.ResponseWriter, request *mdns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsForwardTimeout)
	defer cancel()
	network := "udp"
	if _, ok := writer.RemoteAddr().(*net.TCPAddr); ok {
		network = "tcp"
	}
	response := handler.handleDNSQuery(ctx, request, network)
	if response == nil {
		return
	}
	_ = writer.WriteMsg(response)
}

func (handler *trustIXDNSHandler) handleDNSQuery(ctx context.Context, request *mdns.Msg, network string) *mdns.Msg {
	response := new(mdns.Msg)
	response.SetReply(request)
	response.Compress = true
	response.RecursionAvailable = len(handler.config.Upstreams) > 0
	if request.Opcode != mdns.OpcodeQuery {
		response.SetRcode(request, mdns.RcodeNotImplemented)
		return response
	}
	if len(request.Question) == 0 {
		response.SetRcode(request, mdns.RcodeFormatError)
		return response
	}
	zoneQuestions := make([]mdns.Question, 0, len(request.Question))
	for _, question := range request.Question {
		if handler.nameInZone(question.Name) {
			zoneQuestions = append(zoneQuestions, question)
		}
	}
	if len(zoneQuestions) == 0 {
		return handler.forwardDNSQuery(ctx, request, network)
	}
	response.Authoritative = true
	for _, question := range zoneQuestions {
		handled := handler.answerTrustIXQuestion(response, question)
		if !handled {
			response.SetRcode(request, mdns.RcodeNameError)
			return response
		}
	}
	return response
}

func (handler *trustIXDNSHandler) nameInZone(name string) bool {
	queryName := strings.ToLower(mdns.Fqdn(name))
	suffix := strings.ToLower(mdns.Fqdn(handler.config.Domain))
	return queryName == suffix || strings.HasSuffix(queryName, "."+suffix)
}

func (handler *trustIXDNSHandler) ixIDFromName(name string) (core.IXID, bool) {
	queryName := strings.ToLower(mdns.Fqdn(name))
	suffix := strings.ToLower(mdns.Fqdn(handler.config.Domain))
	if queryName == suffix || !strings.HasSuffix(queryName, suffix) {
		return "", false
	}
	left := strings.TrimSuffix(queryName, suffix)
	left = strings.TrimSuffix(left, ".")
	if left == "" || strings.Contains(left, ".") {
		return "", false
	}
	return core.IXID(left), true
}

func (handler *trustIXDNSHandler) answerTrustIXQuestion(response *mdns.Msg, question mdns.Question) bool {
	ixID, ok := handler.ixIDFromName(question.Name)
	if !ok {
		return false
	}
	if !handler.daemon.dnsIXKnown(ixID) {
		return false
	}
	if question.Qclass != mdns.ClassINET && question.Qclass != mdns.ClassANY {
		return true
	}
	switch question.Qtype {
	case mdns.TypeA, mdns.TypeANY:
	default:
		return true
	}
	addr, ok := handler.daemon.dnsAddressForIX(ixID)
	if !ok || !addr.Is4() {
		return true
	}
	response.Answer = append(response.Answer, &mdns.A{
		Hdr: mdns.RR_Header{
			Name:   mdns.Fqdn(question.Name),
			Rrtype: mdns.TypeA,
			Class:  mdns.ClassINET,
			Ttl:    uint32(handler.config.TTL / time.Second),
		},
		A: net.IP(addr.AsSlice()),
	})
	return true
}

func (handler *trustIXDNSHandler) forwardDNSQuery(ctx context.Context, request *mdns.Msg, network string) *mdns.Msg {
	response := new(mdns.Msg)
	response.SetReply(request)
	response.Compress = true
	response.RecursionAvailable = len(handler.config.Upstreams) > 0
	if len(handler.config.Upstreams) == 0 {
		response.SetRcode(request, mdns.RcodeRefused)
		return response
	}
	queryNet := network
	if queryNet != "tcp" {
		queryNet = "udp"
	}
	var lastErr error
	for _, upstream := range handler.config.Upstreams {
		client := &mdns.Client{Net: queryNet, Timeout: dnsForwardTimeout}
		forwarded, _, err := client.ExchangeContext(ctx, request.Copy(), upstream)
		if err == nil && forwarded != nil {
			if queryNet == "udp" && forwarded.Truncated {
				tcpClient := &mdns.Client{Net: "tcp", Timeout: dnsForwardTimeout}
				if tcpForwarded, _, tcpErr := tcpClient.ExchangeContext(ctx, request.Copy(), upstream); tcpErr == nil && tcpForwarded != nil {
					return tcpForwarded
				}
			}
			return forwarded
		}
		lastErr = err
	}
	if lastErr != nil {
		response.Extra = nil
	}
	response.SetRcode(request, mdns.RcodeServerFailure)
	return response
}

func (daemon *Daemon) dnsIXKnown(ixID core.IXID) bool {
	if ixID == "" {
		return false
	}
	if ixID == daemon.desired.IX.ID {
		return true
	}
	daemon.membershipMu.RLock()
	_, ok := daemon.members[ixID]
	daemon.membershipMu.RUnlock()
	return ok
}

func (daemon *Daemon) dnsAddressForIX(ixID core.IXID) (netip.Addr, bool) {
	if ixID == daemon.desired.IX.ID {
		if addr := daemon.managementHostAPIAddr(); addr.IsValid() && addr.Is4() {
			return addr, true
		}
		if addr, ok := firstLANGatewayAddress(daemon.desired); ok {
			return addr, true
		}
		return netip.Addr{}, false
	}
	daemon.membershipMu.RLock()
	record, ok := daemon.members[ixID]
	daemon.membershipMu.RUnlock()
	if !ok {
		return netip.Addr{}, false
	}
	advertisedAddr := managementVIPFromAdvertisement(record.Advertisement)
	if !advertisedAddr.IsValid() || !advertisedAddr.Is4() {
		return netip.Addr{}, false
	}
	if acceptedAddr, ok := daemon.acceptedManagementVIPRoutes()[ixID]; ok && advertisedAddr == acceptedAddr {
		return advertisedAddr, true
	}
	if daemon.routeAuthorizesDNSAddress(ixID, advertisedAddr) {
		return advertisedAddr, true
	}
	return netip.Addr{}, false
}

func (daemon *Daemon) routeAuthorizesDNSAddress(ixID core.IXID, addr netip.Addr) bool {
	for _, route := range daemon.runtimeRoutes() {
		if route.Kind == routing.RouteBlackhole || route.Kind == routing.RouteReject {
			continue
		}
		if route.Owner != ixID && !(route.Owner == "" && route.NextHop == ixID) {
			continue
		}
		prefix, err := route.Prefix.Parse()
		if err != nil || !prefix.Contains(addr) {
			continue
		}
		return true
	}
	return false
}

func firstLANGatewayAddress(desired config.Desired) (netip.Addr, bool) {
	lan, ok := config.FirstLANGatewayLAN(desired)
	if !ok {
		return netip.Addr{}, false
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(lan.Gateway))
	if err != nil || !prefix.Addr().Is4() {
		return netip.Addr{}, false
	}
	return prefix.Addr(), true
}
