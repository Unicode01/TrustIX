// Package daemon wires the high-level TrustIX runtime components. Real config
// loading, peer networking, and BPF attachment will be added behind the package
// boundaries defined in internal packages.
package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/dataplane/ebpf"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
	experimentaltcptransport "trustix.local/trustix/internal/transport/experimentaltcp"
	httpconnecttransport "trustix.local/trustix/internal/transport/httpconnect"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
	quictransport "trustix.local/trustix/internal/transport/quic"
	securetransport "trustix.local/trustix/internal/transport/secure"
	tcptransport "trustix.local/trustix/internal/transport/tcp"
	udptransport "trustix.local/trustix/internal/transport/udp"
	websockettransport "trustix.local/trustix/internal/transport/websocket"
)

type Config struct {
	ConfigPath    string
	DataDir       string
	APIAddr       string
	PeerAPIAddr   string
	DataplaneMode string
	APIAdminAuth  bool
	DomainID      core.DomainID
	IXID          core.IXID
}

type Daemon struct {
	cfg                  Config
	dataplane            dataplane.Manager
	kernelCrypto         *kernelmodule.Manager
	kernelDatapath       *kernelmodule.Manager
	kernelHelpers        *kernelmodule.Manager
	kernelSysctlRestore  map[string]string
	routes               *routing.Table
	transports           *transport.Registry
	desired              config.Desired
	store                configlog.Store
	logPath              string
	dataDirLock          heldDataDirLock
	head                 configlog.Head
	startedAt            time.Time
	runCtx               context.Context
	configMu             sync.RWMutex
	configSyncMu         sync.RWMutex
	controlClientMu      sync.Mutex
	controlViewMu        sync.Mutex
	controlClients       map[string]*cachedControlClient
	controlMembers       map[string]cachedControlMembers
	controlMemberCursors map[string]string
	controlAdPush        map[string]cachedAdvertisementPush
	controlTargetCursor  atomic.Uint64
	controlView          controlViewSnapshot
	cryptoPlacement      atomic.Uint32
	secureKeySource      atomic.Uint32
	secureEncryption     atomic.Uint32
	secureSuites         atomic.Value
	configSync           map[string]configSyncPeerState
	signerMu             sync.RWMutex
	signerCerts          map[core.SignerID]*x509.Certificate
	peerMu               sync.RWMutex
	peerState            map[core.IXID]peerRuntime
	membershipMu         sync.RWMutex
	membershipDiskMu     sync.Mutex
	members              map[core.IXID]memberRecord
	pendingMembers       map[core.IXID]pendingMemberRecord
	provisionMu          sync.Mutex
	provisionLoaded      bool
	provisionTokens      map[string]ixProvisionTokenRecord
	localAd              advertisementResponse
	runtimeEpoch         uint64
	dataMu               sync.Mutex
	dataStats            dataPathStats
	dataMetrics          dataPathMetrics
	dataSessions         map[dataSessionKey]transport.Session
	dataSessionState     map[dataSessionKey]*dataSessionRuntime
	deviceLeases         map[deviceLeaseKey]deviceAccessLease
	sessionPoolRR        map[dataSessionPoolKey]uint64
	sessionPoolFlow      map[dataSessionFlowPoolKey]int
	dataSessionEpoch     uint64
	routeWarmupEpoch     atomic.Uint64
	forwardCacheMu       sync.RWMutex
	forwardCache         map[routing.FlowKey]*dataForwardCacheEntry
	dataPathStarted      bool
	dataListeners        []dataListenerRuntime
	captureCancel        context.CancelFunc
	captureSub           dataplane.CaptureSubscription
	kernelRXStage        kernelDatapathRXStageRuntime
	localLAN             atomic.Value
	flowMu               sync.RWMutex
	flows                map[routing.FlowKey]routing.FlowBinding
	nat                  *natTable
	endpointMu           sync.Mutex
	endpointState        map[endpointStateKey]rstate.EndpointState
	apiMu                sync.Mutex
	apiErr               chan error
	apiServers           []apiServerRuntime
	dnsMu                sync.Mutex
	dnsServer            *dnsServerRuntime
}

type Option func(*Daemon)

type apiServerRuntime struct {
	Name   string
	Listen string
	TLS    bool
	Server *http.Server
}

const (
	apiServerPrimary = "management"
	apiServerHost    = "host_management"

	managementHTTPReadHeaderTimeout = 5 * time.Second
	managementHTTPWriteTimeout      = 2 * time.Minute
	managementHTTPIdleTimeout       = 90 * time.Second
	peerHTTPReadHeaderTimeout       = 5 * time.Second
	peerHTTPWriteTimeout            = 2 * time.Minute
	peerHTTPIdleTimeout             = 90 * time.Second
	httpMaxHeaderBytes              = 1 << 20
)

func DefaultConfig() Config {
	return Config{
		ConfigPath:    "configs/lab-a.yaml",
		DataDir:       ".trustix",
		APIAddr:       "127.0.0.1:8787",
		PeerAPIAddr:   "127.0.0.1:9443",
		DataplaneMode: "noop",
	}
}

func WithDataplane(manager dataplane.Manager) Option {
	return func(daemon *Daemon) {
		daemon.dataplane = manager
	}
}

func New(cfg Config, options ...Option) (*Daemon, error) {
	daemon := &Daemon{
		cfg:                  cfg,
		dataplane:            selectDataplane(cfg.DataplaneMode),
		kernelCrypto:         kernelmodule.NewTrustIXCryptoManager(),
		kernelDatapath:       kernelmodule.NewTrustIXDatapathManager(),
		kernelHelpers:        kernelmodule.NewTrustIXDatapathHelpersManager(),
		routes:               routing.NewTable(),
		transports:           transport.NewRegistry(),
		configSync:           make(map[string]configSyncPeerState),
		controlClients:       make(map[string]*cachedControlClient),
		controlMembers:       make(map[string]cachedControlMembers),
		controlMemberCursors: make(map[string]string),
		signerCerts:          make(map[core.SignerID]*x509.Certificate),
		peerState:            make(map[core.IXID]peerRuntime),
		members:              make(map[core.IXID]memberRecord),
		pendingMembers:       make(map[core.IXID]pendingMemberRecord),
		provisionTokens:      make(map[string]ixProvisionTokenRecord),
		dataSessions:         make(map[dataSessionKey]transport.Session),
		dataSessionState:     make(map[dataSessionKey]*dataSessionRuntime),
		deviceLeases:         make(map[deviceLeaseKey]deviceAccessLease),
		flows:                make(map[routing.FlowKey]routing.FlowBinding),
		nat:                  newNATTable(),
		endpointState:        make(map[endpointStateKey]rstate.EndpointState),
	}
	for _, option := range options {
		option(daemon)
	}
	if daemon.dataplane == nil {
		return nil, fmt.Errorf("unsupported dataplane mode %q", cfg.DataplaneMode)
	}
	secureOptions := securetransport.Options{
		KeySource:     daemon.secureTransportKeySource,
		Encryption:    daemon.secureTransportEncryption,
		CryptoSuites:  daemon.secureTransportCryptoSuites,
		ClientAuthTLS: daemon.secureClientAuthTLSConfig,
		ServerAuthTLS: daemon.secureServerAuthTLSConfig,
	}
	udpTransport := udptransport.New(udptransport.Options{
		CryptoPlacement:          daemon.transportCryptoPlacement,
		KernelTransport:          daemon.kernelTransportMode,
		Encryption:               daemon.secureTransportEncryption,
		RequireSecureClientHello: true,
	})
	if provider, ok := daemon.dataplane.(dataplane.KernelUDPProvider); ok {
		udpTransport = udptransport.NewWithKernelProvider(provider, udptransport.Options{
			CryptoPlacement:          daemon.transportCryptoPlacement,
			KernelTransport:          daemon.kernelTransportMode,
			Encryption:               daemon.secureTransportEncryption,
			RequireSecureClientHello: true,
		})
	}
	if err := daemon.transports.Register(securetransport.New(udpTransport, secureOptions)); err != nil {
		return nil, err
	}
	if err := daemon.transports.Register(securetransport.New(tcptransport.New(), secureOptions)); err != nil {
		return nil, err
	}
	if err := daemon.transports.Register(securetransport.New(quictransport.New(), secureOptions)); err != nil {
		return nil, err
	}
	if err := daemon.transports.Register(securetransport.New(websockettransport.New(), secureOptions)); err != nil {
		return nil, err
	}
	if err := daemon.transports.Register(securetransport.New(httpconnecttransport.New(), secureOptions)); err != nil {
		return nil, err
	}
	tunnelManager := iptunneltransport.NewManager(cfg.DataDir)
	if err := daemon.transports.Register(securetransport.New(iptunneltransport.NewGREWithManager(tunnelManager), secureOptions)); err != nil {
		return nil, err
	}
	if err := daemon.transports.Register(securetransport.New(iptunneltransport.NewIPIPWithManager(tunnelManager), secureOptions)); err != nil {
		return nil, err
	}
	if err := daemon.transports.Register(securetransport.New(iptunneltransport.NewVXLANWithManager(tunnelManager), secureOptions)); err != nil {
		return nil, err
	}
	if provider, ok := daemon.dataplane.(dataplane.ExperimentalTCPProvider); ok {
		if err := daemon.transports.Register(securetransport.New(experimentaltcptransport.New(provider, experimentaltcptransport.Options{
			CryptoPlacement: daemon.transportCryptoPlacement,
			Encryption:      daemon.secureTransportEncryption,
		}), secureOptions)); err != nil {
			return nil, err
		}
	}
	return daemon, nil
}

func selectDataplane(mode string) dataplane.Manager {
	switch mode {
	case "", "noop":
		return dataplane.NewNoopManager()
	case "linux":
		return ebpf.NewManager()
	case "auto":
		if runtime.GOOS == "linux" {
			return ebpf.NewManager()
		}
		return dataplane.NewNoopManager()
	default:
		return nil
	}
}

func (daemon *Daemon) Run(ctx context.Context) error {
	daemon.runCtx = ctx
	daemon.startedAt = time.Now().UTC()
	lock, err := acquireDataDirLock(daemon.cfg.DataDir)
	if err != nil {
		return err
	}
	daemon.dataDirLock = lock
	if err := daemon.loadAndApply(ctx); err != nil {
		detachErr := daemon.dataplane.Detach(context.Background())
		moduleErr := daemon.closeKernelModules(context.Background())
		daemon.releaseDataDirLock()
		return errors.Join(err, detachErr, moduleErr)
	}

	apiErr, err := daemon.startAPIServers()
	if err != nil {
		detachErr := daemon.dataplane.Detach(context.Background())
		moduleErr := daemon.closeKernelModules(context.Background())
		daemon.releaseDataDirLock()
		return errors.Join(err, detachErr, moduleErr)
	}
	defer daemon.releaseDataDirLock()
	var peerServer *http.Server
	cleanup := func() error {
		return daemon.shutdownRuntime(peerServer, true)
	}
	if err := daemon.startDNSServer(ctx); err != nil {
		return errors.Join(err, cleanup())
	}
	if err := daemon.syncDNSMasq(ctx); err != nil {
		return errors.Join(err, cleanup())
	}
	peerServer, peerErr, err := daemon.startPeerAPIServer()
	if err != nil {
		return errors.Join(err, cleanup())
	}
	dataErr, err := daemon.startDataPath(ctx)
	if err != nil {
		return errors.Join(err, cleanup())
	}
	go daemon.peerPoller(ctx)
	go daemon.endpointHealthPoller(ctx)
	go daemon.endpointGrantExpiryReaper(ctx)
	go daemon.deviceAccessExpiryReaper(ctx)
	go daemon.apiServerWatchdog(ctx)

	select {
	case <-ctx.Done():
		return cleanup()
	case err := <-dataErr:
		if err != nil {
			return errors.Join(fmt.Errorf("data path: %w", err), cleanup())
		}
		return cleanup()
	case err := <-apiErr:
		if err != nil {
			return errors.Join(err, cleanup())
		}
		return cleanup()
	case err := <-peerErr:
		if err != nil {
			return errors.Join(fmt.Errorf("serve peer api: %w", err), cleanup())
		}
		return cleanup()
	}
}

func (daemon *Daemon) shutdownRuntime(peerServer *http.Server, detach bool) error {
	daemon.closeControlClients()
	daemon.stopKernelDatapathRXStage()
	daemon.closeCaptureForwarder()
	daemon.closeDataPath()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var errs []error
	if err := daemon.closeAPIServers(shutdownCtx); err != nil {
		errs = append(errs, err)
	}
	if err := daemon.cleanupDNSMasq(shutdownCtx); err != nil {
		errs = append(errs, err)
	}
	if err := daemon.closeDNSServer(shutdownCtx); err != nil {
		errs = append(errs, err)
	}
	if peerServer != nil {
		if err := peerServer.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown peer api: %w", err))
		}
	}
	if detach && daemon.dataplane != nil {
		if err := daemon.dataplane.Detach(context.Background()); err != nil {
			errs = append(errs, fmt.Errorf("detach dataplane: %w", err))
		}
	}
	if detach {
		if _, err := iptunneltransport.NewManager(daemon.cfg.DataDir).Cleanup(context.Background()); err != nil {
			errs = append(errs, fmt.Errorf("cleanup ip tunnels: %w", err))
		}
	}
	if detach {
		if err := daemon.closeKernelModules(context.Background()); err != nil {
			errs = append(errs, fmt.Errorf("close kernel modules: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (daemon *Daemon) releaseDataDirLock() {
	if daemon.dataDirLock == nil {
		return
	}
	_ = daemon.dataDirLock.Close()
	daemon.dataDirLock = nil
}

func (daemon *Daemon) startAPIServers() (<-chan error, error) {
	errc := make(chan error, 1)
	daemon.apiMu.Lock()
	daemon.apiErr = errc
	var startErr error
	if startErr = daemon.startAPIServerLocked(apiServerPrimary, daemon.cfg.APIAddr, daemon.handler()); startErr == nil {
		startErr = daemon.startHostAPIServerLocked()
	}
	if startErr == nil {
		startErr = daemon.startManagementVIPAPIServersLocked(context.Background())
	}
	if startErr != nil {
		servers := daemon.takeAPIServersLocked("")
		daemon.apiErr = nil
		daemon.apiMu.Unlock()
		_ = shutdownAPIServerRuntimes(context.Background(), servers)
		return nil, startErr
	}
	daemon.apiMu.Unlock()
	return errc, nil
}

func (daemon *Daemon) startHostAPIServerLocked() error {
	if !daemon.managementHostAPIEnabled() {
		return nil
	}
	listen, err := daemon.managementHostAPIListenAddress()
	if err != nil {
		return err
	}
	if runtime, ok := daemon.apiServerCoveringListenLocked(listen); ok {
		daemon.apiServers = append(daemon.apiServers, apiServerRuntime{
			Name:   apiServerHost,
			Listen: listen,
			TLS:    runtime.TLS,
		})
		return nil
	}
	return daemon.startAPIServerLocked(apiServerHost, listen, daemon.hostAPIHandler())
}

func (daemon *Daemon) apiServerCoveringListenLocked(listen string) (apiServerRuntime, bool) {
	for _, runtime := range daemon.apiServers {
		if runtime.Server == nil {
			continue
		}
		if apiServerListenCovers(runtime.Listen, listen) {
			return runtime, true
		}
	}
	return apiServerRuntime{}, false
}

func apiServerListenCovers(existing, requested string) bool {
	existing = strings.TrimSpace(existing)
	requested = strings.TrimSpace(requested)
	if existing == "" || requested == "" {
		return false
	}
	if existing == requested {
		return true
	}
	existingHost, existingPort, err := net.SplitHostPort(existing)
	if err != nil {
		return false
	}
	requestedHost, requestedPort, err := net.SplitHostPort(requested)
	if err != nil || existingPort != requestedPort {
		return false
	}
	if existingHost == requestedHost {
		return true
	}
	existingAddr, err := netip.ParseAddr(existingHost)
	if err != nil {
		if existingHost != "" {
			return false
		}
	} else if !existingAddr.IsUnspecified() {
		return false
	}
	if requestedHost == "" {
		return true
	}
	requestedAddr, err := netip.ParseAddr(requestedHost)
	if err != nil {
		return false
	}
	if existingHost == "" {
		return true
	}
	if existingAddr.Is4() {
		return requestedAddr.Is4()
	}
	return existingAddr.Is6() && requestedAddr.Is6()
}

func (daemon *Daemon) startAPIServerLocked(name string, listen string, handler http.Handler) error {
	listener, err := listenTCP(context.Background(), listen)
	if err != nil {
		return fmt.Errorf("listen %s api %q: %w", name, listen, err)
	}
	tlsEnabled := daemon.managementTLSEnabledForListen(listen)
	if tlsEnabled {
		tlsConf, err := daemon.managementServerTLSConfig()
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("configure %s api TLS %q: %w", name, listen, err)
		}
		listener = tls.NewListener(listener, tlsConf)
	}
	server := newManagementHTTPServer(handler)
	daemon.apiServers = append(daemon.apiServers, apiServerRuntime{
		Name:   name,
		Listen: listen,
		TLS:    tlsEnabled,
		Server: server,
	})
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			daemon.reportAPIServerError(name, listen, err)
		}
	}()
	return nil
}

func (daemon *Daemon) reportAPIServerError(name string, listen string, err error) {
	daemon.apiMu.Lock()
	errc := daemon.apiErr
	daemon.apiMu.Unlock()
	if errc == nil {
		return
	}
	select {
	case errc <- fmt.Errorf("serve %s api %q: %w", name, listen, err):
	default:
	}
}

func (daemon *Daemon) closeAPIServers(ctx context.Context) error {
	daemon.apiMu.Lock()
	servers := daemon.takeAPIServersLocked("")
	daemon.apiErr = nil
	daemon.apiMu.Unlock()
	return shutdownAPIServerRuntimes(ctx, servers)
}

func (daemon *Daemon) restartHostAPIServers(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	daemon.apiMu.Lock()
	if daemon.apiErr == nil {
		daemon.apiMu.Unlock()
		return nil
	}
	servers := daemon.takeAPIServersLocked(apiServerHost)
	daemon.apiMu.Unlock()
	if err := shutdownAPIServerRuntimes(ctx, servers); err != nil {
		return err
	}
	daemon.apiMu.Lock()
	err := daemon.startHostAPIServerLocked()
	daemon.apiMu.Unlock()
	return err
}

func (daemon *Daemon) restartAPIServersSoon() {
	go func() {
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-daemon.runCtxDone():
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		daemon.apiMu.Lock()
		if daemon.apiErr == nil {
			daemon.apiMu.Unlock()
			return
		}
		servers := daemon.takeAPIServersLocked("")
		daemon.apiMu.Unlock()
		if err := shutdownAPIServerRuntimes(shutdownCtx, servers); err != nil {
			daemon.reportAPIServerError(apiServerPrimary, daemon.cfg.APIAddr, err)
			return
		}
		daemon.apiMu.Lock()
		if daemon.apiErr == nil {
			daemon.apiMu.Unlock()
			return
		}
		err := daemon.startAPIServerLocked(apiServerPrimary, daemon.cfg.APIAddr, daemon.handler())
		if err == nil {
			err = daemon.startHostAPIServerLocked()
		}
		if err == nil {
			err = daemon.startManagementVIPAPIServersLocked(context.Background())
		}
		daemon.apiMu.Unlock()
		if err != nil {
			daemon.reportAPIServerError(apiServerPrimary, daemon.cfg.APIAddr, err)
		}
	}()
}

func (daemon *Daemon) apiServerWatchdog(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = daemon.ensureHostAPIServerReachable(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (daemon *Daemon) ensureHostAPIServerReachable(ctx context.Context) error {
	if !daemon.managementHostAPIEnabled() {
		return nil
	}
	listen, err := daemon.managementHostAPIListenAddress()
	if err != nil {
		return err
	}
	if daemon.managementAPIReachable(ctx, listen) {
		return nil
	}
	restartCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return daemon.restartHostAPIServers(restartCtx)
}

func (daemon *Daemon) managementAPIReachable(ctx context.Context, listen string) bool {
	target, err := daemon.managementAPIProbeURL(listen)
	if err != nil {
		return false
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	transport := &http.Transport{}
	if daemon.managementTLSEnabledForListen(listen) {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{Timeout: time.Second, Transport: transport}
	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

func (daemon *Daemon) managementAPIProbeURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	addr := host
	if addr == "" {
		addr = "127.0.0.1"
	} else if parsed, err := netip.ParseAddr(host); err == nil && parsed.IsUnspecified() {
		if parsed.Is6() {
			addr = "::1"
		} else {
			addr = "127.0.0.1"
		}
	}
	scheme := daemon.managementAPIScheme(listen)
	return scheme + "://" + net.JoinHostPort(addr, port) + "/", nil
}

func (daemon *Daemon) runCtxDone() <-chan struct{} {
	if daemon.runCtx == nil {
		return nil
	}
	return daemon.runCtx.Done()
}

func (daemon *Daemon) takeAPIServersLocked(name string) []apiServerRuntime {
	if len(daemon.apiServers) == 0 {
		return nil
	}
	taken := make([]apiServerRuntime, 0, len(daemon.apiServers))
	kept := daemon.apiServers[:0]
	for _, server := range daemon.apiServers {
		if name == "" || server.Name == name {
			taken = append(taken, server)
			continue
		}
		kept = append(kept, server)
	}
	daemon.apiServers = kept
	return taken
}

func shutdownAPIServerRuntimes(ctx context.Context, servers []apiServerRuntime) error {
	var errs []error
	for _, runtime := range servers {
		if runtime.Server == nil {
			continue
		}
		if err := runtime.Server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown %s api %q: %w", runtime.Name, runtime.Listen, err))
		}
	}
	return errors.Join(errs...)
}

func (daemon *Daemon) startPeerAPIServer() (*http.Server, <-chan error, error) {
	if daemon.cfg.PeerAPIAddr == "" {
		return nil, nil, nil
	}
	errc := make(chan error, 1)
	tlsConf, err := daemon.peerServerTLSConfig()
	if err != nil {
		return nil, nil, err
	}
	listener, err := listenTCP(context.Background(), daemon.cfg.PeerAPIAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen peer api %q: %w", daemon.cfg.PeerAPIAddr, err)
	}
	listener = tls.NewListener(listener, tlsConf)
	server := newPeerHTTPServer(daemon.peerHandler())
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
		close(errc)
	}()
	return server, errc, nil
}

func newManagementHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: managementHTTPReadHeaderTimeout,
		WriteTimeout:      managementHTTPWriteTimeout,
		IdleTimeout:       managementHTTPIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

func newPeerHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: peerHTTPReadHeaderTimeout,
		WriteTimeout:      peerHTTPWriteTimeout,
		IdleTimeout:       peerHTTPIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

func listenTCP(ctx context.Context, listen string) (net.Listener, error) {
	return (&net.ListenConfig{KeepAlive: serverTCPKeepAlive()}).Listen(ctx, "tcp", listen)
}

func (daemon *Daemon) loadAndApply(ctx context.Context) error {
	desired, err := config.LoadFile(daemon.cfg.ConfigPath)
	if err != nil {
		return err
	}
	if err := verifyLocalRouteAuthorizations(desired); err != nil {
		return err
	}
	daemon.desired = desired
	daemon.configureNATTable()
	daemon.configureLocalLANCache(desired)
	daemon.setTransportCryptoPlacement(desired.TransportPolicy)
	daemon.setSecureTransportKeySource(desired.TransportPolicy.CryptoKeySource)
	daemon.setSecureTransportEncryption(desired.TransportPolicy.Encryption)
	daemon.setSecureTransportCryptoSuites(desired.TransportPolicy.CryptoSuites)
	daemon.cfg.DomainID = desired.Domain.ID
	daemon.cfg.IXID = desired.IX.ID
	if _, err := daemon.ensureKernelModules(ctx, desired); err != nil {
		return err
	}

	storePath := desired.IX.ConfigLog
	if storePath == "" {
		storePath = filepath.Join(daemon.cfg.DataDir, "config.log")
	}
	store, err := configlog.NewFileStore(storePath)
	if err != nil {
		return err
	}
	daemon.store = store
	daemon.logPath = storePath

	if err := daemon.registerLocalConfigSigner(); err != nil {
		return err
	}
	if err := daemon.loadConfigSignerCache(); err != nil {
		return err
	}
	if err := daemon.loadPersistedMembers(); err != nil {
		return err
	}
	if err := daemon.ensureConfigGenesisEvent(desired); err != nil {
		return err
	}
	if err := daemon.verifyExistingConfigLog(store, desired); err != nil {
		return err
	}
	head, err := store.Head()
	if err != nil {
		return err
	}
	daemon.head = head
	if _, err := daemon.applyLatestDomainTrustFromLogLocked(ctx); err != nil {
		return err
	}
	if err := daemon.restoreLatestLocalDesiredFromLogLocked(ctx); err != nil {
		return err
	}
	if err := daemon.loadPersistedPendingMembers(); err != nil {
		return err
	}
	_ = daemon.pruneExpiredPendingMembers()
	_ = daemon.admitPendingMembers()
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		return err
	}

	runtimeSnapshot := daemon.runtimeDataplaneSnapshot()
	if err := daemon.routes.Replace(runtimeSnapshot.Routes); err != nil {
		return err
	}
	if err := daemon.loadAttachDataplane(ctx, desired); err != nil {
		return err
	}
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		return err
	}
	return nil
}

func (daemon *Daemon) loadAttachDataplane(ctx context.Context, desired config.Desired) error {
	if err := daemon.dataplane.Load(ctx); err != nil {
		return fmt.Errorf("load dataplane: %w", err)
	}
	if err := daemon.attachDataplane(ctx, desired); err != nil {
		return err
	}
	return nil
}

func (daemon *Daemon) attachDataplane(ctx context.Context, desired config.Desired) error {
	if err := daemon.dataplane.Attach(ctx, dataplaneAttachSpec(daemon.cfg.DataDir, desired)); err != nil {
		return fmt.Errorf("attach dataplane: %w", err)
	}
	snapshot := daemon.runtimeDataplaneSnapshot()
	if err := daemon.dataplane.ApplySnapshot(ctx, snapshot); err != nil {
		return fmt.Errorf("apply initial dataplane snapshot: %w", err)
	}
	daemon.syncKernelDatapathState(ctx, snapshot)
	return nil
}

func dataplaneAttachSpec(dataDir string, desired config.Desired) dataplane.AttachSpec {
	lan := config.PrimaryLAN(desired)
	lanSpec := dataplaneLANAttachSpec(lan, desired)
	secureFullDirect := kernelUDPSecureFullDirectForDesired(desired)
	experimentalTCPRouteGSOAsync := experimentalTCPPerformanceRouteGSOAsyncForDesired(desired)
	experimentalTCPFastPathDisabledReason := experimentalTCPFastPathDisabledReasonForDesired(desired)
	return dataplane.AttachSpec{
		LANIface:                                 lanSpec.Iface,
		UnderlayIface:                            lanSpec.UnderlayIface,
		Gateway:                                  lanSpec.Gateway,
		LANAttachMode:                            lanSpec.LANAttachMode,
		ManageQdisc:                              lanSpec.ManageQdisc,
		ManageAddress:                            lanSpec.ManageAddress,
		ManageForwarding:                         lanSpec.ManageForwarding,
		ManageRPFilter:                           lanSpec.ManageRPFilter,
		ManagedMTU:                               lanSpec.ManagedMTU,
		KernelUDPTXDirectOnly:                    kernelUDPTXDirectOnlyAttachForDesired(desired),
		KernelUDPTXDirectOnlyReason:              kernelUDPTXDirectOnlyAttachReasonForDesired(desired),
		KernelUDPTXSecureDirect:                  secureFullDirect,
		KernelUDPRXSecureDirect:                  secureFullDirect,
		KernelUDPSecureDirectTrustInnerChecksums: secureFullDirect,
		KernelUDPTXSecureDirectKfuncSeal:         secureFullDirect,
		KernelUDPTXSecureDirectSKBSealKfunc:      secureFullDirect,
		ExperimentalTCPTXDirect:                  experimentalTCPTXDirectForDesired(desired),
		ExperimentalTCPRouteGSOSync:              experimentalTCPRouteGSOAsync,
		ExperimentalTCPRouteGSOAsync:             experimentalTCPRouteGSOAsync,
		ExperimentalTCPRouteXmitWorker:           experimentalTCPRouteGSOAsync,
		ExperimentalTCPPlainSkipSequence:         experimentalTCPRouteGSOAsync,
		ExperimentalTCPPlainACKOnly:              experimentalTCPRouteGSOAsync,
		ExperimentalTCPFastPathDisabled:          experimentalTCPFastPathDisabledReason != "",
		ExperimentalTCPFastPathDisabledReason:    experimentalTCPFastPathDisabledReason,
		PinPath:                                  filepath.Join(dataDir, "bpf"),
		DataDir:                                  dataDir,
		LANs:                                     dataplaneLANAttachSpecs(desired),
	}
}

func dataplaneLANAttachSpecs(desired config.Desired) []dataplane.LANAttachSpec {
	lans := config.EffectiveLANs(desired)
	if len(lans) == 0 {
		return nil
	}
	out := make([]dataplane.LANAttachSpec, 0, len(lans))
	for _, lan := range lans {
		out = append(out, dataplaneLANAttachSpec(lan, desired))
	}
	return out
}

func dataplaneLANAttachSpec(lan config.LANConfig, desired config.Desired) dataplane.LANAttachSpec {
	attachMode := lan.AttachMode
	if attachMode == "" {
		attachMode = config.LANAttachModeManaged
	}
	manageAddress := lan.ManageAddress
	if attachMode == config.LANAttachModeExisting {
		manageAddress = false
	}
	manageQdisc := lan.Iface != "" &&
		!nativePlaintextKernelTunnelRouteOffloadForDesired(desired) &&
		!kernelDatapathFullPlaintextEnabledForDesired(desired)
	managedMTU := 0
	if !manageQdisc && manageAddress && nativeTunnelManagedLANMTUEnabled() {
		managedMTU = nativePlaintextKernelTunnelMTUForDesired(desired)
	}
	return dataplane.LANAttachSpec{
		ID:               lan.ID,
		Type:             string(lan.Type),
		Iface:            lan.Iface,
		UnderlayIface:    lan.UnderlayIface,
		Gateway:          lan.Gateway,
		LANAttachMode:    string(attachMode),
		ManageQdisc:      manageQdisc,
		ManageAddress:    manageAddress,
		ManageForwarding: lan.ManageForwarding,
		ManageRPFilter:   lan.ManageRPFilter,
		ManagedMTU:       managedMTU,
		Advertise:        append([]core.Prefix(nil), lan.Advertise...),
		DeviceAccess:     lan.DeviceAccess.Enabled,
		DeviceAccessPool: lan.DeviceAccess.AddressPool,
	}
}

func (daemon *Daemon) appendDesiredEventIfChanged(desired config.Desired) error {
	event, _, changed, err := daemon.desiredEventIfChanged(desired, nil)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if err := daemon.store.Append(*event); err != nil {
		return fmt.Errorf("append desired config event: %w", err)
	}
	return nil
}

func (daemon *Daemon) desiredEventIfChanged(desired config.Desired, adminProofs []configlog.AdminProof) (*configlog.Event, configlog.Head, bool, error) {
	payload, err := json.Marshal(desired)
	if err != nil {
		return nil, configlog.Head{}, false, fmt.Errorf("encode desired config: %w", err)
	}
	head, err := daemon.store.Head()
	if err != nil {
		return nil, configlog.Head{}, false, err
	}
	return daemon.desiredEventIfChangedAtHead(desired, adminProofs, head, payload)
}

func (daemon *Daemon) desiredEventIfChangedAtHead(desired config.Desired, adminProofs []configlog.AdminProof, head configlog.Head, payload []byte) (*configlog.Event, configlog.Head, bool, error) {
	storeHead, err := daemon.store.Head()
	if err != nil {
		return nil, configlog.Head{}, false, err
	}
	if storeHead.Seq > 0 {
		events, err := daemon.store.Range(1, storeHead.Seq)
		if err != nil {
			return nil, configlog.Head{}, false, err
		}
		resource := desiredResourceForIX(desired.IX.ID)
		for i := len(events) - 1; i >= 0; i-- {
			if events[i].Resource == resource || events[i].Resource == "/desired" && desired.IX.ID == daemon.desired.IX.ID {
				if bytes.Equal(events[i].Payload, payload) {
					return nil, head, false, nil
				}
				break
			}
		}
	}
	return daemon.signedConfigEventAtHead(desiredResourceForIX(desired.IX.ID), configlog.ActionUpsert, payload, desired, adminProofs, head)
}

func (daemon *Daemon) signedConfigEventAtHead(resource core.ResourcePath, action configlog.Action, payload []byte, signerDesired config.Desired, adminProofs []configlog.AdminProof, head configlog.Head) (*configlog.Event, configlog.Head, bool, error) {
	prevHash := head.Hash
	eventID, err := newEventID()
	if err != nil {
		return nil, configlog.Head{}, false, err
	}
	now := time.Now().UTC()
	event := configlog.Event{
		DomainID:    signerDesired.Domain.ID,
		EventID:     core.EventID(eventID),
		Seq:         head.Seq + 1,
		PrevHash:    prevHash,
		Resource:    resource,
		Action:      action,
		Payload:     payload,
		SignerID:    core.SignerID("ix:" + string(signerDesired.IX.ID)),
		CreatedAt:   now,
		EffectiveAt: now,
		AdminProofs: append([]configlog.AdminProof(nil), adminProofs...),
	}
	if err := signConfigEvent(&event, signerDesired); err != nil {
		return nil, configlog.Head{}, false, err
	}
	hash, err := event.Hash()
	if err != nil {
		return nil, configlog.Head{}, false, err
	}
	return &event, configlog.Head{Seq: event.Seq, Hash: hash}, true, nil
}

func (daemon *Daemon) latestResourcePayload(resource core.ResourcePath) ([]byte, bool, error) {
	head, err := daemon.store.Head()
	if err != nil || head.Seq == 0 {
		return nil, false, err
	}
	events, err := daemon.store.Range(1, head.Seq)
	if err != nil {
		return nil, false, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Resource == resource {
			return events[i].Payload, true, nil
		}
	}
	return nil, false, nil
}

func signConfigEvent(event *configlog.Event, desired config.Desired) error {
	if desired.IX.CertPath == "" || desired.IX.KeyPath == "" {
		return fmt.Errorf("ix cert and key are required to sign config events")
	}
	bundle, err := pki.LoadBundle(desired.IX.CertPath, desired.IX.KeyPath)
	if err != nil {
		return err
	}
	if err := verifyCertificateNotRevokedByDesired(desired, bundle.Cert, "config signer certificate"); err != nil {
		return err
	}
	meta := pki.ParseMetadata(bundle.Cert)
	if meta.Role != pki.RoleIX {
		return fmt.Errorf("signer certificate role is %q, want %q", meta.Role, pki.RoleIX)
	}
	if meta.Domain != string(desired.Domain.ID) {
		return fmt.Errorf("signer certificate domain is %q, want %q", meta.Domain, desired.Domain.ID)
	}
	if meta.IX != string(desired.IX.ID) {
		return fmt.Errorf("signer certificate ix is %q, want %q", meta.IX, desired.IX.ID)
	}
	payload, err := event.SigningBytes()
	if err != nil {
		return err
	}
	signature, err := pki.Sign(bundle.Key, payload)
	if err != nil {
		return err
	}
	if err := pki.Verify(bundle.Cert, payload, signature); err != nil {
		return err
	}
	event.Signature = signature
	return nil
}

func (daemon *Daemon) peerServerTLSConfig() (*tls.Config, error) {
	return daemon.peerServerTLSConfigWithRoles(map[pki.Role]struct{}{
		pki.RoleIX: {},
	})
}

func (daemon *Daemon) dataTransportPeerServerTLSConfig() (*tls.Config, error) {
	roles := map[pki.Role]struct{}{
		pki.RoleIX: {},
	}
	if daemon.deviceAccessEnabled() {
		roles[pki.RoleDevice] = struct{}{}
	}
	return daemon.peerServerTLSConfigWithRoles(roles)
}

func (daemon *Daemon) peerServerTLSConfigWithRoles(allowedRoles map[pki.Role]struct{}) (*tls.Config, error) {
	cert, err := loadTLSCertificateChecked(daemon.desired, daemon.desired.IX.CertPath, daemon.desired.IX.KeyPath, "local peer API certificate")
	if err != nil {
		return nil, fmt.Errorf("load peer api certificate: %w", err)
	}
	pool, err := daemon.trustPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer client certificate is required")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if err := daemon.verifyCertificateNotRevoked(cert, "peer client certificate"); err != nil {
				return err
			}
			meta := pki.ParseMetadata(cert)
			if _, ok := allowedRoles[meta.Role]; !ok {
				return fmt.Errorf("peer client certificate role is %q, want one of %s", meta.Role, roleSetString(allowedRoles))
			}
			if meta.Domain != string(daemon.desired.Domain.ID) {
				return fmt.Errorf("peer client certificate domain is %q, want %q", meta.Domain, daemon.desired.Domain.ID)
			}
			return nil
		},
	}, nil
}

func roleSetString(roles map[pki.Role]struct{}) string {
	if len(roles) == 0 {
		return ""
	}
	values := make([]string, 0, len(roles))
	for role := range roles {
		values = append(values, string(role))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func (daemon *Daemon) peerClientTLSConfig(peer config.PeerConfig) (*tls.Config, error) {
	cert, err := loadTLSCertificateChecked(daemon.desired, daemon.desired.IX.CertPath, daemon.desired.IX.KeyPath, "local peer client certificate")
	if err != nil {
		return nil, fmt.Errorf("load peer client certificate: %w", err)
	}
	pool, err := daemon.trustPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   string(peer.Domain),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer server certificate is required")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if err := daemon.verifyCertificateNotRevoked(cert, "peer server certificate"); err != nil {
				return err
			}
			meta := pki.ParseMetadata(cert)
			if meta.Role != pki.RoleIX {
				return fmt.Errorf("peer server certificate role is %q, want %q", meta.Role, pki.RoleIX)
			}
			if meta.Domain != string(peer.Domain) {
				return fmt.Errorf("peer server certificate domain is %q, want %q", meta.Domain, peer.Domain)
			}
			if meta.IX != string(peer.ID) {
				return fmt.Errorf("peer server certificate ix is %q, want %q", meta.IX, peer.ID)
			}
			return nil
		},
	}, nil
}

func (daemon *Daemon) peerClient(peer config.PeerConfig) (*http.Client, error) {
	tlsConf, err := daemon.peerClientTLSConfig(peer)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConf,
		},
	}, nil
}

func (daemon *Daemon) trustPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	roots, err := daemon.trustRootCertificates()
	if err != nil {
		return nil, err
	}
	for _, cert := range roots {
		pool.AddCert(cert)
	}
	return pool, nil
}

func verifyLocalRouteAuthorizations(desired config.Desired) error {
	rawAdvertised := config.EffectiveLANAdvertise(desired)
	if len(rawAdvertised) == 0 {
		return nil
	}
	if len(desired.IX.RouteAuthorizations) == 0 {
		return fmt.Errorf("route authorization certificate is required for advertised LAN prefixes")
	}

	advertised := make([]netip.Prefix, 0, len(rawAdvertised))
	for _, prefix := range rawAdvertised {
		parsed, err := prefix.Parse()
		if err != nil {
			return err
		}
		advertised = append(advertised, parsed)
	}

	authorized := make([]netip.Prefix, 0, len(desired.IX.RouteAuthorizations))
	for _, path := range desired.IX.RouteAuthorizations {
		cert, _, err := pki.LoadCertificate(path)
		if err != nil {
			return err
		}
		if err := verifyCertificateNotRevokedByDesired(desired, cert, fmt.Sprintf("route authorization %q", path)); err != nil {
			return err
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("route authorization %q is not valid at current time", path)
		}
		meta := pki.ParseMetadata(cert)
		if meta.Role != pki.RoleRouteAuthorization {
			return fmt.Errorf("route authorization %q role is %q, want %q", path, meta.Role, pki.RoleRouteAuthorization)
		}
		if meta.Domain != string(desired.Domain.ID) {
			return fmt.Errorf("route authorization %q domain is %q, want %q", path, meta.Domain, desired.Domain.ID)
		}
		if meta.IX != string(desired.IX.ID) {
			return fmt.Errorf("route authorization %q ix is %q, want %q", path, meta.IX, desired.IX.ID)
		}
		for _, rawPrefix := range meta.Prefixes {
			parsed, err := netip.ParsePrefix(rawPrefix)
			if err != nil {
				return fmt.Errorf("route authorization %q prefix %q: %w", path, rawPrefix, err)
			}
			authorized = append(authorized, parsed.Masked())
		}
	}

	for _, prefix := range advertised {
		if !prefixCovered(prefix, authorized) {
			return fmt.Errorf("advertised prefix %q is not covered by route authorization certificates", prefix)
		}
	}
	return nil
}

func prefixCovered(prefix netip.Prefix, candidates []netip.Prefix) bool {
	for _, candidate := range candidates {
		if candidate.Contains(prefix.Addr()) && candidate.Bits() <= prefix.Bits() {
			return true
		}
	}
	return false
}

func (daemon *Daemon) Routes() routing.Engine {
	return daemon.routes
}

func (daemon *Daemon) Transports() *transport.Registry {
	return daemon.transports
}

func (daemon *Daemon) APIAddr() string {
	return daemon.cfg.APIAddr
}

func newEventID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate event id: %w", err)
	}
	return "evt-" + hex.EncodeToString(buf[:]), nil
}

func routesFromConfig(desired config.Desired) []routing.Route {
	routes := make([]routing.Route, 0, len(desired.Routes))
	for _, route := range desired.Routes {
		kind := route.Kind
		if kind == "" {
			kind = routing.RouteUnicast
		}
		owner := route.Owner
		if owner == "" && kind == routing.RouteUnicast {
			owner = route.NextHop
		}
		nextHop := route.NextHop
		if kind == routing.RouteLocal && nextHop == "" {
			nextHop = desired.IX.ID
		}
		routes = append(routes, routing.Route{
			Prefix:   route.Prefix,
			Owner:    owner,
			NextHop:  nextHop,
			Endpoint: route.Endpoint,
			Metric:   route.Metric,
			Policy:   route.Policy,
			Kind:     kind,
			Source:   "static",
		})
	}
	return routes
}

func peersFromConfig(desired config.Desired) []dataplane.PeerMetadata {
	peers := make([]dataplane.PeerMetadata, 0, len(desired.Peers))
	for _, peer := range desired.Peers {
		peers = append(peers, dataplane.PeerMetadata{
			ID:       peer.ID,
			DomainID: peer.Domain,
			Trusted:  true,
		})
	}
	return peers
}

func (daemon *Daemon) endpointsFromConfig(desired config.Desired) []dataplane.EndpointMetadata {
	endpoints := make([]dataplane.EndpointMetadata, 0, len(desired.Endpoints))
	for _, ep := range desired.Endpoints {
		endpoints = append(endpoints, dataplane.EndpointMetadata{
			ID:        ep.Name,
			Peer:      desired.IX.ID,
			Transport: ep.Transport,
			Address:   ep.Address,
			Listen:    ep.Listen,
			LocalBind: endpointLocalBindMetadataFromConfig(ep.LocalBind),
			Priority:  ep.Priority,
			Enabled:   ep.Enabled,
			Security:  daemon.endpointSecurityMetadata(ep),
			Profile:   endpointTransportProfileMetadataForPolicy(ep, desired.TransportPolicy),
			Access:    endpointAccessMetadataFromConfig(ep.Access),
		})
	}
	for _, peer := range desired.Peers {
		for _, ep := range peer.Endpoints {
			security := endpointSecurityMetadataFromConfig(ep.Security, ep.TLSServerName)
			if security.Encryption == "" {
				security.Encryption = parseSecureTransportEncryption(desired.TransportPolicy.Encryption)
			}
			endpoints = append(endpoints, dataplane.EndpointMetadata{
				ID:        ep.Name,
				Peer:      peer.ID,
				Transport: ep.Transport,
				Address:   ep.Address,
				LocalBind: endpointLocalBindMetadataFromConfig(ep.LocalBind),
				Priority:  ep.Priority,
				Enabled:   endpointDataSessionEnabled(ep),
				Security:  security,
				Profile:   endpointTransportProfileMetadataFromConfig(ep.Profile),
				Access:    endpointAccessMetadataFromConfig(ep.Access),
			})
		}
	}
	return endpoints
}

func endpointsFromConfig(desired config.Desired) []dataplane.EndpointMetadata {
	return (&Daemon{desired: desired}).endpointsFromConfig(desired)
}

func endpointLocalBindMetadataFromConfig(bind config.EndpointLocalBindConfig) dataplane.EndpointLocalBindMetadata {
	return dataplane.EndpointLocalBindMetadata{
		SourceIP: strings.TrimSpace(bind.SourceIP),
		Iface:    strings.TrimSpace(bind.Iface),
	}
}

func endpointLocalBindConfigFromMetadata(bind dataplane.EndpointLocalBindMetadata) config.EndpointLocalBindConfig {
	return config.EndpointLocalBindConfig{
		SourceIP: strings.TrimSpace(bind.SourceIP),
		Iface:    strings.TrimSpace(bind.Iface),
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseUintParam(r *http.Request, name string, defaultValue uint64) (uint64, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", name, raw)
	}
	return value, nil
}

const maxPaginatedAPILimit = 10000

func parsePaginationParams(r *http.Request, defaultLimit int) (int, int, error) {
	offset := 0
	limit := defaultLimit
	query := r.URL.Query()
	if raw := strings.TrimSpace(query.Get("offset")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, 0, fmt.Errorf("invalid offset %q", raw)
		}
		offset = value
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, 0, fmt.Errorf("invalid limit %q", raw)
		}
		limit = value
	}
	if limit > maxPaginatedAPILimit {
		limit = maxPaginatedAPILimit
	}
	return offset, limit, nil
}

func paginateSlice[T any](items []T, offset, limit int) ([]T, int, bool) {
	total := len(items)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []T{}, total, total > 0
	}
	if limit <= 0 {
		return items[offset:], total, false
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return items[offset:end], total, end < total
}
