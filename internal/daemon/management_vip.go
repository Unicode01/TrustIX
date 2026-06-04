package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
)

const apiServerManagementVIPPrefix = "management_vip:"

type managementVIPTarget struct {
	IXID core.IXID
	Addr netip.Addr
	Port string
}

func (target managementVIPTarget) listenAddress() string {
	return net.JoinHostPort(target.Addr.String(), target.Port)
}

func (target managementVIPTarget) serverName() string {
	return apiServerManagementVIPPrefix + string(target.IXID) + "/" + target.listenAddress()
}

func (daemon *Daemon) managementVIPTargets() []managementVIPTarget {
	if !daemon.managementHostAPIEnabled() {
		return nil
	}
	accepted := daemon.acceptedManagementVIPRoutes()
	if len(accepted) == 0 {
		return nil
	}
	localAddr := daemon.managementHostAPIAddr()
	targets := make([]managementVIPTarget, 0, len(accepted))
	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	for ixID, record := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		acceptedAddr, ok := accepted[ixID]
		if !ok {
			continue
		}
		ad := record.Advertisement
		if strings.TrimSpace(ad.ControlAPI) == "" || ad.Management == nil || ad.Management.HostAPI == nil {
			continue
		}
		addr, err := netip.ParseAddr(ad.Management.HostAPI.IP)
		if err != nil || addr != acceptedAddr || !addr.Is4() || addr == localAddr {
			continue
		}
		port := strings.TrimSpace(ad.Management.HostAPI.Port)
		if port == "" {
			continue
		}
		targets = append(targets, managementVIPTarget{IXID: ixID, Addr: addr, Port: port})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].IXID != targets[j].IXID {
			return targets[i].IXID < targets[j].IXID
		}
		return targets[i].listenAddress() < targets[j].listenAddress()
	})
	return targets
}

func (daemon *Daemon) acceptedManagementVIPRoutes() map[core.IXID]netip.Addr {
	routes := daemon.runtimeRoutes()
	out := make(map[core.IXID]netip.Addr)
	for _, route := range routes {
		if route.Kind != routing.RouteLocal || route.Source != "management_vip" {
			continue
		}
		prefix, err := route.Prefix.Parse()
		if err != nil || prefix.Bits() != 32 || !prefix.Addr().Is4() {
			continue
		}
		out[route.Owner] = prefix.Addr()
	}
	return out
}

func (daemon *Daemon) startManagementVIPAPIServersLocked(ctx context.Context) error {
	targets := daemon.managementVIPTargets()
	if err := daemon.syncManagementVIPAddresses(ctx, targets); err != nil {
		return err
	}
	for _, target := range targets {
		if err := daemon.startManagementVIPAPIServerLocked(target); err != nil {
			return err
		}
	}
	return nil
}

func (daemon *Daemon) syncManagementVIPAPIServers(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	targets := daemon.managementVIPTargets()
	desired := make(map[string]managementVIPTarget, len(targets))
	for _, target := range targets {
		desired[target.serverName()] = target
	}

	daemon.apiMu.Lock()
	if daemon.apiErr == nil {
		daemon.apiMu.Unlock()
		return nil
	}
	existing := make(map[string]struct{}, len(targets))
	var closing []apiServerRuntime
	kept := daemon.apiServers[:0]
	for _, runtime := range daemon.apiServers {
		if !strings.HasPrefix(runtime.Name, apiServerManagementVIPPrefix) {
			kept = append(kept, runtime)
			continue
		}
		if _, ok := desired[runtime.Name]; ok {
			existing[runtime.Name] = struct{}{}
			kept = append(kept, runtime)
			continue
		}
		closing = append(closing, runtime)
	}
	daemon.apiServers = kept
	daemon.apiMu.Unlock()

	if err := shutdownAPIServerRuntimes(ctx, closing); err != nil {
		return err
	}
	if err := daemon.syncManagementVIPAddresses(ctx, targets); err != nil {
		return err
	}

	daemon.apiMu.Lock()
	defer daemon.apiMu.Unlock()
	for _, target := range targets {
		if _, ok := existing[target.serverName()]; ok {
			continue
		}
		if err := daemon.startManagementVIPAPIServerLocked(target); err != nil {
			return err
		}
	}
	return nil
}

func (daemon *Daemon) syncManagementVIPAddresses(ctx context.Context, targets []managementVIPTarget) error {
	manager, ok := daemon.dataplane.(dataplane.LocalVIPManager)
	if !ok {
		return nil
	}
	seen := make(map[netip.Addr]struct{}, len(targets))
	vips := make([]dataplane.LocalVIP, 0, len(targets))
	for _, target := range targets {
		if _, exists := seen[target.Addr]; exists {
			continue
		}
		seen[target.Addr] = struct{}{}
		vips = append(vips, dataplane.LocalVIP{Addr: target.Addr})
	}
	return manager.SyncLocalVIPs(ctx, vips)
}

func (daemon *Daemon) startManagementVIPAPIServerLocked(target managementVIPTarget) error {
	name := target.serverName()
	for _, runtime := range daemon.apiServers {
		if runtime.Name == name {
			return nil
		}
	}
	listen := target.listenAddress()
	listener, err := listenTCP(context.Background(), listen)
	if err != nil {
		if listenAddressInUse(err) {
			daemon.apiServers = append(daemon.apiServers, apiServerRuntime{Name: name, Listen: listen})
			return nil
		}
		return fmt.Errorf("listen management VIP api %q for %s: %w", listen, target.IXID, err)
	}
	tlsEnabled := daemon.managementTLSEnabledForListen(listen)
	if tlsEnabled {
		tlsConf, err := daemon.managementServerTLSConfig()
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("configure management VIP api TLS %q for %s: %w", listen, target.IXID, err)
		}
		listener = tls.NewListener(listener, tlsConf)
	}
	server := &http.Server{Handler: daemon.managementVIPProxyHandler(target.IXID)}
	daemon.apiServers = append(daemon.apiServers, apiServerRuntime{
		Name:   name,
		Listen: listen,
		TLS:    tlsEnabled,
		Server: server,
	})
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			daemon.reportAPIServerError(name, listen, err)
		}
	}()
	return nil
}

func listenAddressInUse(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "address already in use")
}

func (daemon *Daemon) managementVIPProxyHandler(targetIX core.IXID) http.Handler {
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURI := r.URL.RequestURI()
		if err := validateManagementProxyTargetURI(targetURI); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		body, err := readLimitedBody(r.Body, maxConfigEventsBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err := daemon.proxyManagementToIX(w, r, targetIX, targetURI, body); err != nil {
			writeError(w, http.StatusBadGateway, err)
		}
	})
	authenticatedProxy := daemon.managementAuthMiddleware(proxy, managementAuthOptions{
		RequireWriteAuth: daemon.managementHostAPIWriteAuthRequired(),
		RequireReadAuth:  daemon.managementHostAPIReadAuthRequired(),
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if daemon.managementWebUIEnabled() && daemon.serveWebUIIfRequest(w, r) {
			return
		}
		authenticatedProxy.ServeHTTP(w, r)
	})
}
