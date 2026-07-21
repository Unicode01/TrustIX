//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/dataplane"
)

var (
	errNeighborUnresolved = errors.New("neighbor unresolved")
	errMTUExceeded        = errors.New("mtu exceeded")
	errGSOUnsupported     = errors.New("packet socket GSO unsupported")
)

const virtioNetHdrLen = 10
const lanSoftwareSegmentSendLimit = 512
const lanGSORawMixedBatchDefaultLimit = 256
const lanGSOScatterDefaultMaxIPv4Len = 32768
const lanGSOScatterDefaultMaxSegments = 32

var lanPacketStats = &lanPacketInjectorStats{}

type lanPacketInjectorStats struct {
	gsoAttempts              atomic.Uint64
	gsoSuccesses             atomic.Uint64
	gsoUnsupported           atomic.Uint64
	gsoErrors                atomic.Uint64
	gsoDisabled              atomic.Uint64
	gsoRawAttempts           atomic.Uint64
	gsoRawSuccesses          atomic.Uint64
	gsoRawBatchAttempts      atomic.Uint64
	gsoRawBatchSuccesses     atomic.Uint64
	gsoRawBatchMessages      atomic.Uint64
	gsoRawMixedAttempts      atomic.Uint64
	gsoRawMixedSuccesses     atomic.Uint64
	gsoRawMixedMessages      atomic.Uint64
	rawVNetBatchAttempts     atomic.Uint64
	rawVNetBatchSuccesses    atomic.Uint64
	rawVNetBatchMessages     atomic.Uint64
	rawVNetBatchErrors       atomic.Uint64
	rawVNetBatchUnsupported  atomic.Uint64
	gsoRawScatterAttempts    atomic.Uint64
	gsoRawScatterSuccesses   atomic.Uint64
	gsoRawScatterMessages    atomic.Uint64
	gsoCookedAttempts        atomic.Uint64
	gsoCookedSuccesses       atomic.Uint64
	gsoErrnoEINVAL           atomic.Uint64
	gsoErrnoEMSGSIZE         atomic.Uint64
	gsoErrnoEOPNOTSUPP       atomic.Uint64
	gsoErrnoENOPROTOOPT      atomic.Uint64
	gsoErrnoEPERM            atomic.Uint64
	gsoErrnoEIO              atomic.Uint64
	gsoErrnoENOTSUP          atomic.Uint64
	gsoErrnoEAGAIN           atomic.Uint64
	gsoErrnoEACCES           atomic.Uint64
	gsoErrnoENOBUFS          atomic.Uint64
	gsoErrnoENODEV           atomic.Uint64
	gsoErrnoENXIO            atomic.Uint64
	gsoErrnoEFAULT           atomic.Uint64
	gsoErrnoEDESTADDRREQ     atomic.Uint64
	gsoErrnoOther            atomic.Uint64
	gsoVNetHdrSizeConfigured atomic.Uint64
	gsoVNetHdrSizeFallbacks  atomic.Uint64
	softwareSegments         atomic.Uint64
	softwareSegmentBatches   atomic.Uint64
	batchSendAttempts        atomic.Uint64
	batchSendMessages        atomic.Uint64
	batchSendErrors          atomic.Uint64
	singleSendPackets        atomic.Uint64
}

func (stats *lanPacketInjectorStats) recordGSOErrno(err error) {
	errno := packetSocketGSOErrno(err)
	if errno == unix.EINVAL {
		stats.gsoErrnoEINVAL.Add(1)
		return
	}
	if errno == unix.EMSGSIZE {
		stats.gsoErrnoEMSGSIZE.Add(1)
		return
	}
	if errno == unix.EOPNOTSUPP {
		stats.gsoErrnoEOPNOTSUPP.Add(1)
		return
	}
	if errno == unix.ENOPROTOOPT {
		stats.gsoErrnoENOPROTOOPT.Add(1)
		return
	}
	if errno == unix.EPERM {
		stats.gsoErrnoEPERM.Add(1)
		return
	}
	if errno == unix.EIO {
		stats.gsoErrnoEIO.Add(1)
		return
	}
	if errno == unix.ENOTSUP {
		stats.gsoErrnoENOTSUP.Add(1)
		return
	}
	if errno == unix.EAGAIN {
		stats.gsoErrnoEAGAIN.Add(1)
		return
	}
	if errno == unix.EACCES {
		stats.gsoErrnoEACCES.Add(1)
		return
	}
	if errno == unix.ENOBUFS {
		stats.gsoErrnoENOBUFS.Add(1)
		return
	}
	if errno == unix.ENODEV {
		stats.gsoErrnoENODEV.Add(1)
		return
	}
	if errno == unix.ENXIO {
		stats.gsoErrnoENXIO.Add(1)
		return
	}
	if errno == unix.EFAULT {
		stats.gsoErrnoEFAULT.Add(1)
		return
	}
	if errno == unix.EDESTADDRREQ {
		stats.gsoErrnoEDESTADDRREQ.Add(1)
		return
	}
	stats.gsoErrnoOther.Add(1)
}

func packetSocketGSOErrno(err error) unix.Errno {
	for err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return errno
		}
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			for _, child := range multi.Unwrap() {
				if errno := packetSocketGSOErrno(child); errno != 0 {
					return errno
				}
			}
			return 0
		}
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return 0
		}
		err = unwrapped
	}
	return 0
}

type neighborKey struct {
	linkIndex int
	addr      netip.Addr
}

type resolvedNeighborEntry struct {
	nextHop   netip.Addr
	mac       [6]byte
	expiresAt time.Time
}

type neighborCache struct {
	mu        sync.RWMutex
	entries   map[neighborKey]net.HardwareAddr
	resolved  map[neighborKey]resolvedNeighborEntry
	links     map[int]struct{}
	done      chan struct{}
	closeOnce sync.Once
	onUpdate  func(netlink.Neigh, bool)
}

func newNeighborCache() *neighborCache {
	return &neighborCache{
		entries:  make(map[neighborKey]net.HardwareAddr),
		resolved: make(map[neighborKey]resolvedNeighborEntry),
		links:    make(map[int]struct{}),
		done:     make(chan struct{}),
	}
}

func (manager *Manager) startNeighborMonitorLocked(spec dataplane.AttachSpec) error {
	if manager.neighborCache != nil {
		return nil
	}
	cache := newNeighborCache()
	cache.onUpdate = manager.updateKernelUDPRXDirectNeighbor
	manager.neighborCache = cache
	ifaces := []string{spec.UnderlayIface}
	for _, lan := range effectiveLANAttachSpecs(spec) {
		ifaces = append(ifaces, lan.Iface, lan.UnderlayIface)
	}
	ifaces = append(ifaces, spec.LANIface)
	seen := make(map[string]struct{}, len(ifaces))
	for _, iface := range ifaces {
		if iface == "" {
			continue
		}
		if _, ok := seen[iface]; ok {
			continue
		}
		seen[iface] = struct{}{}
		link, err := netlink.LinkByName(iface)
		if err != nil {
			continue
		}
		cache.watchLink(link.Attrs().Index)
	}
	updates := make(chan netlink.NeighUpdate, 64)
	if err := netlink.NeighSubscribeWithOptions(updates, cache.done, netlink.NeighSubscribeOptions{ListExisting: true}); err != nil {
		cache.Close()
		manager.neighborCache = nil
		return err
	}
	go cache.run(updates)
	return nil
}

func (manager *Manager) stopNeighborMonitorLocked() error {
	if manager.neighborCache == nil {
		return nil
	}
	manager.neighborCache.Close()
	manager.neighborCache = nil
	return nil
}

func (cache *neighborCache) Close() {
	cache.closeOnce.Do(func() {
		close(cache.done)
	})
}

func (cache *neighborCache) run(updates <-chan netlink.NeighUpdate) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-cache.done:
			return
		case <-ticker.C:
			for _, linkIndex := range cache.watchedLinks() {
				cache.seed(linkIndex)
			}
		case update, ok := <-updates:
			if !ok {
				return
			}
			cache.apply(update.Neigh, update.Type == unix.RTM_DELNEIGH)
		}
	}
}

func (cache *neighborCache) watchLink(linkIndex int) {
	if linkIndex <= 0 {
		return
	}
	cache.mu.Lock()
	cache.links[linkIndex] = struct{}{}
	cache.mu.Unlock()
	cache.seed(linkIndex)
}

func (cache *neighborCache) watchedLinks() []int {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	links := make([]int, 0, len(cache.links))
	for linkIndex := range cache.links {
		links = append(links, linkIndex)
	}
	return links
}

func (cache *neighborCache) seed(linkIndex int) {
	neighbors, err := netlink.NeighList(linkIndex, netlink.FAMILY_V4)
	if err != nil {
		return
	}
	for _, neighbor := range neighbors {
		cache.apply(neighbor, false)
	}
}

func (cache *neighborCache) apply(neighbor netlink.Neigh, deleted bool) {
	addr, ok := ipv4AddrFromIP(neighbor.IP)
	if !ok {
		return
	}
	key := neighborKey{linkIndex: neighbor.LinkIndex, addr: addr}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if deleted || neighbor.State == netlink.NUD_FAILED || neighbor.State == netlink.NUD_INCOMPLETE || len(neighbor.HardwareAddr) != 6 {
		cache.invalidateResolvedLocked(neighbor.LinkIndex, addr)
		delete(cache.entries, key)
		if cache.onUpdate != nil {
			cache.onUpdate(neighbor, true)
		}
		return
	}
	if existing, ok := cache.entries[key]; !ok || !hardwareAddrEqual6(existing, neighbor.HardwareAddr) {
		cache.invalidateResolvedLocked(neighbor.LinkIndex, addr)
	}
	cache.entries[key] = append(net.HardwareAddr(nil), neighbor.HardwareAddr...)
	if cache.onUpdate != nil {
		cache.onUpdate(neighbor, false)
	}
}

func (cache *neighborCache) lookup(linkIndex int, addr netip.Addr) (net.HardwareAddr, bool) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	mac, ok := cache.entries[neighborKey{linkIndex: linkIndex, addr: addr}]
	if !ok || len(mac) != 6 {
		return nil, false
	}
	return append(net.HardwareAddr(nil), mac...), true
}

func (cache *neighborCache) lookupResolved(linkIndex int, addr netip.Addr, now time.Time) (net.HardwareAddr, bool) {
	cache.mu.RLock()
	entry, ok := cache.resolved[neighborKey{linkIndex: linkIndex, addr: addr}]
	if !ok || (!entry.expiresAt.IsZero() && !now.Before(entry.expiresAt)) {
		cache.mu.RUnlock()
		if ok {
			cache.deleteResolvedIfExpired(linkIndex, addr, entry.expiresAt)
		}
		return nil, false
	}
	cache.mu.RUnlock()
	return net.HardwareAddr{entry.mac[0], entry.mac[1], entry.mac[2], entry.mac[3], entry.mac[4], entry.mac[5]}, true
}

func (cache *neighborCache) rememberResolved(linkIndex int, addr netip.Addr, nextHop netip.Addr, mac net.HardwareAddr, now time.Time) {
	if cache == nil || linkIndex <= 0 || !addr.Is4() || !nextHop.Is4() || len(mac) != 6 {
		return
	}
	entry := resolvedNeighborEntry{
		nextHop:   nextHop,
		expiresAt: now.Add(neighborResolvedCacheTTL()),
	}
	copy(entry.mac[:], mac[:6])
	cache.mu.Lock()
	cache.resolved[neighborKey{linkIndex: linkIndex, addr: addr}] = entry
	cache.mu.Unlock()
}

func (cache *neighborCache) deleteResolvedIfExpired(linkIndex int, addr netip.Addr, expiresAt time.Time) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	key := neighborKey{linkIndex: linkIndex, addr: addr}
	entry, ok := cache.resolved[key]
	if ok && entry.expiresAt == expiresAt && !time.Now().Before(entry.expiresAt) {
		delete(cache.resolved, key)
	}
}

func (cache *neighborCache) invalidateResolvedLocked(linkIndex int, addr netip.Addr) {
	for key, entry := range cache.resolved {
		if key.linkIndex == linkIndex && (key.addr == addr || entry.nextHop == addr) {
			delete(cache.resolved, key)
		}
	}
}

func neighborResolvedCacheTTL() time.Duration {
	return 30 * time.Second
}

func (manager *Manager) learnNeighbor(linkIndex int, addr netip.Addr, mac net.HardwareAddr) {
	if manager.neighborCache == nil || !addr.Is4() || len(mac) != 6 {
		return
	}
	key := neighborKey{linkIndex: linkIndex, addr: addr}
	manager.neighborCache.mu.RLock()
	existing, ok := manager.neighborCache.entries[key]
	if ok && hardwareAddrEqual6(existing, mac) {
		manager.neighborCache.mu.RUnlock()
		manager.updateKernelUDPRXDirectNeighbor(netlink.Neigh{
			LinkIndex:    linkIndex,
			Family:       netlink.FAMILY_V4,
			IP:           net.IP(addr.AsSlice()),
			HardwareAddr: mac[:6],
			State:        netlink.NUD_REACHABLE,
		}, false)
		return
	}
	manager.neighborCache.mu.RUnlock()

	manager.neighborCache.mu.Lock()
	existing, ok = manager.neighborCache.entries[key]
	if ok && hardwareAddrEqual6(existing, mac) {
		manager.neighborCache.mu.Unlock()
		manager.updateKernelUDPRXDirectNeighbor(netlink.Neigh{
			LinkIndex:    linkIndex,
			Family:       netlink.FAMILY_V4,
			IP:           net.IP(addr.AsSlice()),
			HardwareAddr: mac[:6],
			State:        netlink.NUD_REACHABLE,
		}, false)
		return
	}
	manager.neighborCache.invalidateResolvedLocked(linkIndex, addr)
	manager.neighborCache.entries[key] = append(net.HardwareAddr(nil), mac[:6]...)
	manager.neighborCache.mu.Unlock()
	manager.updateKernelUDPRXDirectNeighbor(netlink.Neigh{
		LinkIndex:    linkIndex,
		Family:       netlink.FAMILY_V4,
		IP:           net.IP(addr.AsSlice()),
		HardwareAddr: mac[:6],
		State:        netlink.NUD_REACHABLE,
	}, false)
}

func (manager *Manager) syncKernelUDPRXDirectNeighborsFromCache(linkIndex int) {
	if manager.neighborCache == nil || linkIndex <= 0 {
		return
	}
	type cachedNeighbor struct {
		addr netip.Addr
		mac  net.HardwareAddr
	}
	var cached []cachedNeighbor
	manager.neighborCache.mu.RLock()
	for key, mac := range manager.neighborCache.entries {
		if key.linkIndex != linkIndex || !key.addr.Is4() || len(mac) != 6 {
			continue
		}
		cached = append(cached, cachedNeighbor{
			addr: key.addr,
			mac:  append(net.HardwareAddr(nil), mac[:6]...),
		})
	}
	manager.neighborCache.mu.RUnlock()
	for _, neighbor := range cached {
		manager.updateKernelUDPRXDirectNeighbor(netlink.Neigh{
			LinkIndex:    linkIndex,
			Family:       netlink.FAMILY_V4,
			IP:           net.IP(neighbor.addr.AsSlice()),
			HardwareAddr: neighbor.mac,
			State:        netlink.NUD_REACHABLE,
		}, false)
	}
}

func hardwareAddrEqual6(a, b net.HardwareAddr) bool {
	return len(a) == 6 && len(b) >= 6 &&
		a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
		a[3] == b[3] && a[4] == b[4] && a[5] == b[5]
}

func (manager *Manager) resolveIPv4Neighbor(linkIndex int, remoteIP netip.Addr) (net.HardwareAddr, error) {
	if !remoteIP.Is4() {
		return nil, fmt.Errorf("resolve neighbor for non-IPv4 address %s", remoteIP)
	}
	now := time.Now()
	if manager.neighborCache != nil {
		if mac, ok := manager.neighborCache.lookupResolved(linkIndex, remoteIP, now); ok {
			return mac, nil
		}
		if mac, ok := manager.neighborCache.lookup(linkIndex, remoteIP); ok {
			manager.neighborCache.rememberResolved(linkIndex, remoteIP, remoteIP, mac, now)
			return mac, nil
		}
	}
	if link, err := netlink.LinkByIndex(linkIndex); err == nil && isVethLink(link) {
		if peerMAC, warning := vethPeerHardwareAddr(link); len(peerMAC) == 6 {
			manager.learnNeighbor(linkIndex, remoteIP, peerMAC)
			if manager.neighborCache != nil {
				manager.neighborCache.rememberResolved(linkIndex, remoteIP, remoteIP, peerMAC, now)
			}
			return peerMAC, nil
		} else if warning != "" {
			manager.warnings = appendManagerWarning(manager.warnings, warning)
		}
	}
	if manager.neighborCache != nil {
		if mac, ok := manager.neighborCache.lookup(linkIndex, remoteIP); ok {
			return mac, nil
		}
	}
	nextHop := remoteIP
	routes, err := netlink.RouteGet(net.IP(remoteIP.AsSlice()))
	if err != nil {
		return nil, fmt.Errorf("resolve route for %s: %w", remoteIP, err)
	}
	if len(routes) > 0 {
		route := routes[0]
		if route.LinkIndex != 0 && route.LinkIndex != linkIndex {
			return nil, fmt.Errorf("remote %s routes via ifindex %d, not ifindex %d", remoteIP, route.LinkIndex, linkIndex)
		}
		if route.Gw != nil {
			if gw, ok := ipv4AddrFromIP(route.Gw); ok {
				nextHop = gw
			}
		}
	}
	if manager.neighborCache != nil {
		if mac, ok := manager.neighborCache.lookup(linkIndex, nextHop); ok {
			manager.neighborCache.rememberResolved(linkIndex, remoteIP, nextHop, mac, now)
			return mac, nil
		}
	}
	manager.seedNeighborCache(linkIndex)
	if manager.neighborCache != nil {
		if mac, ok := manager.neighborCache.lookup(linkIndex, nextHop); ok {
			manager.neighborCache.rememberResolved(linkIndex, remoteIP, nextHop, mac, now)
			return mac, nil
		}
	}
	probeErr := triggerNeighborProbe(linkIndex, nextHop)
	time.Sleep(25 * time.Millisecond)
	manager.seedNeighborCache(linkIndex)
	if manager.neighborCache != nil {
		if mac, ok := manager.neighborCache.lookup(linkIndex, nextHop); ok {
			manager.neighborCache.rememberResolved(linkIndex, remoteIP, nextHop, mac, now)
			return mac, nil
		}
	}
	return nil, errors.Join(
		fmt.Errorf("%w: %s on ifindex %d", errNeighborUnresolved, nextHop, linkIndex),
		wrapEBPFOperation("trigger neighbor probe", probeErr),
	)
}

func (manager *Manager) resolveIPv4NeighborVia(linkIndex int, remoteIP netip.Addr, nextHop netip.Addr) (net.HardwareAddr, error) {
	if !remoteIP.Is4() {
		return nil, fmt.Errorf("resolve neighbor for non-IPv4 address %s", remoteIP)
	}
	if !nextHop.Is4() {
		return nil, fmt.Errorf("resolve neighbor for non-IPv4 next-hop %s", nextHop)
	}
	now := time.Now()
	if manager.neighborCache != nil {
		if mac, ok := manager.neighborCache.lookupResolved(linkIndex, remoteIP, now); ok {
			return mac, nil
		}
		if nextHop == remoteIP {
			if mac, ok := manager.neighborCache.lookup(linkIndex, remoteIP); ok {
				manager.neighborCache.rememberResolved(linkIndex, remoteIP, remoteIP, mac, now)
				return mac, nil
			}
		}
	}
	if nextHop == remoteIP {
		if link, err := netlink.LinkByIndex(linkIndex); err == nil && isVethLink(link) {
			if peerMAC, warning := vethPeerHardwareAddr(link); len(peerMAC) == 6 {
				manager.learnNeighbor(linkIndex, remoteIP, peerMAC)
				if manager.neighborCache != nil {
					manager.neighborCache.rememberResolved(linkIndex, remoteIP, remoteIP, peerMAC, now)
				}
				return peerMAC, nil
			} else if warning != "" {
				manager.warnings = appendManagerWarning(manager.warnings, warning)
			}
		}
	}
	if manager.neighborCache != nil {
		if nextHop == remoteIP {
			if mac, ok := manager.neighborCache.lookup(linkIndex, remoteIP); ok {
				return mac, nil
			}
		}
		if mac, ok := manager.neighborCache.lookup(linkIndex, nextHop); ok {
			manager.neighborCache.rememberResolved(linkIndex, remoteIP, nextHop, mac, now)
			return mac, nil
		}
	}
	manager.seedNeighborCache(linkIndex)
	if manager.neighborCache != nil {
		if mac, ok := manager.neighborCache.lookup(linkIndex, nextHop); ok {
			manager.neighborCache.rememberResolved(linkIndex, remoteIP, nextHop, mac, now)
			return mac, nil
		}
	}
	probeErr := triggerNeighborProbe(linkIndex, nextHop)
	time.Sleep(25 * time.Millisecond)
	manager.seedNeighborCache(linkIndex)
	if manager.neighborCache != nil {
		if mac, ok := manager.neighborCache.lookup(linkIndex, nextHop); ok {
			manager.neighborCache.rememberResolved(linkIndex, remoteIP, nextHop, mac, now)
			return mac, nil
		}
	}
	return nil, errors.Join(
		fmt.Errorf("%w: %s on ifindex %d", errNeighborUnresolved, nextHop, linkIndex),
		wrapEBPFOperation("trigger neighbor probe", probeErr),
	)
}

func (manager *Manager) seedNeighborCache(linkIndex int) {
	if manager.neighborCache == nil {
		return
	}
	manager.neighborCache.watchLink(linkIndex)
}

func triggerNeighborProbe(linkIndex int, addr netip.Addr) error {
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: linkIndex,
		Family:    netlink.FAMILY_V4,
		IP:        net.IP(addr.AsSlice()),
		State:     netlink.NUD_PROBE,
		Flags:     netlink.NTF_USE,
	}); err != nil {
		return fmt.Errorf("probe IPv4 neighbor %s on ifindex %d: %w", addr, linkIndex, err)
	}
	return nil
}

type lanPacketInjector struct {
	mu                   sync.RWMutex
	fd                   int
	gsoFD                int
	gsoRawFD             int
	gsoDisabled          bool
	gsoRawDisabled       bool
	rawVNetBatchDisabled bool
	ifindex              int
	ifname               string
	mtu                  int
	hardwareAddr         net.HardwareAddr
}

func (manager *Manager) lanPacketInjectorForIface(iface string) (*lanPacketInjector, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.lanInjectors == nil {
		manager.lanInjectors = make(map[string]*lanPacketInjector)
	}
	if injector := manager.lanInjectors[iface]; injector != nil {
		return injector, nil
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("inspect LAN iface %q for packet reinject: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(etherTypeIPv4)))
	if err != nil {
		return nil, fmt.Errorf("open LAN packet reinject socket for %q: %w", iface, err)
	}
	if err := configureLANPacketSocket(fd); err != nil {
		return nil, errors.Join(
			fmt.Errorf("configure LAN packet reinject socket for %q: %w", iface, err),
			wrapEBPFOperation("close failed LAN packet reinject socket", unix.Close(fd)),
		)
	}
	injector := &lanPacketInjector{
		fd:           fd,
		gsoFD:        -1,
		gsoRawFD:     -1,
		ifindex:      link.Attrs().Index,
		ifname:       link.Attrs().Name,
		mtu:          link.Attrs().MTU,
		hardwareAddr: append(net.HardwareAddr(nil), link.Attrs().HardwareAddr...),
	}
	manager.lanInjectors[iface] = injector
	return injector, nil
}

func (manager *Manager) sendLANIPv4Packet(iface string, packet []byte, dst netip.Addr) error {
	injector, err := manager.lanPacketInjectorForIface(iface)
	if err != nil {
		return err
	}
	dstMAC, err := manager.resolveIPv4Neighbor(injector.ifindex, dst)
	if err != nil {
		return err
	}
	return manager.sendLANIPv4PacketWithMAC(injector, packet, dst, dstMAC)
}

func (manager *Manager) sendLANIPv4PacketWithMAC(injector *lanPacketInjector, packet []byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	if injector == nil {
		return fmt.Errorf("LAN packet reinject injector is not available")
	}
	if len(dstMAC) < 6 {
		return fmt.Errorf("%w: invalid cached LAN neighbor for %s", errNeighborUnresolved, dst)
	}
	var err error
	packets := [][]byte{packet}
	if len(packet) > injector.mtu {
		var gsoErr error
		if lanReinjectGSOEnabled() {
			lanPacketStats.gsoAttempts.Add(1)
			if gsoErr = injector.sendLANIPv4TCPGSO(packet, dst, dstMAC); gsoErr == nil {
				lanPacketStats.gsoSuccesses.Add(1)
				return nil
			} else if !errors.Is(gsoErr, errGSOUnsupported) {
				lanPacketStats.gsoErrors.Add(1)
			} else {
				lanPacketStats.gsoUnsupported.Add(1)
			}
		} else {
			lanPacketStats.gsoDisabled.Add(1)
		}
		packets, err = segmentLANIPv4TCPPacket(packet, injector.mtu)
		if err != nil {
			if gsoErr != nil && !errors.Is(gsoErr, errGSOUnsupported) {
				return fmt.Errorf("%w; software segment fallback: %v", gsoErr, err)
			}
			return err
		}
		lanPacketStats.softwareSegments.Add(uint64(len(packets)))
		lanPacketStats.softwareSegmentBatches.Add(1)
	}
	if len(packets) > 1 {
		return injector.sendBatch(packets, dst, dstMAC)
	}
	for _, packet := range packets {
		if len(packet) > injector.mtu {
			return fmt.Errorf("%w: LAN packet size %d exceeds MTU %d", errMTUExceeded, len(packet), injector.mtu)
		}
		if err := injector.send(packet, dst, dstMAC); err != nil {
			return err
		}
	}
	return nil
}

func (manager *Manager) sendLANIPv4Packets(iface string, packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	injector, err := manager.lanPacketInjectorForIface(iface)
	if err != nil {
		return err
	}
	if len(packets) == 1 {
		ipPacket, dstRaw, err := ipv4Payload(packets[0])
		if err != nil {
			return err
		}
		dst := netip.AddrFrom4(dstRaw)
		dstMAC, err := manager.resolveIPv4Neighbor(injector.ifindex, dst)
		if err != nil {
			return err
		}
		return manager.sendLANIPv4PacketWithMAC(injector, ipPacket, dst, dstMAC)
	}
	ipPackets, dst, sameDst, err := lanIPv4SingleDestinationBatch(packets)
	if err != nil {
		return err
	}
	if sameDst {
		dstMAC, err := manager.resolveIPv4Neighbor(injector.ifindex, dst)
		if err != nil {
			return err
		}
		return injector.sendBatchWithGSO(ipPackets, dst, dstMAC)
	}
	type lanBatch struct {
		dst    netip.Addr
		dstMAC net.HardwareAddr
		items  [][]byte
	}
	batches := make([]lanBatch, 0, 1)
	var batchIndexByDst map[netip.Addr]int
	firstDst := netip.Addr{}
	for _, packet := range packets {
		ipPacket, dstRaw, err := ipv4Payload(packet)
		if err != nil {
			return err
		}
		dst := netip.AddrFrom4(dstRaw)
		index := 0
		ok := false
		if len(batches) == 0 {
			dstMAC, err := manager.resolveIPv4Neighbor(injector.ifindex, dst)
			if err != nil {
				return err
			}
			batches = append(batches, lanBatch{
				dst:    dst,
				dstMAC: dstMAC,
				items:  make([][]byte, 0, len(packets)),
			})
			firstDst = dst
			ok = true
		} else if batchIndexByDst == nil && dst == firstDst {
			ok = true
		} else if batchIndexByDst != nil {
			index, ok = batchIndexByDst[dst]
		}
		if !ok {
			if batchIndexByDst == nil {
				batchIndexByDst = make(map[netip.Addr]int, len(batches)+1)
				for i := range batches {
					batchIndexByDst[batches[i].dst] = i
				}
			}
			dstMAC, err := manager.resolveIPv4Neighbor(injector.ifindex, dst)
			if err != nil {
				return err
			}
			batches = append(batches, lanBatch{
				dst:    dst,
				dstMAC: dstMAC,
			})
			index = len(batches) - 1
			batchIndexByDst[dst] = index
		} else if len(batches[index].dstMAC) == 0 {
			return fmt.Errorf("%w: invalid cached LAN neighbor for %s", errNeighborUnresolved, dst)
		}
		batches[index].items = append(batches[index].items, ipPacket)
	}
	for _, batch := range batches {
		if err := injector.sendBatchWithGSO(batch.items, batch.dst, batch.dstMAC); err != nil {
			return err
		}
	}
	return nil
}

func lanIPv4SingleDestinationBatch(packets [][]byte) ([][]byte, netip.Addr, bool, error) {
	if len(packets) == 0 {
		return nil, netip.Addr{}, false, nil
	}
	ipPacket, dstRaw, err := ipv4Payload(packets[0])
	if err != nil {
		return nil, netip.Addr{}, false, err
	}
	dst := netip.AddrFrom4(dstRaw)
	if &ipPacket[0] != &packets[0][0] {
		out := make([][]byte, len(packets))
		out[0] = ipPacket
		for i := 1; i < len(packets); i++ {
			nextPacket, nextDstRaw, err := ipv4Payload(packets[i])
			if err != nil {
				return nil, netip.Addr{}, false, err
			}
			if netip.AddrFrom4(nextDstRaw) != dst {
				return nil, netip.Addr{}, false, nil
			}
			out[i] = nextPacket
		}
		return out, dst, true, nil
	}
	for i := 1; i < len(packets); i++ {
		nextPacket, nextDstRaw, err := ipv4Payload(packets[i])
		if err != nil {
			return nil, netip.Addr{}, false, err
		}
		if &nextPacket[0] != &packets[i][0] {
			return nil, netip.Addr{}, false, nil
		}
		if netip.AddrFrom4(nextDstRaw) != dst {
			return nil, netip.Addr{}, false, nil
		}
	}
	return packets, dst, true, nil
}

func (injector *lanPacketInjector) sendBatchWithGSO(packets [][]byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	if len(packets) == 0 {
		return nil
	}
	for start := 0; start < len(packets); {
		if lanReinjectGSOEnabled() && lanReinjectGSORawMixedBatchEnabled() {
			limit := lanReinjectGSORawMixedBatchLimit()
			end := min(start+limit, len(packets))
			if lanIPv4BatchHasGSOPacket(packets[start:end], injector.mtu) {
				sent, err := injector.sendRawVNetMixedBatch(packets[start:end], dst, dstMAC)
				if sent > 0 {
					start += sent
					continue
				}
				if err == nil {
					start = end
					continue
				}
				if !errors.Is(err, errGSOUnsupported) {
					lanPacketStats.gsoErrors.Add(1)
				}
			}
		}
		if lanReinjectGSOEnabled() && lanReinjectGSOScatterEnabled() {
			sent, err := injector.sendRawGSOScatterRun(packets[start:], dst, dstMAC)
			if err != nil && !errors.Is(err, errGSOUnsupported) {
				lanPacketStats.gsoErrors.Add(1)
				return err
			}
			if sent > 0 {
				start += sent
				continue
			}
		}
		packet := packets[start]
		if len(packet) > injector.mtu {
			end := start + 1
			for end < len(packets) && len(packets[end]) > injector.mtu {
				end++
			}
			if end-start > 1 && lanReinjectGSOEnabled() && lanReinjectGSORawBatchEnabled() {
				sent, err := injector.sendRawGSOBatch(packets[start:end], dst, dstMAC)
				if err != nil && !errors.Is(err, errGSOUnsupported) {
					lanPacketStats.gsoErrors.Add(1)
					return err
				}
				if sent > 0 {
					start += sent
					if start >= end {
						continue
					}
					packet = packets[start]
				}
			}
			if start >= end {
				continue
			}
			gsoEnabled := lanReinjectGSOEnabled()
			if !gsoEnabled || !injector.canAttemptGSO() {
				lanPacketStats.gsoDisabled.Add(uint64(end - start))
				if err := injector.sendSoftwareSegmentedRun(packets[start:end], dst, dstMAC); err != nil {
					return err
				}
				start = end
				continue
			}
			var gsoErr error
			if gsoEnabled {
				lanPacketStats.gsoAttempts.Add(1)
				if gsoErr = injector.sendLANIPv4TCPGSO(packet, dst, dstMAC); gsoErr == nil {
					lanPacketStats.gsoSuccesses.Add(1)
					start++
					continue
				} else if !errors.Is(gsoErr, errGSOUnsupported) {
					lanPacketStats.gsoErrors.Add(1)
				} else {
					lanPacketStats.gsoUnsupported.Add(1)
				}
			} else {
				lanPacketStats.gsoDisabled.Add(1)
			}
			if !injector.canAttemptGSO() && end-start > 1 {
				lanPacketStats.gsoDisabled.Add(uint64(end - start - 1))
				if err := injector.sendSoftwareSegmentedRun(packets[start:end], dst, dstMAC); err != nil {
					return err
				}
				start = end
				continue
			}
			segments, err := segmentLANIPv4TCPPacket(packet, injector.mtu)
			if err != nil {
				if gsoErr != nil && !errors.Is(gsoErr, errGSOUnsupported) {
					return fmt.Errorf("%w; software segment fallback: %v", gsoErr, err)
				}
				return err
			}
			lanPacketStats.softwareSegments.Add(uint64(len(segments)))
			lanPacketStats.softwareSegmentBatches.Add(1)
			if len(segments) == 1 {
				if err := injector.send(segments[0], dst, dstMAC); err != nil {
					return err
				}
				start++
				continue
			}
			if err := injector.sendBatch(segments, dst, dstMAC); err != nil {
				return err
			}
			start++
			continue
		}
		end := start + 1
		for end < len(packets) && len(packets[end]) <= injector.mtu {
			end++
		}
		small := packets[start:end]
		if len(small) > 1 && lanReinjectRawVNetBatchEnabled() {
			sent := injector.sendRawVNetSmallBatches(small, dst, dstMAC)
			if sent >= len(small) {
				start = end
				continue
			}
			small = small[sent:]
		}
		if len(small) == 1 {
			if err := injector.send(small[0], dst, dstMAC); err != nil {
				return err
			}
		} else if err := injector.sendBatch(small, dst, dstMAC); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func (injector *lanPacketInjector) canAttemptGSO() bool {
	injector.mu.RLock()
	defer injector.mu.RUnlock()
	return !injector.gsoRawDisabled || !injector.gsoDisabled
}

func (injector *lanPacketInjector) sendSoftwareSegmentedRun(packets [][]byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	if len(packets) == 0 {
		return nil
	}
	scratch := takeLANSegmentBatchScratch(lanSoftwareSegmentSendLimit)
	defer putLANSegmentBatchScratch(scratch)
	flush := func() error {
		if len(scratch.segments) == 0 {
			return nil
		}
		if len(scratch.segments) == 1 {
			if err := injector.send(scratch.segments[0], dst, dstMAC); err != nil {
				return err
			}
		} else if err := injector.sendBatch(scratch.segments, dst, dstMAC); err != nil {
			return err
		}
		clear(scratch.segments)
		scratch.segments = scratch.segments[:0]
		return nil
	}
	for _, packet := range packets {
		segments, err := segmentLANIPv4TCPPacket(packet, injector.mtu)
		if err != nil {
			return err
		}
		lanPacketStats.softwareSegments.Add(uint64(len(segments)))
		lanPacketStats.softwareSegmentBatches.Add(1)
		for len(segments) > 0 {
			available := cap(scratch.segments) - len(scratch.segments)
			if available <= 0 {
				if err := flush(); err != nil {
					return err
				}
				available = cap(scratch.segments)
			}
			n := min(available, len(segments))
			scratch.segments = append(scratch.segments, segments[:n]...)
			segments = segments[n:]
		}
	}
	return flush()
}

func (injector *lanPacketInjector) sendRawGSOBatch(packets [][]byte, dst netip.Addr, dstMAC net.HardwareAddr) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(injector.hardwareAddr) < 6 || len(dstMAC) < 6 {
		return 0, fmt.Errorf("%w: LAN raw GSO batch needs Ethernet source and destination MAC", errGSOUnsupported)
	}
	firstLarge := -1
	for i, packet := range packets {
		if len(packet) > injector.mtu {
			firstLarge = i
			break
		}
	}
	if firstLarge < 0 {
		return 0, fmt.Errorf("%w: LAN raw GSO batch has no GSO packets", errGSOUnsupported)
	}
	if firstLarge > 0 {
		return 0, fmt.Errorf("%w: LAN raw GSO batch starts after small packets", errGSOUnsupported)
	}
	end := 0
	for end < len(packets) && len(packets[end]) > injector.mtu {
		end++
	}
	if end < 2 {
		return 0, fmt.Errorf("%w: LAN raw GSO batch needs at least two GSO packets", errGSOUnsupported)
	}
	scratch := takeLANGSOSendMMSGScratch(end)
	defer putLANGSOSendMMSGScratch(scratch)
	for i := 0; i < end; i++ {
		packet := packets[i]
		virtioHdr, _, err := prepareLANIPv4TCPGSOHeader(packet, injector.mtu, true)
		if err != nil {
			return i, fmt.Errorf("%w: %v", errGSOUnsupported, err)
		}
		header := scratch.virtioHeader(i)
		copy(header, virtioHdr[:])
		ethernet := scratch.ethernetHeader(i)
		copy(ethernet[0:6], dstMAC)
		copy(ethernet[6:12], injector.hardwareAddr)
		binary.BigEndian.PutUint16(ethernet[12:14], etherTypeIPv4)
		resetSendMMSGNoControl(&scratch.msgs[i])
		scratch.addrs[i] = rawSockaddrLinklayer(injector.ifindex, dstMAC)
		iovBase := i * 3
		scratch.iovs[iovBase].Base = &header[0]
		scratch.iovs[iovBase].SetLen(len(header))
		scratch.iovs[iovBase+1].Base = &ethernet[0]
		scratch.iovs[iovBase+1].SetLen(len(ethernet))
		scratch.iovs[iovBase+2].Base = &packet[0]
		scratch.iovs[iovBase+2].SetLen(len(packet))
		scratch.msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&scratch.addrs[i]))
		scratch.msgs[i].hdr.Namelen = unix.SizeofSockaddrLinklayer
		scratch.msgs[i].hdr.Iov = &scratch.iovs[iovBase]
		scratch.msgs[i].hdr.SetIovlen(3)
	}
	injector.mu.Lock()
	defer injector.mu.Unlock()
	if injector.fd < 0 {
		return 0, fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	fd, err := injector.gsoRawSocketLocked()
	if err != nil {
		return 0, err
	}
	lanPacketStats.gsoAttempts.Add(uint64(end))
	lanPacketStats.gsoRawAttempts.Add(uint64(end))
	lanPacketStats.gsoRawBatchAttempts.Add(1)
	sent, err := sendmmsg(fd, scratch.msgs[:end])
	runtime.KeepAlive(scratch.iovs)
	runtime.KeepAlive(scratch.headers)
	runtime.KeepAlive(scratch.ethernets)
	runtime.KeepAlive(packets)
	if err != nil {
		lanPacketStats.recordGSOErrno(err)
		if isPacketSocketGSOUnsupported(err) {
			return sent, errors.Join(
				fmt.Errorf("%w: send LAN raw GSO batch to %s on %q: %v", errGSOUnsupported, dst, injector.ifname, err),
				wrapEBPFOperation("close disabled LAN raw GSO socket", injector.disableRawGSOLocked()),
			)
		}
		return sent, fmt.Errorf("reinject LAN raw GSO IPv4 batch to %s on %q: %w", dst, injector.ifname, err)
	}
	lanPacketStats.gsoSuccesses.Add(uint64(sent))
	lanPacketStats.gsoRawSuccesses.Add(uint64(sent))
	lanPacketStats.gsoRawBatchSuccesses.Add(1)
	lanPacketStats.gsoRawBatchMessages.Add(uint64(sent))
	return sent, nil
}

func (injector *lanPacketInjector) sendRawVNetMixedBatch(packets [][]byte, dst netip.Addr, dstMAC net.HardwareAddr) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(injector.hardwareAddr) < 6 || len(dstMAC) < 6 {
		return 0, fmt.Errorf("%w: LAN raw mixed batch needs Ethernet source and destination MAC", errGSOUnsupported)
	}
	scratch := takeLANGSOSendMMSGScratch(len(packets))
	defer putLANGSOSendMMSGScratch(scratch)
	var gsoPackets int
	for i, packet := range packets {
		if len(packet) == 0 {
			return 0, fmt.Errorf("%w: LAN raw mixed batch has empty packet", errGSOUnsupported)
		}
		header := scratch.virtioHeader(i)
		clear(header)
		if len(packet) > injector.mtu {
			virtioHdr, _, err := prepareLANIPv4TCPGSOHeader(packet, injector.mtu, true)
			if err != nil {
				return 0, fmt.Errorf("%w: %v", errGSOUnsupported, err)
			}
			copy(header, virtioHdr[:])
			gsoPackets++
		}
		ethernet := scratch.ethernetHeader(i)
		copy(ethernet[0:6], dstMAC)
		copy(ethernet[6:12], injector.hardwareAddr)
		binary.BigEndian.PutUint16(ethernet[12:14], etherTypeIPv4)
		resetSendMMSGNoControl(&scratch.msgs[i])
		scratch.addrs[i] = rawSockaddrLinklayer(injector.ifindex, dstMAC)
		iovBase := i * 3
		scratch.iovs[iovBase].Base = &header[0]
		scratch.iovs[iovBase].SetLen(len(header))
		scratch.iovs[iovBase+1].Base = &ethernet[0]
		scratch.iovs[iovBase+1].SetLen(len(ethernet))
		scratch.iovs[iovBase+2].Base = &packet[0]
		scratch.iovs[iovBase+2].SetLen(len(packet))
		scratch.msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&scratch.addrs[i]))
		scratch.msgs[i].hdr.Namelen = unix.SizeofSockaddrLinklayer
		scratch.msgs[i].hdr.Iov = &scratch.iovs[iovBase]
		scratch.msgs[i].hdr.SetIovlen(3)
	}
	if gsoPackets == 0 {
		return 0, nil
	}
	injector.mu.Lock()
	defer injector.mu.Unlock()
	if injector.fd < 0 {
		return 0, fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	fd, err := injector.gsoRawSocketLocked()
	if err != nil {
		return 0, err
	}
	lanPacketStats.gsoAttempts.Add(uint64(gsoPackets))
	lanPacketStats.gsoRawAttempts.Add(uint64(gsoPackets))
	lanPacketStats.gsoRawMixedAttempts.Add(1)
	var sent int
	for sent < len(packets) {
		n, err := sendmmsg(fd, scratch.msgs[sent:])
		if n > 0 {
			sent += n
		}
		if err != nil {
			lanPacketStats.recordGSOErrno(err)
			if isPacketSocketGSOUnsupported(err) {
				return sent, errors.Join(
					fmt.Errorf("%w: send LAN raw mixed batch to %s on %q: %v", errGSOUnsupported, dst, injector.ifname, err),
					wrapEBPFOperation("close disabled LAN raw GSO socket", injector.disableRawGSOLocked()),
				)
			}
			if n > 0 {
				continue
			}
			return sent, fmt.Errorf("reinject LAN raw mixed batch to %s on %q: %w", dst, injector.ifname, err)
		}
		if n <= 0 {
			return sent, fmt.Errorf("reinject LAN raw mixed batch to %s on %q: %w", dst, injector.ifname, unix.EIO)
		}
	}
	runtime.KeepAlive(scratch.iovs)
	runtime.KeepAlive(scratch.headers)
	runtime.KeepAlive(scratch.ethernets)
	runtime.KeepAlive(packets)
	lanPacketStats.gsoSuccesses.Add(uint64(gsoPackets))
	lanPacketStats.gsoRawSuccesses.Add(uint64(gsoPackets))
	lanPacketStats.gsoRawMixedSuccesses.Add(1)
	lanPacketStats.gsoRawMixedMessages.Add(uint64(sent))
	return sent, nil
}

func (injector *lanPacketInjector) sendRawVNetSmallBatches(packets [][]byte, dst netip.Addr, dstMAC net.HardwareAddr) int {
	if len(packets) == 0 {
		return 0
	}
	limit := lanReinjectRawVNetBatchLimit()
	sentTotal := 0
	for sentTotal < len(packets) {
		end := min(sentTotal+limit, len(packets))
		sent, err := injector.sendRawVNetBatch(packets[sentTotal:end], dst, dstMAC)
		if sent > 0 {
			sentTotal += sent
		}
		if err != nil || sent <= 0 {
			return sentTotal
		}
	}
	return sentTotal
}

func (injector *lanPacketInjector) sendRawVNetBatch(packets [][]byte, dst netip.Addr, dstMAC net.HardwareAddr) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(injector.hardwareAddr) < 6 || len(dstMAC) < 6 {
		return 0, fmt.Errorf("%w: LAN raw VNET batch needs Ethernet source and destination MAC", errGSOUnsupported)
	}
	scratch := takeLANGSOSendMMSGScratch(len(packets))
	defer putLANGSOSendMMSGScratch(scratch)
	for i, packet := range packets {
		if len(packet) == 0 {
			return 0, fmt.Errorf("%w: LAN raw VNET batch has empty packet", errGSOUnsupported)
		}
		if len(packet) > injector.mtu {
			return 0, fmt.Errorf("%w: LAN raw VNET packet size %d exceeds MTU %d", errMTUExceeded, len(packet), injector.mtu)
		}
		header := scratch.virtioHeader(i)
		clear(header)
		ethernet := scratch.ethernetHeader(i)
		copy(ethernet[0:6], dstMAC)
		copy(ethernet[6:12], injector.hardwareAddr)
		binary.BigEndian.PutUint16(ethernet[12:14], etherTypeIPv4)
		resetSendMMSGNoControl(&scratch.msgs[i])
		scratch.addrs[i] = rawSockaddrLinklayer(injector.ifindex, dstMAC)
		iovBase := i * 3
		scratch.iovs[iovBase].Base = &header[0]
		scratch.iovs[iovBase].SetLen(len(header))
		scratch.iovs[iovBase+1].Base = &ethernet[0]
		scratch.iovs[iovBase+1].SetLen(len(ethernet))
		scratch.iovs[iovBase+2].Base = &packet[0]
		scratch.iovs[iovBase+2].SetLen(len(packet))
		scratch.msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&scratch.addrs[i]))
		scratch.msgs[i].hdr.Namelen = unix.SizeofSockaddrLinklayer
		scratch.msgs[i].hdr.Iov = &scratch.iovs[iovBase]
		scratch.msgs[i].hdr.SetIovlen(3)
	}
	injector.mu.Lock()
	defer injector.mu.Unlock()
	if injector.fd < 0 {
		return 0, fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	if injector.rawVNetBatchDisabled {
		return 0, fmt.Errorf("%w for %q raw VNET batch", errGSOUnsupported, injector.ifname)
	}
	fd, err := injector.gsoRawSocketLocked()
	if err != nil {
		lanPacketStats.rawVNetBatchUnsupported.Add(1)
		return 0, err
	}
	lanPacketStats.rawVNetBatchAttempts.Add(1)
	var sent int
	for sent < len(packets) {
		n, err := sendmmsg(fd, scratch.msgs[sent:])
		if n > 0 {
			sent += n
		}
		if err != nil {
			lanPacketStats.rawVNetBatchErrors.Add(1)
			lanPacketStats.recordGSOErrno(err)
			if isPacketSocketGSOUnsupported(err) {
				injector.rawVNetBatchDisabled = true
				lanPacketStats.rawVNetBatchUnsupported.Add(1)
				if sent > 0 {
					lanPacketStats.rawVNetBatchMessages.Add(uint64(sent))
				}
				return sent, fmt.Errorf("%w: send LAN raw VNET batch to %s on %q: %v", errGSOUnsupported, dst, injector.ifname, err)
			}
			if n > 0 {
				continue
			}
			if sent > 0 {
				lanPacketStats.rawVNetBatchMessages.Add(uint64(sent))
			}
			return sent, fmt.Errorf("reinject LAN raw VNET batch to %s on %q: %w", dst, injector.ifname, err)
		}
		if n <= 0 {
			lanPacketStats.rawVNetBatchErrors.Add(1)
			if sent > 0 {
				lanPacketStats.rawVNetBatchMessages.Add(uint64(sent))
			}
			return sent, fmt.Errorf("reinject LAN raw VNET batch to %s on %q: %w", dst, injector.ifname, unix.EIO)
		}
	}
	runtime.KeepAlive(scratch.iovs)
	runtime.KeepAlive(scratch.headers)
	runtime.KeepAlive(scratch.ethernets)
	runtime.KeepAlive(packets)
	lanPacketStats.rawVNetBatchSuccesses.Add(1)
	lanPacketStats.rawVNetBatchMessages.Add(uint64(sent))
	return sent, nil
}

func (injector *lanPacketInjector) sendRawGSOScatterRun(packets [][]byte, dst netip.Addr, dstMAC net.HardwareAddr) (int, error) {
	if len(packets) < 2 {
		return 0, nil
	}
	if len(injector.hardwareAddr) < 6 || len(dstMAC) < 6 {
		return 0, fmt.Errorf("%w: LAN raw GSO scatter needs Ethernet source and destination MAC", errGSOUnsupported)
	}
	run, meta, totalLen, ok := lanIPv4TCPGSOScatterRun(packets, injector.mtu)
	if !ok || run < 2 || totalLen <= injector.mtu {
		return 0, nil
	}
	if totalLen > 0xffff {
		return 0, fmt.Errorf("%w: LAN raw GSO scatter packet size %d exceeds IPv4 length", errMTUExceeded, totalLen)
	}
	scratch := takeLANGSOSendMMSGScratch(1)
	defer putLANGSOSendMMSGScratch(scratch)
	packet := packets[0]
	header := scratch.virtioHeader(0)
	virtioHdr, err := prepareLANIPv4TCPGSOScatterHeader(header, packet, meta, injector.mtu, totalLen, true)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errGSOUnsupported, err)
	}
	ethernet := scratch.ethernetHeader(0)
	copy(ethernet[0:6], dstMAC)
	copy(ethernet[6:12], injector.hardwareAddr)
	binary.BigEndian.PutUint16(ethernet[12:14], etherTypeIPv4)
	ipHeader := scratch.ipHeader(0, meta.payloadOffset)
	copy(ipHeader, packet[:meta.payloadOffset])
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	ipHeader[6] &^= 0x20
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	binary.BigEndian.PutUint16(ipHeader[10:12], captureChecksum(ipHeader[:meta.ihl]))
	tcpHeader := ipHeader[meta.tcpOffset:meta.payloadOffset]
	tcpHeader[13] = lanIPv4TCPGSOScatterFlags(packets[:run], meta)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpPseudoHeaderPartialChecksum(ipHeader, totalLen-meta.tcpOffset))

	iovCount := 3 + run
	if cap(scratch.iovs) < iovCount {
		scratch.iovs = make([]unix.Iovec, iovCount)
	} else {
		scratch.iovs = scratch.iovs[:iovCount]
	}
	scratch.iovs[0].Base = &virtioHdr[0]
	scratch.iovs[0].SetLen(len(virtioHdr))
	scratch.iovs[1].Base = &ethernet[0]
	scratch.iovs[1].SetLen(len(ethernet))
	scratch.iovs[2].Base = &ipHeader[0]
	scratch.iovs[2].SetLen(len(ipHeader))
	for i := 0; i < run; i++ {
		payload := packets[i][meta.payloadOffset:]
		scratch.iovs[3+i].Base = &payload[0]
		scratch.iovs[3+i].SetLen(len(payload))
	}
	addr := rawSockaddrLinklayer(injector.ifindex, dstMAC)
	injector.mu.Lock()
	defer injector.mu.Unlock()
	if injector.fd < 0 {
		return 0, fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	fd, err := injector.gsoRawSocketLocked()
	if err != nil {
		return 0, err
	}
	lanPacketStats.gsoAttempts.Add(1)
	lanPacketStats.gsoRawAttempts.Add(1)
	lanPacketStats.gsoRawScatterAttempts.Add(1)
	n, err := sendmsgRaw(fd, &addr, scratch.iovs[:iovCount])
	runtime.KeepAlive(virtioHdr)
	runtime.KeepAlive(ethernet)
	runtime.KeepAlive(ipHeader)
	runtime.KeepAlive(packets)
	if err != nil {
		lanPacketStats.recordGSOErrno(err)
		if isPacketSocketGSOUnsupported(err) {
			return 0, errors.Join(
				fmt.Errorf("%w: send LAN raw GSO scatter to %s on %q: %v", errGSOUnsupported, dst, injector.ifname, err),
				wrapEBPFOperation("close disabled LAN raw GSO socket", injector.disableRawGSOLocked()),
			)
		}
		return 0, fmt.Errorf("reinject LAN raw GSO scatter IPv4 packet to %s on %q: %w", dst, injector.ifname, err)
	}
	if n != virtioNetHdrLen+ethernetHeaderLen+totalLen {
		return 0, fmt.Errorf("reinject LAN raw GSO scatter IPv4 packet to %s on %q: short write %d/%d", dst, injector.ifname, n, virtioNetHdrLen+ethernetHeaderLen+totalLen)
	}
	lanPacketStats.gsoSuccesses.Add(1)
	lanPacketStats.gsoRawSuccesses.Add(1)
	lanPacketStats.gsoRawScatterSuccesses.Add(1)
	lanPacketStats.gsoRawScatterMessages.Add(uint64(run))
	return run, nil
}

func lanReinjectGSOEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_LAN_REINJECT_GSO"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func lanReinjectGSORawBatchEnabled() bool {
	return envTruthy("TRUSTIX_LAN_REINJECT_GSO_RAW_BATCH")
}

func lanReinjectGSORawMixedBatchEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_LAN_REINJECT_GSO_RAW_MIXED_BATCH"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func lanReinjectGSORawMixedBatchLimit() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_LAN_REINJECT_GSO_RAW_MIXED_BATCH_LIMIT"))
	if value == "" {
		return lanGSORawMixedBatchDefaultLimit
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return lanGSORawMixedBatchDefaultLimit
	}
	if parsed > 256 {
		return 256
	}
	return parsed
}

func lanReinjectRawVNetBatchEnabled() bool {
	return !envFalsey("TRUSTIX_LAN_REINJECT_RAW_VNET_BATCH", "TRUSTIX_LAN_REINJECT_GSO_RAW_VNET_BATCH")
}

func lanReinjectRawVNetBatchLimit() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_LAN_REINJECT_RAW_VNET_BATCH_LIMIT"))
	if value == "" {
		return lanGSORawMixedBatchDefaultLimit
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return lanGSORawMixedBatchDefaultLimit
	}
	if parsed > 256 {
		return 256
	}
	return parsed
}

func lanReinjectGSOScatterEnabled() bool {
	return envTruthy("TRUSTIX_LAN_REINJECT_GSO_SCATTER")
}

func lanReinjectGSOScatterMaxIPv4Len() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_LAN_REINJECT_GSO_SCATTER_MAX_IPV4_LEN"))
	if value == "" {
		return lanGSOScatterDefaultMaxIPv4Len
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1500 {
		return lanGSOScatterDefaultMaxIPv4Len
	}
	if parsed > 0xffff {
		return 0xffff
	}
	return parsed
}

func lanReinjectGSOScatterMaxSegments() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_LAN_REINJECT_GSO_SCATTER_MAX_SEGMENTS"))
	if value == "" {
		return lanGSOScatterDefaultMaxSegments
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 2 {
		return lanGSOScatterDefaultMaxSegments
	}
	if parsed > 256 {
		return 256
	}
	return parsed
}

func lanIPv4BatchHasGSOPacket(packets [][]byte, mtu int) bool {
	for _, packet := range packets {
		if len(packet) > mtu {
			return true
		}
	}
	return false
}

func lanIPv4TCPGSOScatterRun(packets [][]byte, mtu int) (int, lanIPv4TCPSegmentMeta, int, bool) {
	if len(packets) < 2 {
		return 0, lanIPv4TCPSegmentMeta{}, 0, false
	}
	maxIPv4Len := lanReinjectGSOScatterMaxIPv4Len()
	if maxIPv4Len < mtu {
		maxIPv4Len = mtu
	}
	if maxIPv4Len > 0xffff {
		maxIPv4Len = 0xffff
	}
	maxSegments := lanReinjectGSOScatterMaxSegments()
	if maxSegments < 2 {
		maxSegments = 2
	}
	first := packets[0]
	meta, err := lanIPv4TCPSegmentationMeta(first, mtu)
	if err != nil || len(first) > mtu {
		return 0, lanIPv4TCPSegmentMeta{}, 0, false
	}
	if len(first) <= meta.payloadOffset {
		return 0, lanIPv4TCPSegmentMeta{}, 0, false
	}
	tcp := first[meta.tcpOffset:meta.payloadOffset]
	if !lanIPv4TCPGSOScatterFlagsOK(tcp[13]) {
		return 0, lanIPv4TCPSegmentMeta{}, 0, false
	}
	sourcePort := binary.BigEndian.Uint16(tcp[0:2])
	destinationPort := binary.BigEndian.Uint16(tcp[2:4])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	window := binary.BigEndian.Uint16(tcp[14:16])
	urgent := binary.BigEndian.Uint16(tcp[18:20])
	nextSeq := binary.BigEndian.Uint32(tcp[4:8]) + uint32(len(first)-meta.payloadOffset)
	totalLen := len(first)
	run := 1
	for run < len(packets) && run < maxSegments {
		packet := packets[run]
		nextMeta, err := lanIPv4TCPSegmentationMeta(packet, mtu)
		if err != nil || len(packet) > mtu ||
			nextMeta.ihl != meta.ihl ||
			nextMeta.tcpOffset != meta.tcpOffset ||
			nextMeta.tcpHeaderLen != meta.tcpHeaderLen ||
			nextMeta.payloadOffset != meta.payloadOffset ||
			len(packet) <= nextMeta.payloadOffset {
			break
		}
		if !bytes.Equal(first[12:20], packet[12:20]) {
			break
		}
		if !bytes.Equal(first[meta.tcpOffset+20:meta.payloadOffset], packet[nextMeta.tcpOffset+20:nextMeta.payloadOffset]) {
			break
		}
		nextTCP := packet[nextMeta.tcpOffset:nextMeta.payloadOffset]
		if binary.BigEndian.Uint16(nextTCP[0:2]) != sourcePort ||
			binary.BigEndian.Uint16(nextTCP[2:4]) != destinationPort ||
			binary.BigEndian.Uint32(nextTCP[4:8]) != nextSeq ||
			binary.BigEndian.Uint32(nextTCP[8:12]) != ack ||
			binary.BigEndian.Uint16(nextTCP[14:16]) != window ||
			binary.BigEndian.Uint16(nextTCP[18:20]) != urgent ||
			!lanIPv4TCPGSOScatterFlagsOK(nextTCP[13]) {
			break
		}
		if tcp[12] != nextTCP[12] {
			break
		}
		payloadLen := len(packet) - nextMeta.payloadOffset
		if totalLen+payloadLen > maxIPv4Len {
			break
		}
		totalLen += payloadLen
		nextSeq += uint32(payloadLen)
		run++
	}
	if run < 2 {
		return 0, lanIPv4TCPSegmentMeta{}, 0, false
	}
	return run, meta, totalLen, true
}

func lanIPv4TCPGSOScatterFlagsOK(flags byte) bool {
	return flags == 0x10 || flags == 0x18
}

func lanIPv4TCPGSOScatterFlags(packets [][]byte, meta lanIPv4TCPSegmentMeta) byte {
	flags := packets[0][meta.tcpOffset+13]
	for i := 1; i < len(packets); i++ {
		flags |= packets[i][meta.tcpOffset+13] & 0x08
	}
	return flags
}

func prepareLANIPv4TCPGSOScatterHeader(hdr []byte, packet []byte, meta lanIPv4TCPSegmentMeta, mtu int, totalLen int, raw bool) ([]byte, error) {
	if len(hdr) < virtioNetHdrLen {
		return nil, fmt.Errorf("%w: short LAN GSO scatter virtio header", errGSOUnsupported)
	}
	headerLen := meta.ihl + meta.tcpHeaderLen
	csumStart := meta.tcpOffset
	if raw {
		headerLen += ethernetHeaderLen
		csumStart += ethernetHeaderLen
	}
	if meta.ihl+meta.tcpHeaderLen > len(packet) || totalLen < meta.payloadOffset {
		return nil, fmt.Errorf("%w: invalid LAN GSO scatter packet bounds", errMTUExceeded)
	}
	if headerLen > 0xffff || meta.maxPayload > 0xffff || csumStart > 0xffff {
		return nil, fmt.Errorf("%w: LAN GSO scatter header length %d, checksum start %d, or size %d exceeds virtio header limits", errMTUExceeded, headerLen, csumStart, meta.maxPayload)
	}
	clear(hdr[:virtioNetHdrLen])
	hdr[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	hdr[1] = unix.VIRTIO_NET_HDR_GSO_TCPV4
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(headerLen))
	binary.LittleEndian.PutUint16(hdr[4:6], uint16(mtu-meta.ihl-meta.tcpHeaderLen))
	binary.LittleEndian.PutUint16(hdr[6:8], uint16(csumStart))
	binary.LittleEndian.PutUint16(hdr[8:10], 16)
	return hdr[:virtioNetHdrLen], nil
}

func segmentLANIPv4TCPPacket(packet []byte, mtu int) ([][]byte, error) {
	if len(packet) <= mtu {
		return [][]byte{packet}, nil
	}
	meta, err := lanIPv4TCPSegmentationMeta(packet, mtu)
	if err != nil {
		return nil, err
	}
	payload := packet[meta.payloadOffset:]
	segments := make([][]byte, 0, (len(payload)+meta.maxPayload-1)/meta.maxPayload)
	originalSeq := binary.BigEndian.Uint32(packet[meta.tcpOffset+4 : meta.tcpOffset+8])
	originalID := binary.BigEndian.Uint16(packet[4:6])
	for offset := 0; offset < len(payload); offset += meta.maxPayload {
		chunkLen := min(meta.maxPayload, len(payload)-offset)
		segmentLen := meta.ihl + meta.tcpHeaderLen + chunkLen
		segment := make([]byte, segmentLen)
		copy(segment[:meta.ihl], packet[:meta.ihl])
		copy(segment[meta.ihl:meta.ihl+meta.tcpHeaderLen], packet[meta.tcpOffset:meta.payloadOffset])
		copy(segment[meta.ihl+meta.tcpHeaderLen:], payload[offset:offset+chunkLen])

		binary.BigEndian.PutUint16(segment[2:4], uint16(segmentLen))
		binary.BigEndian.PutUint16(segment[4:6], originalID+uint16(len(segments)))
		binary.BigEndian.PutUint16(segment[10:12], 0)
		binary.BigEndian.PutUint16(segment[10:12], captureChecksum(segment[:meta.ihl]))

		tcp := segment[meta.ihl:]
		binary.BigEndian.PutUint32(tcp[4:8], originalSeq+uint32(offset))
		if offset+chunkLen < len(payload) {
			tcp[13] &^= 0x09
		}
		binary.BigEndian.PutUint16(tcp[16:18], 0)
		binary.BigEndian.PutUint16(tcp[16:18], captureTransportChecksum(segment[12:16], segment[16:20], ipProtocolTCP, tcp))
		segments = append(segments, segment)
	}
	return segments, nil
}

type lanIPv4TCPSegmentMeta struct {
	ihl           int
	tcpOffset     int
	tcpHeaderLen  int
	payloadOffset int
	maxPayload    int
}

func lanIPv4TCPSegmentationMeta(packet []byte, mtu int) (lanIPv4TCPSegmentMeta, error) {
	fail := func(format string, args ...any) ([][]byte, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{errMTUExceeded}, args...)...)
	}
	failMeta := func(format string, args ...any) (lanIPv4TCPSegmentMeta, error) {
		_, err := fail(format, args...)
		return lanIPv4TCPSegmentMeta{}, err
	}
	if mtu <= rejectIPv4HeaderLen+rejectTCPHeaderLen {
		return failMeta("LAN MTU %d cannot carry an IPv4/TCP header", mtu)
	}
	if len(packet) < rejectIPv4HeaderLen {
		return failMeta("LAN packet size %d exceeds MTU %d and is too short for IPv4", len(packet), mtu)
	}
	if packet[0]>>4 != 4 {
		return failMeta("LAN packet size %d exceeds MTU %d and is not IPv4", len(packet), mtu)
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl != rejectIPv4HeaderLen || len(packet) < ihl {
		return failMeta("LAN packet size %d exceeds MTU %d and has unsupported IPv4 header length %d", len(packet), mtu, ihl)
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) {
		return failMeta("LAN packet size %d exceeds MTU %d with IPv4 total length %d", len(packet), mtu, totalLen)
	}
	if packet[9] != ipProtocolTCP {
		return failMeta("LAN packet size %d exceeds MTU %d and protocol %d is not TCP", len(packet), mtu, packet[9])
	}
	flagsAndFragment := binary.BigEndian.Uint16(packet[6:8])
	if flagsAndFragment&(0x2000|0x1fff) != 0 {
		return failMeta("LAN packet size %d exceeds MTU %d and is already fragmented", len(packet), mtu)
	}
	tcpOffset := ihl
	if len(packet) < tcpOffset+rejectTCPHeaderLen {
		return failMeta("LAN packet size %d exceeds MTU %d and is too short for TCP", len(packet), mtu)
	}
	tcpHeaderLen := int(packet[tcpOffset+12]>>4) * 4
	if tcpHeaderLen < rejectTCPHeaderLen || len(packet) < tcpOffset+tcpHeaderLen {
		return failMeta("LAN packet size %d exceeds MTU %d and has invalid TCP header length %d", len(packet), mtu, tcpHeaderLen)
	}
	tcpFlags := packet[tcpOffset+13]
	if tcpFlags&(0x02|0x04|0x20) != 0 {
		return failMeta("LAN packet size %d exceeds MTU %d and has unsupported TCP flags %#x", len(packet), mtu, tcpFlags)
	}
	payloadOffset := tcpOffset + tcpHeaderLen
	payload := packet[payloadOffset:]
	if len(payload) == 0 {
		return failMeta("LAN packet size %d exceeds MTU %d without TCP payload to segment", len(packet), mtu)
	}
	maxPayload := mtu - ihl - tcpHeaderLen
	if maxPayload <= 0 {
		return failMeta("LAN MTU %d cannot carry IPv4/TCP headers of %d bytes", mtu, ihl+tcpHeaderLen)
	}
	return lanIPv4TCPSegmentMeta{
		ihl:           ihl,
		tcpOffset:     tcpOffset,
		tcpHeaderLen:  tcpHeaderLen,
		payloadOffset: payloadOffset,
		maxPayload:    maxPayload,
	}, nil
}

func prepareLANIPv4TCPGSOPacket(packet []byte, mtu int) ([]byte, error) {
	meta, err := lanIPv4TCPSegmentationMeta(packet, mtu)
	if err != nil {
		return nil, err
	}
	if meta.ihl+meta.tcpHeaderLen > 0xffff || meta.maxPayload > 0xffff {
		return nil, fmt.Errorf("%w: LAN GSO header length %d or size %d exceeds virtio header limits", errMTUExceeded, meta.ihl+meta.tcpHeaderLen, meta.maxPayload)
	}
	wire := make([]byte, virtioNetHdrLen+len(packet))
	wire[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	wire[1] = unix.VIRTIO_NET_HDR_GSO_TCPV4
	binary.LittleEndian.PutUint16(wire[2:4], uint16(meta.ihl+meta.tcpHeaderLen))
	binary.LittleEndian.PutUint16(wire[4:6], uint16(meta.maxPayload))
	binary.LittleEndian.PutUint16(wire[6:8], uint16(meta.tcpOffset))
	binary.LittleEndian.PutUint16(wire[8:10], 16)
	copy(wire[virtioNetHdrLen:], packet)
	ip := wire[virtioNetHdrLen:]
	tcp := ip[meta.tcpOffset:]
	binary.BigEndian.PutUint16(tcp[16:18], tcpPseudoHeaderPartialChecksum(ip, len(tcp)))
	return wire, nil
}

func prepareLANIPv4TCPGSORawPacket(packet []byte, mtu int, srcMAC, dstMAC net.HardwareAddr) ([]byte, error) {
	if len(srcMAC) < 6 || len(dstMAC) < 6 {
		return nil, fmt.Errorf("%w: LAN GSO raw packet needs Ethernet source and destination MAC", errGSOUnsupported)
	}
	meta, err := lanIPv4TCPSegmentationMeta(packet, mtu)
	if err != nil {
		return nil, err
	}
	if ethernetHeaderLen+meta.ihl+meta.tcpHeaderLen > 0xffff || meta.maxPayload > 0xffff {
		return nil, fmt.Errorf("%w: LAN raw GSO header length %d or size %d exceeds virtio header limits", errMTUExceeded, ethernetHeaderLen+meta.ihl+meta.tcpHeaderLen, meta.maxPayload)
	}
	wire := make([]byte, virtioNetHdrLen+ethernetHeaderLen+len(packet))
	wire[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	wire[1] = unix.VIRTIO_NET_HDR_GSO_TCPV4
	binary.LittleEndian.PutUint16(wire[2:4], uint16(ethernetHeaderLen+meta.ihl+meta.tcpHeaderLen))
	binary.LittleEndian.PutUint16(wire[4:6], uint16(meta.maxPayload))
	binary.LittleEndian.PutUint16(wire[6:8], uint16(ethernetHeaderLen+meta.tcpOffset))
	binary.LittleEndian.PutUint16(wire[8:10], 16)
	ethernet := wire[virtioNetHdrLen:]
	copy(ethernet[0:6], dstMAC)
	copy(ethernet[6:12], srcMAC)
	binary.BigEndian.PutUint16(ethernet[12:14], etherTypeIPv4)
	copy(ethernet[ethernetHeaderLen:], packet)
	ip := ethernet[ethernetHeaderLen:]
	tcp := ip[meta.tcpOffset:]
	binary.BigEndian.PutUint16(tcp[16:18], tcpPseudoHeaderPartialChecksum(ip, len(tcp)))
	return wire, nil
}

func prepareLANIPv4TCPGSOHeader(packet []byte, mtu int, raw bool) ([virtioNetHdrLen]byte, lanIPv4TCPSegmentMeta, error) {
	meta, err := lanIPv4TCPSegmentationMeta(packet, mtu)
	if err != nil {
		return [virtioNetHdrLen]byte{}, lanIPv4TCPSegmentMeta{}, err
	}
	headerLen := meta.ihl + meta.tcpHeaderLen
	csumStart := meta.tcpOffset
	if raw {
		headerLen += ethernetHeaderLen
		csumStart += ethernetHeaderLen
	}
	if headerLen > 0xffff || meta.maxPayload > 0xffff || csumStart > 0xffff {
		return [virtioNetHdrLen]byte{}, lanIPv4TCPSegmentMeta{}, fmt.Errorf("%w: LAN GSO header length %d, checksum start %d, or size %d exceeds virtio header limits", errMTUExceeded, headerLen, csumStart, meta.maxPayload)
	}
	var hdr [virtioNetHdrLen]byte
	hdr[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	hdr[1] = unix.VIRTIO_NET_HDR_GSO_TCPV4
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(headerLen))
	binary.LittleEndian.PutUint16(hdr[4:6], uint16(meta.maxPayload))
	binary.LittleEndian.PutUint16(hdr[6:8], uint16(csumStart))
	binary.LittleEndian.PutUint16(hdr[8:10], 16)
	tcp := packet[meta.tcpOffset:]
	binary.BigEndian.PutUint16(tcp[16:18], tcpPseudoHeaderPartialChecksum(packet, len(tcp)))
	return hdr, meta, nil
}

func tcpPseudoHeaderPartialChecksum(ip []byte, tcpLen int) uint16 {
	sum := captureChecksumAddBytes(0, ip[12:16])
	sum = captureChecksumAddBytes(sum, ip[16:20])
	sum += uint32(ipProtocolTCP)
	sum += uint32(tcpLen)
	return ^captureChecksumFold(sum)
}

func (injector *lanPacketInjector) send(packet []byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	var lladdr [8]byte
	copy(lladdr[:], dstMAC)
	injector.mu.RLock()
	defer injector.mu.RUnlock()
	if injector.fd < 0 {
		return fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	if err := unix.Sendto(injector.fd, packet, 0, &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeIPv4),
		Ifindex:  injector.ifindex,
		Halen:    uint8(len(dstMAC)),
		Addr:     lladdr,
	}); err != nil {
		return fmt.Errorf("reinject LAN IPv4 packet to %s on %q: %w", dst, injector.ifname, err)
	}
	lanPacketStats.singleSendPackets.Add(1)
	return nil
}

func (injector *lanPacketInjector) sendBatch(packets [][]byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	for _, packet := range packets {
		if len(packet) > injector.mtu {
			return fmt.Errorf("%w: LAN packet size %d exceeds MTU %d", errMTUExceeded, len(packet), injector.mtu)
		}
	}
	injector.mu.RLock()
	defer injector.mu.RUnlock()
	if injector.fd < 0 {
		return fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	lanPacketStats.batchSendAttempts.Add(1)
	sent, err := sendLANIPv4PacketBatch(injector.fd, injector.ifindex, packets, dstMAC)
	if err != nil {
		lanPacketStats.batchSendErrors.Add(1)
		return fmt.Errorf("reinject LAN IPv4 packet batch to %s on %q: %w", dst, injector.ifname, err)
	}
	lanPacketStats.batchSendMessages.Add(uint64(sent))
	return nil
}

func (injector *lanPacketInjector) sendLANIPv4TCPGSO(packet []byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	var failures []error
	if err := injector.sendRawGSO(packet, dst, dstMAC); err == nil {
		lanPacketStats.gsoRawSuccesses.Add(1)
		return nil
	} else {
		failures = append(failures, err)
	}
	if err := injector.sendCookedGSO(packet, dst, dstMAC); err == nil {
		lanPacketStats.gsoCookedSuccesses.Add(1)
		return nil
	} else {
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return fmt.Errorf("%w for %q", errGSOUnsupported, injector.ifname)
	}
	return errors.Join(failures...)
}

func (injector *lanPacketInjector) sendLANIPv4TCPGSOContiguous(packet []byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	var failures []error
	if rawPacket, err := prepareLANIPv4TCPGSORawPacket(packet, injector.mtu, injector.hardwareAddr, dstMAC); err == nil {
		if err := injector.sendRawGSOContiguous(rawPacket, dst, dstMAC); err == nil {
			lanPacketStats.gsoRawSuccesses.Add(1)
			return nil
		} else {
			failures = append(failures, err)
		}
	} else if !errors.Is(err, errMTUExceeded) {
		failures = append(failures, err)
	}
	if cookedPacket, err := prepareLANIPv4TCPGSOPacket(packet, injector.mtu); err == nil {
		if err := injector.sendCookedGSOContiguous(cookedPacket, dst, dstMAC); err == nil {
			lanPacketStats.gsoCookedSuccesses.Add(1)
			return nil
		} else {
			failures = append(failures, err)
		}
	} else {
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return fmt.Errorf("%w for %q", errGSOUnsupported, injector.ifname)
	}
	return errors.Join(failures...)
}

func (injector *lanPacketInjector) sendRawGSO(packet []byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	if len(injector.hardwareAddr) < 6 || len(dstMAC) < 6 {
		return fmt.Errorf("%w: LAN raw GSO packet needs Ethernet source and destination MAC", errGSOUnsupported)
	}
	virtioHdr, _, err := prepareLANIPv4TCPGSOHeader(packet, injector.mtu, true)
	if err != nil {
		return fmt.Errorf("%w: %v", errGSOUnsupported, err)
	}
	var ethernet [ethernetHeaderLen]byte
	copy(ethernet[0:6], dstMAC)
	copy(ethernet[6:12], injector.hardwareAddr)
	binary.BigEndian.PutUint16(ethernet[12:14], etherTypeIPv4)
	addr := rawSockaddrLinklayer(injector.ifindex, dstMAC)
	var iovs [3]unix.Iovec
	iovs[0].Base = &virtioHdr[0]
	iovs[0].SetLen(len(virtioHdr))
	iovs[1].Base = &ethernet[0]
	iovs[1].SetLen(len(ethernet))
	iovs[2].Base = &packet[0]
	iovs[2].SetLen(len(packet))
	injector.mu.Lock()
	defer injector.mu.Unlock()
	if injector.fd < 0 {
		return fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	fd, err := injector.gsoRawSocketLocked()
	if err != nil {
		return err
	}
	lanPacketStats.gsoRawAttempts.Add(1)
	n, err := sendmsgRaw(fd, &addr, iovs[:])
	runtime.KeepAlive(virtioHdr)
	runtime.KeepAlive(ethernet)
	runtime.KeepAlive(packet)
	if err != nil {
		lanPacketStats.recordGSOErrno(err)
		if isPacketSocketGSOUnsupported(err) {
			return errors.Join(
				fmt.Errorf("%w: send LAN raw GSO packet to %s on %q: %v", errGSOUnsupported, dst, injector.ifname, err),
				wrapEBPFOperation("close disabled LAN raw GSO socket", injector.disableRawGSOLocked()),
			)
		}
		return fmt.Errorf("reinject LAN raw GSO IPv4 packet to %s on %q: %w", dst, injector.ifname, err)
	}
	if n != len(virtioHdr)+len(ethernet)+len(packet) {
		return fmt.Errorf("reinject LAN raw GSO IPv4 packet to %s on %q: short write %d/%d", dst, injector.ifname, n, len(virtioHdr)+len(ethernet)+len(packet))
	}
	return nil
}

func (injector *lanPacketInjector) sendCookedGSO(packet []byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	virtioHdr, _, err := prepareLANIPv4TCPGSOHeader(packet, injector.mtu, false)
	if err != nil {
		return fmt.Errorf("%w: %v", errGSOUnsupported, err)
	}
	addr := rawSockaddrLinklayer(injector.ifindex, dstMAC)
	var iovs [2]unix.Iovec
	iovs[0].Base = &virtioHdr[0]
	iovs[0].SetLen(len(virtioHdr))
	iovs[1].Base = &packet[0]
	iovs[1].SetLen(len(packet))
	injector.mu.Lock()
	defer injector.mu.Unlock()
	if injector.fd < 0 {
		return fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	fd, err := injector.gsoCookedSocketLocked()
	if err != nil {
		return err
	}
	lanPacketStats.gsoCookedAttempts.Add(1)
	n, err := sendmsgRaw(fd, &addr, iovs[:])
	runtime.KeepAlive(virtioHdr)
	runtime.KeepAlive(packet)
	if err != nil {
		lanPacketStats.recordGSOErrno(err)
		if isPacketSocketGSOUnsupported(err) {
			return errors.Join(
				fmt.Errorf("%w: send LAN cooked GSO packet to %s on %q: %v", errGSOUnsupported, dst, injector.ifname, err),
				wrapEBPFOperation("close disabled LAN cooked GSO socket", injector.disableCookedGSOLocked()),
			)
		}
		return fmt.Errorf("reinject LAN cooked GSO IPv4 packet to %s on %q: %w", dst, injector.ifname, err)
	}
	if n != len(virtioHdr)+len(packet) {
		return fmt.Errorf("reinject LAN cooked GSO IPv4 packet to %s on %q: short write %d/%d", dst, injector.ifname, n, len(virtioHdr)+len(packet))
	}
	return nil
}

func (injector *lanPacketInjector) sendRawGSOContiguous(packet []byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	var lladdr [8]byte
	copy(lladdr[:], dstMAC)
	injector.mu.Lock()
	defer injector.mu.Unlock()
	if injector.fd < 0 {
		return fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	fd, err := injector.gsoRawSocketLocked()
	if err != nil {
		return err
	}
	lanPacketStats.gsoRawAttempts.Add(1)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeIPv4),
		Ifindex:  injector.ifindex,
		Halen:    uint8(len(dstMAC)),
		Addr:     lladdr,
	}); err != nil {
		lanPacketStats.recordGSOErrno(err)
		if isPacketSocketGSOUnsupported(err) {
			return errors.Join(
				fmt.Errorf("%w: send LAN raw GSO packet to %s on %q: %v", errGSOUnsupported, dst, injector.ifname, err),
				wrapEBPFOperation("close disabled LAN raw GSO socket", injector.disableRawGSOLocked()),
			)
		}
		return fmt.Errorf("reinject LAN raw GSO IPv4 packet to %s on %q: %w", dst, injector.ifname, err)
	}
	return nil
}

func (injector *lanPacketInjector) sendCookedGSOContiguous(packet []byte, dst netip.Addr, dstMAC net.HardwareAddr) error {
	var lladdr [8]byte
	copy(lladdr[:], dstMAC)
	injector.mu.Lock()
	defer injector.mu.Unlock()
	if injector.fd < 0 {
		return fmt.Errorf("LAN packet reinject socket for %q is closed", injector.ifname)
	}
	fd, err := injector.gsoCookedSocketLocked()
	if err != nil {
		return err
	}
	lanPacketStats.gsoCookedAttempts.Add(1)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeIPv4),
		Ifindex:  injector.ifindex,
		Halen:    uint8(len(dstMAC)),
		Addr:     lladdr,
	}); err != nil {
		lanPacketStats.recordGSOErrno(err)
		if isPacketSocketGSOUnsupported(err) {
			return errors.Join(
				fmt.Errorf("%w: send LAN cooked GSO packet to %s on %q: %v", errGSOUnsupported, dst, injector.ifname, err),
				wrapEBPFOperation("close disabled LAN cooked GSO socket", injector.disableCookedGSOLocked()),
			)
		}
		return fmt.Errorf("reinject LAN cooked GSO IPv4 packet to %s on %q: %w", dst, injector.ifname, err)
	}
	return nil
}

func (injector *lanPacketInjector) gsoRawSocketLocked() (int, error) {
	if injector.gsoRawDisabled {
		return -1, fmt.Errorf("%w for %q raw packet socket", errGSOUnsupported, injector.ifname)
	}
	if injector.gsoRawFD >= 0 {
		return injector.gsoRawFD, nil
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherTypeIPv4)))
	if err != nil {
		return -1, fmt.Errorf("%w: open LAN raw GSO packet reinject socket for %q: %v", errGSOUnsupported, injector.ifname, err)
	}
	if err := configureGSOPacketSocket(fd); err != nil {
		injector.gsoRawDisabled = true
		return -1, errors.Join(
			fmt.Errorf("%w: configure raw GSO packet socket on %q: %v", errGSOUnsupported, injector.ifname, err),
			wrapEBPFOperation("close failed raw GSO packet socket", unix.Close(fd)),
		)
	}
	injector.gsoRawFD = fd
	return fd, nil
}

func (injector *lanPacketInjector) gsoCookedSocketLocked() (int, error) {
	if injector.gsoDisabled {
		return -1, fmt.Errorf("%w for %q cooked packet socket", errGSOUnsupported, injector.ifname)
	}
	if injector.gsoFD >= 0 {
		return injector.gsoFD, nil
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(etherTypeIPv4)))
	if err != nil {
		return -1, fmt.Errorf("%w: open LAN GSO packet reinject socket for %q: %v", errGSOUnsupported, injector.ifname, err)
	}
	if err := configureGSOPacketSocket(fd); err != nil {
		injector.gsoDisabled = true
		return -1, errors.Join(
			fmt.Errorf("%w: configure cooked GSO packet socket on %q: %v", errGSOUnsupported, injector.ifname, err),
			wrapEBPFOperation("close failed cooked GSO packet socket", unix.Close(fd)),
		)
	}
	injector.gsoFD = fd
	return fd, nil
}

func configureGSOPacketSocket(fd int) error {
	if err := configureLANPacketSocket(fd); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR_SZ, virtioNetHdrLen); err != nil {
		if !isPacketVNetHeaderSizeOptionalError(err) {
			return fmt.Errorf("set PACKET_VNET_HDR_SZ: %w", err)
		}
		lanPacketStats.gsoVNetHdrSizeFallbacks.Add(1)
	} else {
		lanPacketStats.gsoVNetHdrSizeConfigured.Add(1)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
		return fmt.Errorf("enable PACKET_VNET_HDR: %w", err)
	}
	if lanReinjectGSOQdiscBypassEnabled() {
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_QDISC_BYPASS, 1); err != nil {
			return fmt.Errorf("enable PACKET_QDISC_BYPASS: %w", err)
		}
	}
	return nil
}

func isPacketVNetHeaderSizeOptionalError(err error) bool {
	switch packetSocketGSOErrno(err) {
	case unix.EINVAL, unix.ENOPROTOOPT, unix.EOPNOTSUPP:
		return true
	default:
		return false
	}
}

func configureLANPacketSocket(fd int) error {
	sendBuffer := lanReinjectSocketSendBuffer()
	if sendBuffer <= 0 {
		return nil
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, sendBuffer); err != nil {
		return fmt.Errorf("set SO_SNDBUF: %w", err)
	}
	return nil
}

func lanReinjectSocketSendBuffer() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_LAN_REINJECT_SNDBUF"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_LAN_REINJECT_SOCKET_SNDBUF"))
	}
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0
	}
	if parsed > 128*1024*1024 {
		return 128 * 1024 * 1024
	}
	return parsed
}

func lanReinjectGSOQdiscBypassEnabled() bool {
	return envTruthy("TRUSTIX_LAN_REINJECT_GSO_QDISC_BYPASS")
}

func (injector *lanPacketInjector) disableRawGSOLocked() error {
	injector.gsoRawDisabled = true
	if injector.gsoRawFD >= 0 {
		err := unix.Close(injector.gsoRawFD)
		injector.gsoRawFD = -1
		return err
	}
	return nil
}

func (injector *lanPacketInjector) disableCookedGSOLocked() error {
	injector.gsoDisabled = true
	if injector.gsoFD >= 0 {
		err := unix.Close(injector.gsoFD)
		injector.gsoFD = -1
		return err
	}
	return nil
}

func isPacketSocketGSOUnsupported(err error) bool {
	switch packetSocketGSOErrno(err) {
	case unix.EINVAL, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EMSGSIZE:
		return true
	default:
		return false
	}
}

func (injector *lanPacketInjector) close() error {
	injector.mu.Lock()
	defer injector.mu.Unlock()
	var errs []error
	if injector.fd < 0 {
		return nil
	}
	if err := unix.Close(injector.fd); err != nil {
		errs = append(errs, err)
	}
	injector.fd = -1
	if injector.gsoFD >= 0 {
		if err := unix.Close(injector.gsoFD); err != nil {
			errs = append(errs, err)
		}
		injector.gsoFD = -1
	}
	if injector.gsoRawFD >= 0 {
		if err := unix.Close(injector.gsoRawFD); err != nil {
			errs = append(errs, err)
		}
		injector.gsoRawFD = -1
	}
	return errors.Join(errs...)
}

func (manager *Manager) closeLANPacketInjectorsLocked() error {
	var errs []string
	for iface, injector := range manager.lanInjectors {
		if injector == nil {
			delete(manager.lanInjectors, iface)
			continue
		}
		if err := injector.close(); err != nil {
			errs = append(errs, fmt.Sprintf("close LAN packet reinject socket %q: %v", iface, err))
		}
		delete(manager.lanInjectors, iface)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func htons(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}

func htonl(value uint32) uint32 {
	return (value << 24) | ((value << 8) & 0x00ff0000) | ((value >> 8) & 0x0000ff00) | (value >> 24)
}
