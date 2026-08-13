package tixtcp

import (
	"context"
	"sync"
	"time"

	"trustix.local/trustix/internal/dataplane"
)

const tixTCPCapabilityMonitorCacheTTL = 25 * time.Millisecond

type tixTCPCapabilityObservation struct {
	capabilities uint64
	err          error
}

type tixTCPCapabilitySubscription struct {
	mu      sync.Mutex
	wake    chan struct{}
	pending bool
	floor   tixTCPCapabilityObservation
	latest  tixTCPCapabilityObservation
	closed  bool
}

func newTIXTCPCapabilitySubscription() *tixTCPCapabilitySubscription {
	return &tixTCPCapabilitySubscription{wake: make(chan struct{}, 1)}
}

func (subscription *tixTCPCapabilitySubscription) publish(observation tixTCPCapabilityObservation) {
	if subscription == nil {
		return
	}
	subscription.mu.Lock()
	if subscription.closed {
		subscription.mu.Unlock()
		return
	}
	if !subscription.pending {
		subscription.floor = observation
		subscription.latest = observation
		subscription.pending = true
	} else {
		// Retain the bitwise floor so coalescing cannot hide a transient withdrawal.
		floor := subscription.floor.capabilities & observation.capabilities
		if floor != subscription.floor.capabilities {
			subscription.floor.capabilities = floor
			subscription.floor.err = observation.err
		} else if observation.err != nil {
			subscription.floor.err = observation.err
		}
		subscription.latest = observation
	}
	subscription.mu.Unlock()
	select {
	case subscription.wake <- struct{}{}:
	default:
	}
}

func (subscription *tixTCPCapabilitySubscription) take() (tixTCPCapabilityObservation, bool) {
	if subscription == nil {
		return tixTCPCapabilityObservation{}, false
	}
	subscription.mu.Lock()
	defer subscription.mu.Unlock()
	if subscription.closed || !subscription.pending {
		return tixTCPCapabilityObservation{}, false
	}
	observation := subscription.latest
	if !sameTIXTCPCapabilityObservation(subscription.floor, subscription.latest) {
		observation = subscription.floor
		subscription.floor = subscription.latest
		select {
		case subscription.wake <- struct{}{}:
		default:
		}
		return observation, true
	}
	subscription.pending = false
	return observation, true
}

func (subscription *tixTCPCapabilitySubscription) close() {
	if subscription == nil {
		return
	}
	subscription.mu.Lock()
	subscription.closed = true
	subscription.pending = false
	subscription.mu.Unlock()
}

type tixTCPCapabilityMonitor struct {
	provider dataplane.TIXTCPProvider

	probeMu sync.Mutex
	mu      sync.Mutex
	wake    chan struct{}
	running bool

	subscriptions map[*tixTCPCapabilitySubscription]*session
	current       tixTCPCapabilityObservation
	currentAt     time.Time
	initialized   bool
	lastBroadcast time.Time
}

func newTIXTCPCapabilityMonitor(provider dataplane.TIXTCPProvider) *tixTCPCapabilityMonitor {
	if provider == nil {
		return nil
	}
	return &tixTCPCapabilityMonitor{
		provider:      provider,
		wake:          make(chan struct{}, 1),
		subscriptions: make(map[*tixTCPCapabilitySubscription]*session),
	}
}

func sameTIXTCPCapabilityObservation(a, b tixTCPCapabilityObservation) bool {
	if a.capabilities != b.capabilities {
		return false
	}
	if a.err == nil || b.err == nil {
		return a.err == nil && b.err == nil
	}
	return a.err.Error() == b.err.Error()
}

func (monitor *tixTCPCapabilityMonitor) subscribe(session *session) *tixTCPCapabilitySubscription {
	if monitor == nil || session == nil {
		return nil
	}
	subscription := newTIXTCPCapabilitySubscription()
	monitor.mu.Lock()
	observation := monitor.current
	now := time.Now()
	cacheAge := now.Sub(monitor.currentAt)
	initialized := monitor.initialized && cacheAge >= 0 && cacheAge < tixTCPCapabilityMonitorCacheTTL
	if !initialized {
		monitor.lastBroadcast = time.Time{}
	} else {
		// Queue the snapshot before making the subscription visible to broadcasts.
		subscription.floor = observation
		subscription.latest = observation
		subscription.pending = true
		subscription.wake <- struct{}{}
	}
	monitor.subscriptions[subscription] = session
	start := !monitor.running
	if start {
		monitor.running = true
	}
	monitor.mu.Unlock()
	if start {
		go monitor.run()
	}
	monitor.signal()
	return subscription
}

func (monitor *tixTCPCapabilityMonitor) unsubscribe(subscription *tixTCPCapabilitySubscription) {
	if monitor == nil || subscription == nil {
		return
	}
	subscription.close()
	monitor.mu.Lock()
	delete(monitor.subscriptions, subscription)
	monitor.mu.Unlock()
	monitor.signal()
}

func (monitor *tixTCPCapabilityMonitor) signal() {
	if monitor == nil {
		return
	}
	select {
	case monitor.wake <- struct{}{}:
	default:
	}
}

func (monitor *tixTCPCapabilityMonitor) run() {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-monitor.wake:
		}
		_, ok := monitor.refreshInterval()
		if !ok {
			return
		}
		monitor.observe(context.Background())
		interval, ok := monitor.refreshInterval()
		if !ok {
			return
		}
		timer.Reset(interval)
	}
}

func (monitor *tixTCPCapabilityMonitor) refreshInterval() (time.Duration, bool) {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if len(monitor.subscriptions) == 0 {
		monitor.running = false
		return 0, false
	}
	for _, session := range monitor.subscriptions {
		if session != nil && session.localCapabilities.Load()&tixTCPCapabilityInnerGSO != 0 {
			return tixTCPCompatInnerGSOCapabilityRefreshInterval, true
		}
	}
	return tixTCPCompatCapabilityRefreshInterval, true
}

func (monitor *tixTCPCapabilityMonitor) observe(ctx context.Context) tixTCPCapabilityObservation {
	if monitor == nil || monitor.provider == nil {
		return tixTCPCapabilityObservation{}
	}
	monitor.probeMu.Lock()
	defer monitor.probeMu.Unlock()
	now := time.Now()
	monitor.mu.Lock()
	cacheAge := now.Sub(monitor.currentAt)
	if monitor.initialized && cacheAge >= 0 && cacheAge < tixTCPCapabilityMonitorCacheTTL {
		observation := monitor.current
		monitor.mu.Unlock()
		return observation
	}
	monitor.mu.Unlock()

	capabilities, err := tixTCPProviderLocalCapabilities(ctx, monitor.provider)
	observation := tixTCPCapabilityObservation{capabilities: capabilities, err: err}
	now = time.Now()
	monitor.mu.Lock()
	changed := !monitor.initialized || !sameTIXTCPCapabilityObservation(monitor.current, observation)
	monitor.current = observation
	monitor.currentAt = now
	monitor.initialized = true
	broadcast := changed || now.Sub(monitor.lastBroadcast) >= tixTCPCompatCapabilityRefreshInterval
	var subscriptions []*tixTCPCapabilitySubscription
	if broadcast {
		monitor.lastBroadcast = now
		subscriptions = make([]*tixTCPCapabilitySubscription, 0, len(monitor.subscriptions))
		for subscription := range monitor.subscriptions {
			subscriptions = append(subscriptions, subscription)
		}
	}
	monitor.mu.Unlock()
	for _, subscription := range subscriptions {
		subscription.publish(observation)
	}
	return observation
}
