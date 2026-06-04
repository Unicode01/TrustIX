// Package routing owns prefix routing decisions, route import/export contracts,
// and flow stickiness boundaries. It does not know how packets are captured or
// transported.
package routing

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"trustix.local/trustix/internal/core"
)

type RouteKind string

const (
	RouteUnicast   RouteKind = "unicast"
	RouteLocal     RouteKind = "local"
	RouteBlackhole RouteKind = "blackhole"
	RouteReject    RouteKind = "reject"
)

type Route struct {
	Prefix        core.Prefix     `json:"prefix"`
	Owner         core.IXID       `json:"owner,omitempty"`
	NextHop       core.IXID       `json:"next_hop"`
	Endpoint      core.EndpointID `json:"endpoint,omitempty"`
	Metric        int             `json:"metric"`
	Policy        core.PolicyID   `json:"policy,omitempty"`
	Kind          RouteKind       `json:"kind"`
	LocalProtocol uint8           `json:"local_protocol,omitempty"`
	LocalPort     uint16          `json:"local_port,omitempty"`
	Source        string          `json:"source,omitempty"`
	Reason        string          `json:"reason,omitempty"`
}

type Decision struct {
	Route  Route        `json:"route"`
	Prefix netip.Prefix `json:"prefix"`
}

type Engine interface {
	Replace(routes []Route) error
	Lookup(dst netip.Addr) (Decision, bool)
}

type PrefixAuthorizer interface {
	AuthorizePrefix(ix core.IXID, prefix core.Prefix) error
}

type Table struct {
	mu     sync.RWMutex
	routes []compiledRoute
}

type compiledRoute struct {
	route  Route
	prefix netip.Prefix
}

func NewTable() *Table {
	return &Table{}
}

func (table *Table) Replace(routes []Route) error {
	compiled := make([]compiledRoute, 0, len(routes))
	for _, route := range routes {
		prefix, err := route.Prefix.Parse()
		if err != nil {
			return err
		}
		if route.Kind == "" {
			route.Kind = RouteUnicast
		}
		switch route.Kind {
		case RouteUnicast:
			if err := route.NextHop.Validate(); err != nil {
				return err
			}
			if route.Owner != "" {
				if err := route.Owner.Validate(); err != nil {
					return err
				}
			}
		case RouteLocal:
			if route.NextHop != "" {
				if err := route.NextHop.Validate(); err != nil {
					return err
				}
			}
			if route.Owner != "" {
				if err := route.Owner.Validate(); err != nil {
					return err
				}
			}
		case RouteBlackhole, RouteReject:
			if route.NextHop != "" {
				if err := route.NextHop.Validate(); err != nil {
					return err
				}
			}
			if route.Owner != "" {
				if err := route.Owner.Validate(); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("route %q has unsupported kind %q", route.Prefix, route.Kind)
		}
		if route.Metric < 0 {
			return fmt.Errorf("route %q has negative metric", route.Prefix)
		}
		compiled = append(compiled, compiledRoute{route: route, prefix: prefix})
	}

	table.mu.Lock()
	defer table.mu.Unlock()
	table.routes = compiled
	return nil
}

func (table *Table) Lookup(dst netip.Addr) (Decision, bool) {
	return table.LookupFiltered(dst, nil)
}

func (table *Table) LookupFiltered(dst netip.Addr, include func(Route) bool) (Decision, bool) {
	table.mu.RLock()
	defer table.mu.RUnlock()

	bestIndex := -1
	bestBits := -1
	bestMetric := int(^uint(0) >> 1)
	for i, route := range table.routes {
		if !route.prefix.Contains(dst) {
			continue
		}
		if include != nil && !include(route.route) {
			continue
		}
		bits := route.prefix.Bits()
		if bits > bestBits || bits == bestBits && route.route.Metric < bestMetric {
			bestIndex = i
			bestBits = bits
			bestMetric = route.route.Metric
		}
	}
	if bestIndex < 0 {
		return Decision{}, false
	}
	selected := table.routes[bestIndex]
	return Decision{Route: selected.route, Prefix: selected.prefix}, true
}

type FlowKey struct {
	SourceIP        netip.Addr `json:"source_ip"`
	DestinationIP   netip.Addr `json:"destination_ip"`
	SourcePort      uint16     `json:"source_port"`
	DestinationPort uint16     `json:"destination_port"`
	Protocol        uint8      `json:"protocol"`
}

type FlowBinding struct {
	Key       FlowKey         `json:"key"`
	NextHop   core.IXID       `json:"next_hop"`
	Endpoint  core.EndpointID `json:"endpoint"`
	PoolIndex int             `json:"pool_index,omitempty"`
	LastSeen  time.Time       `json:"last_seen"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type FlowSelector interface {
	SelectEndpoint(route Route, key FlowKey) (core.EndpointID, error)
	Release(binding FlowBinding) error
}
