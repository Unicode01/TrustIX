// Package control defines the peer control-plane contracts: mTLS session
// establishment, capability negotiation, config sync, route sync, and runtime
// state gossip.
package control

import (
	"context"
	"time"

	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
)

type MessageType string

const (
	MessageHello          MessageType = "hello"
	MessageCapabilities   MessageType = "capabilities"
	MessageAuthzProof     MessageType = "authz_proof"
	MessageConfigHead     MessageType = "config_head"
	MessageConfigEvent    MessageType = "config_event"
	MessageConfigSnapshot MessageType = "config_snapshot"
	MessageRouteAdvertise MessageType = "route_advertise"
	MessageRouteWithdraw  MessageType = "route_withdraw"
	MessageStateGossip    MessageType = "state_gossip"
	MessageHealthProbe    MessageType = "health_probe"
	MessageFlowHint       MessageType = "flow_hint"
	MessageDebugRequest   MessageType = "debug_request"
)

type Message struct {
	Type      MessageType `json:"type"`
	Payload   []byte      `json:"payload"`
	CreatedAt time.Time   `json:"created_at"`
}

type Capabilities struct {
	ProtocolVersions      []string `json:"protocol_versions"`
	Transports            []string `json:"transports"`
	OverlayHeaderVersions []string `json:"overlay_header_versions"`
	EBPFFeatures          []string `json:"ebpf_features"`
	CryptoSuites          []string `json:"crypto_suites"`
	RoutePolicies         []string `json:"route_policies"`
	ReloadBehaviors       []string `json:"reload_behaviors"`
}

type PeerInfo struct {
	ID       core.IXID     `json:"id"`
	DomainID core.DomainID `json:"domain_id"`
}

type PeerSession interface {
	Peer() PeerInfo
	Send(ctx context.Context, message Message) error
	Recv(ctx context.Context) (Message, error)
	Close() error
}

type PeerDialer interface {
	DialPeer(ctx context.Context, peer PeerInfo) (PeerSession, error)
}

type ConfigSynchronizer interface {
	AnnounceHead(ctx context.Context, peer PeerSession, head configlog.Head) error
	FetchMissing(ctx context.Context, peer PeerSession, fromSeq uint64, toSeq uint64) ([]configlog.Event, error)
	PushEvents(ctx context.Context, peer PeerSession, events []configlog.Event) error
}

type RouteSynchronizer interface {
	Advertise(ctx context.Context, peer PeerSession, routes []routing.Route) error
	Withdraw(ctx context.Context, peer PeerSession, prefixes []core.Prefix) error
}

type StateGossiper interface {
	Publish(ctx context.Context, peer PeerSession, states []rstate.EndpointState) error
}
