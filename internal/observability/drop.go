// Package observability defines counters, drop reasons, and packet-debug
// contracts shared by the daemon, dataplane, and CLI.
package observability

type DropReason string

const (
	DropNoRoute              DropReason = "NO_ROUTE"
	DropUnauthorizedPrefix   DropReason = "UNAUTHORIZED_PREFIX"
	DropPeerDown             DropReason = "PEER_DOWN"
	DropEndpointDown         DropReason = "ENDPOINT_DOWN"
	DropFlowTableFull        DropReason = "FLOW_TABLE_FULL"
	DropMTUExceeded          DropReason = "MTU_EXCEEDED"
	DropFragmentedPacket     DropReason = "FRAGMENTED_PACKET"
	DropChecksumError        DropReason = "CHECKSUM_ERROR"
	DropInvalidPacket        DropReason = "INVALID_PACKET"
	DropInvalidOverlayHeader DropReason = "INVALID_OVERLAY_HEADER"
	DropReplayDetected       DropReason = "REPLAY_DETECTED"
	DropConfigEpochMismatch  DropReason = "CONFIG_EPOCH_MISMATCH"
	DropNeighborUnresolved   DropReason = "NEIGHBOR_UNRESOLVED"
	DropRingFull             DropReason = "RING_FULL"
	DropTXPoolExhausted      DropReason = "TX_POOL_EXHAUSTED"
	DropCryptoFailed         DropReason = "CRYPTO_FAILED"
	DropFlowNotInstalled     DropReason = "FLOW_NOT_INSTALLED"
	DropBlackholeRoute       DropReason = "BLACKHOLE_ROUTE"
	DropRejectRoute          DropReason = "REJECT_ROUTE"
	DropTTLExpired           DropReason = "TTL_EXPIRED"
)

type Counter struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}
