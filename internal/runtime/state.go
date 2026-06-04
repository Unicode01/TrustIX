// Package runtime contains high-churn state that is gossiped with TTLs. These
// values must never be treated as signed desired configuration.
package runtime

import (
	"time"

	"trustix.local/trustix/internal/core"
)

type EndpointHealth string

const (
	EndpointUnknown EndpointHealth = "unknown"
	EndpointUp      EndpointHealth = "up"
	EndpointDown    EndpointHealth = "down"
)

type EndpointState struct {
	Peer          core.IXID       `json:"peer"`
	Endpoint      core.EndpointID `json:"endpoint"`
	Health        EndpointHealth  `json:"health"`
	RTT           time.Duration   `json:"rtt"`
	PacketLoss    float64         `json:"packet_loss"`
	CurrentFlows  uint64          `json:"current_flows"`
	BytesSent     uint64          `json:"bytes_sent"`
	BytesReceived uint64          `json:"bytes_received"`
	Error         string          `json:"error,omitempty"`
	ObservedAt    time.Time       `json:"observed_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

func (state EndpointState) Expired(now time.Time) bool {
	return !state.ExpiresAt.IsZero() && !now.Before(state.ExpiresAt)
}
