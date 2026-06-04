// Package trust defines certificate, authorization, and policy verification
// boundaries. Concrete X.509 parsing and CA tooling will live behind these
// interfaces.
package trust

import (
	"context"
	"crypto/tls"
	"time"

	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
)

type Role string

const (
	RoleRootCA             Role = "root_ca"
	RoleDomainCA           Role = "domain_ca"
	RoleDomainConfigCA     Role = "domain_config_ca"
	RoleAdmin              Role = "admin"
	RoleIX                 Role = "ix"
	RoleDevice             Role = "device"
	RoleRouteAuthorization Role = "route_authorization"
)

type Identity struct {
	ID             core.SignerID `json:"id"`
	DomainID       core.DomainID `json:"domain_id"`
	IXID           core.IXID     `json:"ix_id,omitempty"`
	Role           Role          `json:"role"`
	CertificatePEM []byte        `json:"certificate_pem,omitempty"`
	NotAfter       time.Time     `json:"not_after"`
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type TLSConfigSource interface {
	ControlPlaneClientConfig(peer core.IXID) (*tls.Config, error)
	ControlPlaneServerConfig() (*tls.Config, error)
}

type IdentityVerifier interface {
	VerifyIXIdentity(ctx context.Context, identity Identity) (Decision, error)
	VerifyRevocation(ctx context.Context, identity Identity) (Decision, error)
}

type ConfigEventVerifier interface {
	VerifyConfigEvent(ctx context.Context, event configlog.Event) (Decision, error)
}

type ResourceAuthorizer interface {
	CanModifyResource(ctx context.Context, signer core.SignerID, resource core.ResourcePath, action configlog.Action) (Decision, error)
}

type RouteAuthorizer interface {
	VerifyRouteAuthorization(ctx context.Context, ix core.IXID, prefix core.Prefix) (Decision, error)
}
