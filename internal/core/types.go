// Package core contains identity and addressing value types shared by TrustIX
// components. It deliberately has no dependencies on higher-level packages.
package core

import (
	"fmt"
	"net/netip"
	"strings"
)

type DomainID string
type IXID string
type DeviceID string
type PeerID string
type EndpointID string
type EventID string
type SignerID string
type PolicyID string
type ResourcePath string

type Prefix string

func (id DomainID) Validate() error {
	return validateNonEmpty("domain id", string(id))
}

func (id IXID) Validate() error {
	return validateNonEmpty("ix id", string(id))
}

func (id DeviceID) Validate() error {
	return validateNonEmpty("device id", string(id))
}

func (id EndpointID) Validate() error {
	return validateNonEmpty("endpoint id", string(id))
}

func (id EventID) Validate() error {
	return validateNonEmpty("event id", string(id))
}

func (id SignerID) Validate() error {
	return validateNonEmpty("signer id", string(id))
}

func (path ResourcePath) Validate() error {
	return validateNonEmpty("resource path", string(path))
}

func (prefix Prefix) Parse() (netip.Prefix, error) {
	raw := strings.TrimSpace(string(prefix))
	if raw == "" {
		return netip.Prefix{}, fmt.Errorf("prefix is required")
	}
	parsed, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse prefix %q: %w", raw, err)
	}
	return parsed.Masked(), nil
}

func validateNonEmpty(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}
