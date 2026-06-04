package daemon

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
)

func loadTLSCertificateChecked(desired config.Desired, certPath, keyPath, label string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, fmt.Errorf("%s has no leaf certificate", label)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse %s: %w", label, err)
	}
	if err := verifyCertificateNotRevokedByDesired(desired, leaf, label); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func (daemon *Daemon) verifyCertificateNotRevoked(cert *x509.Certificate, label string) error {
	return verifyCertificateNotRevokedByDesired(daemon.desired, cert, label)
}

func verifyCertificateNotRevokedByDesired(desired config.Desired, cert *x509.Certificate, label string) error {
	return verifyCertificateNotRevokedByTrust(desired.Trust, cert, label)
}

func verifyCertificateNotRevokedByTrust(trust config.TrustConfig, cert *x509.Certificate, label string) error {
	if cert == nil {
		return fmt.Errorf("%s is required", label)
	}
	fingerprint := pki.CertificateFingerprintSHA256(cert)
	if _, revoked := revokedCertificateFingerprintsFromTrust(trust)[fingerprint]; revoked {
		return fmt.Errorf("%s fingerprint %s is revoked", label, fingerprint)
	}
	return nil
}

func revokedCertificateFingerprints(desired config.Desired) map[string]struct{} {
	return revokedCertificateFingerprintsFromTrust(desired.Trust)
}

func revokedCertificateFingerprintsFromTrust(trust config.TrustConfig) map[string]struct{} {
	revoked := make(map[string]struct{}, len(trust.RevokedCertFingerprints))
	for _, raw := range trust.RevokedCertFingerprints {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(raw)
		if err != nil {
			continue
		}
		revoked[fingerprint] = struct{}{}
	}
	return revoked
}

func (daemon *Daemon) enforceRuntimeTrustState() (bool, error) {
	membersChanged := daemon.pruneRevokedMembers()
	pendingChanged := daemon.pruneInvalidPendingMembers()
	signersChanged, err := daemon.pruneRevokedConfigSigners()
	if err != nil {
		return membersChanged || pendingChanged || signersChanged, err
	}
	if membersChanged {
		if err := daemon.persistMembers(); err != nil {
			return true, err
		}
	}
	if pendingChanged {
		if err := daemon.persistPendingMembers(); err != nil {
			return true, err
		}
	}
	if signersChanged {
		if err := daemon.persistConfigSignerCache(); err != nil {
			return true, err
		}
	}
	if membersChanged || signersChanged {
		daemon.closeUntrustedDataSessions()
	}
	return membersChanged || pendingChanged || signersChanged, nil
}

func (daemon *Daemon) pruneRevokedMembers() bool {
	daemon.membershipMu.RLock()
	ids := make([]core.IXID, 0, len(daemon.members))
	for ixID := range daemon.members {
		if ixID != daemon.desired.IX.ID {
			ids = append(ids, ixID)
		}
	}
	records := make(map[core.IXID]memberRecord, len(ids))
	for _, ixID := range ids {
		records[ixID] = daemon.members[ixID]
	}
	daemon.membershipMu.RUnlock()

	var revoked []core.IXID
	for ixID, record := range records {
		if err := daemon.verifyAdvertisement(record.Advertisement); err != nil {
			revoked = append(revoked, ixID)
		}
	}
	if len(revoked) == 0 {
		return false
	}
	daemon.membershipMu.Lock()
	for _, ixID := range revoked {
		delete(daemon.members, ixID)
	}
	daemon.membershipMu.Unlock()
	return true
}

func (daemon *Daemon) pruneInvalidPendingMembers() bool {
	daemon.membershipMu.RLock()
	ids := make([]core.IXID, 0, len(daemon.pendingMembers))
	for ixID := range daemon.pendingMembers {
		ids = append(ids, ixID)
	}
	records := make(map[core.IXID]pendingMemberRecord, len(ids))
	for _, ixID := range ids {
		records[ixID] = daemon.pendingMembers[ixID]
	}
	daemon.membershipMu.RUnlock()

	remove := make([]core.IXID, 0)
	for ixID, record := range records {
		if _, err := daemon.verifyAdvertisementBase(record.Advertisement); err != nil {
			remove = append(remove, ixID)
		}
	}
	if len(remove) == 0 {
		return false
	}
	daemon.membershipMu.Lock()
	for _, ixID := range remove {
		delete(daemon.pendingMembers, ixID)
	}
	daemon.membershipMu.Unlock()
	return true
}

func (daemon *Daemon) pruneRevokedConfigSigners() (bool, error) {
	daemon.signerMu.Lock()
	defer daemon.signerMu.Unlock()
	if daemon.signerCerts == nil {
		daemon.signerCerts = make(map[core.SignerID]*x509.Certificate)
	}
	changed := false
	localSignerID := signerIDForIX(daemon.desired.IX.ID)
	for signerID, cert := range daemon.signerCerts {
		if cert == nil {
			delete(daemon.signerCerts, signerID)
			changed = true
			continue
		}
		if signerID != localSignerID {
			continue
		}
		if err := verifyCertificateNotRevokedByDesired(daemon.desired, cert, "local config signer certificate"); err != nil {
			delete(daemon.signerCerts, signerID)
			changed = true
		}
	}
	if daemon.desired.IX.CertPath != "" {
		cert, _, err := pki.LoadCertificate(daemon.desired.IX.CertPath)
		if err != nil {
			return changed, err
		}
		signerID := signerIDForIX(daemon.desired.IX.ID)
		if existing := daemon.signerCerts[signerID]; existing == nil || !bytes.Equal(existing.Raw, cert.Raw) {
			if err := verifyCertificateNotRevokedByDesired(daemon.desired, cert, "local config signer certificate"); err != nil {
				return changed, err
			}
			daemon.signerCerts[signerID] = cert
			changed = true
		}
	}
	return changed, nil
}

func (daemon *Daemon) trustRevocationDoctorCheck() doctorCheck {
	count := len(revokedCertificateFingerprints(daemon.desired))
	if count == 0 {
		return doctorCheck{Name: "trust_revocation", Status: "ok", Detail: "no revoked certificate fingerprints configured"}
	}
	return doctorCheck{Name: "trust_revocation", Status: "ok", Detail: fmt.Sprintf("%d revoked certificate fingerprints active", count)}
}

func (daemon *Daemon) closeUntrustedDataSessions() {
	allowedPeers := make(map[core.IXID]struct{})
	for _, peer := range daemon.desired.Peers {
		allowedPeers[peer.ID] = struct{}{}
	}
	daemon.membershipMu.RLock()
	for ixID := range daemon.members {
		allowedPeers[ixID] = struct{}{}
	}
	daemon.membershipMu.RUnlock()

	daemon.dataMu.Lock()
	var sessions []transport.Session
	for key, session := range daemon.dataSessions {
		if _, ok := allowedPeers[key.Peer]; ok {
			continue
		}
		sessions = append(sessions, session)
		delete(daemon.dataSessions, key)
	}
	daemon.dataMu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
}
