package daemon

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/pki"
)

func TestConfigSyncPullsMissingSignedEvents(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), true)
	target := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), false)
	server := httptest.NewServer(source.peerHandler())
	defer server.Close()

	if err := target.syncConfigLogWithTarget(context.Background(), controlTarget{
		ID:         core.IXID("ix-c"),
		Domain:     core.DomainID("lab.local"),
		ControlAPI: server.URL,
	}); err != nil {
		t.Fatalf("sync config log: %v", err)
	}

	if target.head.Seq != source.head.Seq || target.head.Hash != source.head.Hash {
		t.Fatalf("target head = %+v, want source head %+v", target.head, source.head)
	}
	events, err := target.store.Range(2, 2)
	if err != nil {
		t.Fatalf("range target store: %v", err)
	}
	if events[0].SignerID != signerIDForIX("ix-c") {
		t.Fatalf("synced event signer = %q, want ix:ix-c", events[0].SignerID)
	}
	states := target.configSyncSnapshot()
	if len(states) != 1 || states[0].Status != "pulled" || states[0].PulledEvents != 1 {
		t.Fatalf("config sync state = %#v, want one pulled event", states)
	}
}

func TestConfigSyncDetectsForkedHeadConflict(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), true)
	target := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), true)
	server := httptest.NewServer(source.peerHandler())
	defer server.Close()

	err := target.syncConfigLogWithTarget(context.Background(), controlTarget{
		ID:         core.IXID("ix-c"),
		Domain:     core.DomainID("lab.local"),
		ControlAPI: server.URL,
	})
	if err == nil {
		t.Fatal("expected config log conflict")
	}
	if !errors.Is(err, configlog.ErrConflict) && target.configSyncSnapshot()[0].Status != "conflict" {
		t.Fatalf("expected conflict error/state, got err=%v state=%#v", err, target.configSyncSnapshot())
	}
	if target.head.Seq != 2 || target.head.Hash == source.head.Hash {
		t.Fatalf("target head changed after conflict: target=%+v source=%+v", target.head, source.head)
	}
}

func TestConfigSyncRejectsRevokedSigner(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), true)
	targetDesired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24")
	targetDesired.Trust.RevokedCertFingerprints = []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])}
	target := newConfigSyncTestDaemon(t, targetDesired, false)
	server := httptest.NewServer(source.peerHandler())
	defer server.Close()

	err := target.syncConfigLogWithTarget(context.Background(), controlTarget{
		ID:         core.IXID("ix-c"),
		Domain:     core.DomainID("lab.local"),
		ControlAPI: server.URL,
	})
	if err == nil {
		t.Fatal("expected revoked signer sync error")
	}
	if target.head.Seq != 1 {
		t.Fatalf("target head seq = %d, want unchanged genesis seq 1", target.head.Seq)
	}
}

func TestConfigSyncTrustRootBatchAllowsSignerFromNewRoot(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), false)
	target := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), false)
	out := t.TempDir()
	newRoot, err := pki.NewRoot("TrustIX Rotated Event Root", 1)
	if err != nil {
		t.Fatalf("create rotated root: %v", err)
	}
	newIX, err := pki.Issue(newRoot, pki.IssueRequest{
		CommonName: "TrustIX Rotated IX",
		Role:       pki.RoleIX,
		Domain:     "lab.local",
		IX:         "ix-n",
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue rotated ix: %v", err)
	}
	if err := pki.WriteBundle(out, "ix-n", newIX, true); err != nil {
		t.Fatalf("write rotated ix: %v", err)
	}

	rootTrust := source.desired.Trust
	rootTrust.TrustRootsPEM = []string{string(newRoot.CertPEM)}
	body := mustJSON(t, rootTrust)
	request := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	proof, err := source.verifyAdminRequest(request, body)
	if err != nil {
		t.Fatalf("verify admin proof: %v", err)
	}
	head, err := source.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	trustEvent, plannedHead, changed, err := source.domainTrustEventIfChangedAtHead(rootTrust, adminProofsFromContext(context.WithValue(context.Background(), adminProofContextKey{}, proof)), head)
	if err != nil || !changed {
		t.Fatalf("build trust event changed=%t err=%v", changed, err)
	}

	newDesired := config.Desired{
		Domain: config.DomainConfig{ID: "lab.local", TrustRoots: pkiSet.trustRoots},
		IX: config.IXConfig{
			ID:       "ix-n",
			Domain:   "lab.local",
			CertPath: filepath.Join(out, "ix-n.crt"),
			KeyPath:  filepath.Join(out, "ix-n.key"),
		},
	}
	payload := mustJSON(t, newDesired)
	newEvent, _, changed, err := source.signedConfigEventAtHead(desiredResourceForIX("ix-n"), configlog.ActionUpsert, payload, newDesired, nil, plannedHead)
	if err != nil || !changed {
		t.Fatalf("build new-root desired event changed=%t err=%v", changed, err)
	}
	oldSigner, _, err := pki.LoadCertificate(pkiSet.ixCerts["ix-a"])
	if err != nil {
		t.Fatal(err)
	}
	newSigner, _, err := pki.LoadCertificate(filepath.Join(out, "ix-n.crt"))
	if err != nil {
		t.Fatal(err)
	}
	signers := []configSignerCertificate{
		{SignerID: signerIDForIX("ix-a"), Certificate: oldSigner.Raw},
		{SignerID: signerIDForIX("ix-n"), Certificate: newSigner.Raw},
	}

	appended, err := target.appendVerifiedConfigEvents(context.Background(), []configlog.Event{*trustEvent, *newEvent}, signers)
	if err != nil {
		t.Fatalf("append rotated-root batch: %v", err)
	}
	if appended != 2 {
		t.Fatalf("appended = %d, want 2", appended)
	}
	if target.head.Seq != plannedHead.Seq+1 {
		t.Fatalf("target head seq = %d, want %d", target.head.Seq, plannedHead.Seq+1)
	}
	if len(target.desired.Trust.TrustRootsPEM) != 1 {
		t.Fatalf("target trust roots = %d, want 1", len(target.desired.Trust.TrustRootsPEM))
	}
}

func TestConfigSyncPushesLocalEventsToPeer(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), true)
	target := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), false)
	server := httptest.NewServer(target.peerHandler())
	defer server.Close()

	if err := source.syncConfigLogWithTarget(context.Background(), controlTarget{
		ID:         core.IXID("ix-c"),
		Domain:     core.DomainID("lab.local"),
		ControlAPI: server.URL,
	}); err != nil {
		t.Fatalf("sync config log push: %v", err)
	}

	if target.head.Seq != source.head.Seq || target.head.Hash != source.head.Hash {
		t.Fatalf("target head = %+v, want source head %+v", target.head, source.head)
	}
	events, err := target.store.Range(2, 2)
	if err != nil {
		t.Fatalf("range target store: %v", err)
	}
	if events[0].SignerID != signerIDForIX("ix-a") {
		t.Fatalf("pushed event signer = %q, want ix:ix-a", events[0].SignerID)
	}
	states := source.configSyncSnapshot()
	if len(states) != 1 || states[0].Status != "pushed" || states[0].PushedEvents != 1 {
		t.Fatalf("config sync state = %#v, want one pushed event", states)
	}
}

func TestConfigRejoinReplacesForkAndPreservesLocalDesired(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), true)
	target := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), true)
	server := httptest.NewServer(source.peerHandler())
	defer server.Close()

	response, err := target.rejoinConfigLogWithTarget(context.Background(), controlTarget{
		ID:         core.IXID("ix-c"),
		Domain:     core.DomainID("lab.local"),
		ControlAPI: server.URL,
	}, true)
	if err != nil {
		t.Fatalf("rejoin config log: %v", err)
	}
	if !response.Rejoined || !response.PreservedLocalDesired {
		t.Fatalf("rejoin response = %#v, want preserved local desired", response)
	}
	if response.RemoteHead.Seq != source.head.Seq || response.RemoteHead.Hash != source.head.Hash {
		t.Fatalf("remote head = %+v, want source %+v", response.RemoteHead, source.head)
	}
	if target.head.Seq != 3 {
		t.Fatalf("target head seq = %d, want 3", target.head.Seq)
	}
	events, err := target.store.Range(1, target.head.Seq)
	if err != nil {
		t.Fatalf("range target store: %v", err)
	}
	if events[1].SignerID != signerIDForIX("ix-c") {
		t.Fatalf("seq 2 signer = %q, want ix:ix-c", events[1].SignerID)
	}
	if events[2].SignerID != signerIDForIX("ix-a") {
		t.Fatalf("seq 3 signer = %q, want ix:ix-a", events[2].SignerID)
	}
	if target.desired.IX.ID != "ix-a" {
		t.Fatalf("runtime desired ix = %q, want ix-a", target.desired.IX.ID)
	}
	states := target.configSyncSnapshot()
	if len(states) != 1 || states[0].Status != "rejoined" {
		t.Fatalf("config sync state = %#v, want rejoined", states)
	}
}

func TestConfigVerifyAndRestoreBackup(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", freeConfigSyncUDPAddr(t), "", "10.0.0.0/24")
	daemon, err := New(Config{DataplaneMode: "noop", DataDir: t.TempDir()}, WithDataplane(dataplane.NewNoopManager()))
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	daemon.desired = desired
	daemon.cfg.DomainID = desired.Domain.ID
	daemon.cfg.IXID = desired.IX.ID
	logPath := filepath.Join(daemon.cfg.DataDir, "config.log")
	store, err := configlog.NewFileStore(logPath)
	if err != nil {
		t.Fatal(err)
	}
	daemon.store = store
	daemon.logPath = logPath
	if err := daemon.registerLocalConfigSigner(); err != nil {
		t.Fatalf("register signer: %v", err)
	}
	if err := daemon.ensureConfigGenesisEvent(desired); err != nil {
		t.Fatalf("append genesis: %v", err)
	}
	if err := daemon.appendDesiredEventIfChanged(desired); err != nil {
		t.Fatalf("append desired: %v", err)
	}
	head, err := daemon.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	daemon.head = head
	before := daemon.verifyCurrentConfigLog()
	if !before.Valid || before.Events != 2 {
		t.Fatalf("verify before = %#v, want valid events=2", before)
	}

	next := desired
	next.LAN.Advertise = []core.Prefix{"10.0.99.0/24"}
	genesis := mustGenesisEvent(t, daemon)
	genesisHash, err := genesis.Hash()
	if err != nil {
		t.Fatal(err)
	}
	replacementHead := configlog.Head{Seq: 1, Hash: genesisHash}
	payload := mustJSON(t, next)
	event, _, changed, err := daemon.desiredEventIfChangedAtHead(next, nil, replacementHead, payload)
	if err != nil || !changed {
		t.Fatalf("build replacement desired changed=%t err=%v", changed, err)
	}
	if err := daemon.store.ReplaceAll([]configlog.Event{genesis, *event}); err != nil {
		t.Fatalf("replace all: %v", err)
	}
	backups, err := filepath.Glob(logPath + ".backup.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("backups = %d, want 1", len(backups))
	}

	response, err := daemon.restoreConfigLogBackup(context.Background(), backups[0])
	if err != nil {
		t.Fatalf("restore backup: %v", err)
	}
	if !response.Restored || response.Head.Seq != 2 || response.Created == "" {
		t.Fatalf("restore response = %#v", response)
	}
	if daemon.head.Seq != 2 {
		t.Fatalf("daemon head seq = %d, want 2", daemon.head.Seq)
	}
	current, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, original) {
		t.Fatal("restored config log does not match backup")
	}
	after := daemon.verifyCurrentConfigLog()
	if !after.Valid || len(after.Backups) < 2 {
		t.Fatalf("verify after = %#v, want valid with backups", after)
	}
	daemon.closeDataPath()
}

func TestAdmissionRevokePreflightPullsMissingApproval(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), false)
	approveAdmissionViaAPI(t, source, pkiSet, "ix-c", "10.0.2.0/24")
	sourceHead, err := source.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	source.head = sourceHead
	server := httptest.NewServer(source.peerHandler())
	defer server.Close()

	target := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "", "10.0.1.0/24"), false)
	target.desired.Bootstrap.Peers = []config.BootstrapPeerConfig{{
		ID:         "ix-a",
		Domain:     "lab.local",
		ControlAPI: server.URL,
	}}

	body := mustJSON(t, admissionRevokeRequest{IXID: "ix-c"})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions/revoke", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	target.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if target.head.Seq != sourceHead.Seq+1 {
		t.Fatalf("target head seq = %d, want %d", target.head.Seq, sourceHead.Seq+1)
	}
	admission, ok, err := target.latestAdmissionForIXLocked("ix-c")
	if err != nil || !ok {
		t.Fatalf("latest target admission ok=%t err=%v", ok, err)
	}
	if admission.State != admissionStateRevoked {
		t.Fatalf("admission state = %q, want revoked", admission.State)
	}
	states := target.configSyncSnapshot()
	if len(states) != 1 || states[0].Status != "pulled" || states[0].PulledEvents != 1 {
		t.Fatalf("config sync state = %#v, want preflight pulled approval", states)
	}
}

func TestConfigMutationPreflightBlocksForkedWrite(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), true)
	server := httptest.NewServer(source.peerHandler())
	defer server.Close()
	target := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "", "10.0.1.0/24"), true)
	target.desired.Bootstrap.Peers = []config.BootstrapPeerConfig{{
		ID:         "ix-a",
		Domain:     "lab.local",
		ControlAPI: server.URL,
	}}
	before := target.head

	body := mustJSON(t, trustFingerprintRequest{Fingerprint: fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])})
	request := httptest.NewRequest(http.MethodPost, "/v1/trust/revoke", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	target.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("trust revoke status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if target.head != before {
		t.Fatalf("target head changed after blocked write: got %+v want %+v", target.head, before)
	}
	if !strings.Contains(recorder.Body.String(), "rejoin_hint") || !strings.Contains(recorder.Body.String(), server.URL) {
		t.Fatalf("conflict body missing rejoin hint: %s", recorder.Body.String())
	}
	states := target.configSyncSnapshot()
	if len(states) != 1 || states[0].Status != "conflict" {
		t.Fatalf("config sync state = %#v, want conflict", states)
	}
}

func newConfigSyncTestDaemon(t *testing.T, desired config.Desired, appendInitial bool) *Daemon {
	t.Helper()
	daemon, err := New(Config{DataplaneMode: "noop", DataDir: t.TempDir()}, WithDataplane(dataplane.NewNoopManager()))
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	daemon.desired = desired
	daemon.cfg.DomainID = desired.Domain.ID
	daemon.cfg.IXID = desired.IX.ID
	daemon.store = configlog.NewMemoryStore()
	daemon.logPath = "memory"
	if err := daemon.registerLocalConfigSigner(); err != nil {
		t.Fatalf("register local config signer: %v", err)
	}
	if err := daemon.ensureConfigGenesisEvent(desired); err != nil {
		t.Fatalf("append genesis: %v", err)
	}
	head, err := daemon.store.Head()
	if err != nil {
		t.Fatalf("read genesis head: %v", err)
	}
	daemon.head = head
	if appendInitial {
		if err := daemon.appendDesiredEventIfChanged(desired); err != nil {
			t.Fatalf("append initial desired: %v", err)
		}
		head, err := daemon.store.Head()
		if err != nil {
			t.Fatalf("read head: %v", err)
		}
		daemon.head = head
	}
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh local advertisement: %v", err)
	}
	return daemon
}

func freeConfigSyncUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp addr: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}
