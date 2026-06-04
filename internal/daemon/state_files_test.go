package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/configlog"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
)

func TestLoadPersistedMembersQuarantinesCorruptState(t *testing.T) {
	daemon := newMembershipTestDaemon(t, desiredForMembershipTest(buildMembershipPKI(t), "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemon.cfg.DataDir = t.TempDir()
	path := daemon.membershipStatePath()
	if err := os.WriteFile(path, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := daemon.loadPersistedMembers(); err != nil {
		t.Fatalf("load persisted members with corrupt state: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt members state still exists err=%v", err)
	}
	matches, err := filepath.Glob(path + ".bad.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("quarantined members files = %d, want 1", len(matches))
	}
}

func TestLoadPersistedPendingMembersQuarantinesCorruptState(t *testing.T) {
	daemon := newMembershipTestDaemon(t, desiredForMembershipTest(buildMembershipPKI(t), "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemon.cfg.DataDir = t.TempDir()
	path := daemon.pendingMembershipStatePath()
	if err := os.WriteFile(path, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := daemon.loadPersistedPendingMembers(); err != nil {
		t.Fatalf("load persisted pending with corrupt state: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt pending state still exists err=%v", err)
	}
	matches, err := filepath.Glob(path + ".bad.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("quarantined pending files = %d, want 1", len(matches))
	}
}

func TestStateFilesDoctorReportsRuntimeState(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemon.cfg.DataDir = t.TempDir()
	storePath := filepath.Join(daemon.cfg.DataDir, "config.log")
	store, err := configlog.NewFileStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(mustGenesisEvent(t, daemon)); err != nil {
		t.Fatal(err)
	}
	daemon.store = store
	daemon.logPath = storePath
	daemon.head, err = store.Head()
	if err != nil {
		t.Fatal(err)
	}

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	now := time.Now().UTC()
	daemon.membershipMu.Lock()
	daemon.members["ix-c"] = memberRecord{Advertisement: advertisement, LastSeen: now, Source: "test", Direct: true}
	daemon.pendingMembers["ix-b"] = pendingMemberRecord{Advertisement: advertisement, FirstSeen: now.Add(-2 * pendingMemberTTL), LastSeen: now.Add(-pendingMemberTTL - time.Second), Source: "test", RejectReason: "pending"}
	daemon.membershipMu.Unlock()
	if err := daemon.persistMembers(); err != nil {
		t.Fatalf("persist members: %v", err)
	}
	if err := daemon.persistPendingMembers(); err != nil {
		t.Fatalf("persist pending: %v", err)
	}

	status := daemon.stateFilesStatus()
	members := stateFileByName(t, status, "members")
	if members.Records != 1 {
		t.Fatalf("members status = %#v, want records=1", members)
	}
	pending := stateFileByName(t, status, "pending_members")
	if pending.Status != "warn" || pending.Records != 1 || pending.ExpiredRecords != 1 || pending.EarliestExpiry.IsZero() {
		t.Fatalf("pending status = %#v, want warn records=1 expired=1 expiry", pending)
	}
	configLog := stateFileByName(t, status, "config_log")
	if configLog.Records != 1 || !strings.Contains(configLog.Detail, "head_seq=1") {
		t.Fatalf("config log status = %#v, want head_seq=1", configLog)
	}
	check := daemon.stateFilesDoctorCheck()
	if check.Name != "state_files" || check.Status != "warn" || !strings.Contains(check.Detail, "pending_members") {
		t.Fatalf("doctor check = %#v, want warn pending detail", check)
	}
}

func TestStateFilesDoctorWarnsOnConfigLogBackupOverRetention(t *testing.T) {
	t.Setenv(configlog.BackupKeepEnv, "1")
	pkiSet := buildMembershipPKI(t)
	daemon := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemon.cfg.DataDir = t.TempDir()
	storePath := filepath.Join(daemon.cfg.DataDir, "config.log")
	store, err := configlog.NewFileStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(mustGenesisEvent(t, daemon)); err != nil {
		t.Fatal(err)
	}
	daemon.store = store
	daemon.logPath = storePath
	daemon.head, err = store.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath+".backup.old", []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath+".backup.new", []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	status := daemon.stateFilesStatus()
	configLog := stateFileByName(t, status, "config_log")
	if configLog.Status != "warn" || !configLog.BackupOverLimit || configLog.BackupKeep != 1 || configLog.Backups != 2 {
		t.Fatalf("config log status = %#v, want backup retention warning", configLog)
	}
	check := daemon.stateFilesDoctorCheck()
	if check.Status != "warn" || !strings.Contains(check.Detail, "backup_over_limit=true") {
		t.Fatalf("doctor check = %#v, want backup retention warning detail", check)
	}
}

func TestStateFilesStatusReportsIPTunnelState(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemon.cfg.DataDir = t.TempDir()
	manager := iptunneltransport.NewManager(daemon.cfg.DataDir)
	if err := manager.Record(t.Context(), iptunneltransport.TunnelRecord{
		Name:     "tixgrstate",
		Protocol: "gre",
		Endpoint: "gre",
		Role:     "listen",
		Config:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,mtu=1400",
		RefCount: 2,
	}); err != nil {
		t.Fatalf("record ip tunnel: %v", err)
	}
	status := daemon.stateFilesStatus()
	iptunnel := stateFileByName(t, status, "iptunnel")
	if iptunnel.Records != 1 || !strings.Contains(iptunnel.Detail, "active_refs=2") {
		t.Fatalf("iptunnel state status = %#v, want one active tunnel with two refs", iptunnel)
	}
}

func stateFileByName(t *testing.T, status stateFilesStatus, name string) stateFileStatus {
	t.Helper()
	for _, file := range status.Files {
		if file.Name == name {
			return file
		}
	}
	t.Fatalf("state file %q missing from %#v", name, status)
	return stateFileStatus{}
}
