package iptunnel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestManagerAcquireReusesProtocolConfigAndReleaseRefCounts(t *testing.T) {
	manager := NewManager(t.TempDir())
	ctx := context.Background()
	originalExists := managerKernelTunnelExists
	managerKernelTunnelExists = func(name string) bool { return name == "tixgrtest" }
	defer func() { managerKernelTunnelExists = originalExists }()
	creates := 0
	create := func() (string, error) {
		creates++
		return "tixgrtest", nil
	}
	record := TunnelRecord{
		Protocol: "gre",
		Endpoint: "local-gre",
		Role:     "listen",
		Config:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400",
	}
	name, err := manager.Acquire(ctx, record, create)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if name != "tixgrtest" || creates != 1 {
		t.Fatalf("first acquire name=%q creates=%d, want tixgrtest/1", name, creates)
	}
	record.Endpoint = "peer-gre"
	record.Role = "dial"
	name, err = manager.Acquire(ctx, record, create)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if name != "tixgrtest" || creates != 1 {
		t.Fatalf("second acquire name=%q creates=%d, want reused tunnel", name, creates)
	}
	records, err := manager.Plan(ctx)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(records) != 1 || records[0].RefCount != 2 {
		t.Fatalf("records = %#v, want one record with ref_count=2", records)
	}
	if records[0].Endpoint != "local-gre,peer-gre" || records[0].Role != "listen,dial" {
		t.Fatalf("merged record = %#v, want both endpoint/role labels", records[0])
	}
	if err := manager.Release(ctx, "tixgrtest"); err != nil {
		t.Fatalf("first release: %v", err)
	}
	records, err = manager.Plan(ctx)
	if err != nil {
		t.Fatalf("plan after first release: %v", err)
	}
	if len(records) != 1 || records[0].RefCount != 1 {
		t.Fatalf("records after first release = %#v, want ref_count=1", records)
	}
	if err := manager.Release(ctx, "tixgrtest"); err != nil {
		t.Fatalf("second release: %v", err)
	}
	records, err = manager.Plan(ctx)
	if err != nil {
		t.Fatalf("plan after second release: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records after second release = %#v, want empty", records)
	}
}

func TestManagerAcquireDropsStaleMissingTunnelRecord(t *testing.T) {
	manager := NewManager(t.TempDir())
	ctx := context.Background()
	originalExists := managerKernelTunnelExists
	managerKernelTunnelExists = func(name string) bool { return name == "tixgrnew" }
	defer func() { managerKernelTunnelExists = originalExists }()
	config := "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400"
	if err := manager.Record(ctx, TunnelRecord{Name: "tixgrstale", Protocol: "gre", Endpoint: "old", Role: "listen", Config: config, RefCount: 4}); err != nil {
		t.Fatalf("record stale: %v", err)
	}
	name, err := manager.Acquire(ctx, TunnelRecord{Protocol: "gre", Endpoint: "new", Role: "dial", Config: config}, func() (string, error) {
		return "tixgrnew", nil
	})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if name != "tixgrnew" {
		t.Fatalf("acquired name = %q, want new tunnel", name)
	}
	records, err := manager.Plan(ctx)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(records) != 1 || records[0].Name != "tixgrnew" || records[0].RefCount != 1 {
		t.Fatalf("records = %#v, want only new record", records)
	}
}

func TestManagerAcquireReusesDeterministicExistingTunnel(t *testing.T) {
	manager := NewManager(t.TempDir())
	ctx := context.Background()
	originalExists := managerKernelTunnelExists
	defer func() { managerKernelTunnelExists = originalExists }()
	config := "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400"
	name := DeterministicTunnelName("gre", config)
	managerKernelTunnelExists = func(candidate string) bool { return candidate == name }
	creates := 0
	got, err := manager.Acquire(ctx, TunnelRecord{
		Name:     name,
		Protocol: "gre",
		Endpoint: "route",
		Role:     "native_route",
		Config:   config,
	}, func() (string, error) {
		creates++
		return name, nil
	})
	if err != nil {
		t.Fatalf("acquire existing deterministic tunnel: %v", err)
	}
	if got != name || creates != 0 {
		t.Fatalf("acquire name=%q creates=%d, want existing %q without create", got, creates, name)
	}
	records, err := manager.Plan(ctx)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(records) != 1 || records[0].Name != name || records[0].RefCount != 1 {
		t.Fatalf("records = %#v, want recorded existing tunnel", records)
	}
}

func TestManagerAcquireReusesDeterministicTunnelAfterCreateRace(t *testing.T) {
	manager := NewManager(t.TempDir())
	ctx := context.Background()
	originalExists := managerKernelTunnelExists
	defer func() { managerKernelTunnelExists = originalExists }()
	config := "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400"
	name := DeterministicTunnelName("vxlan", config)
	createCalled := false
	managerKernelTunnelExists = func(candidate string) bool {
		return createCalled && candidate == name
	}
	got, err := manager.Acquire(ctx, TunnelRecord{
		Name:     name,
		Protocol: "vxlan",
		Endpoint: "listener",
		Role:     "listen",
		Config:   config,
	}, func() (string, error) {
		createCalled = true
		return "", os.ErrExist
	})
	if err != nil {
		t.Fatalf("acquire racing deterministic tunnel: %v", err)
	}
	if got != name {
		t.Fatalf("acquire name = %q, want %q", got, name)
	}
	records, err := manager.Plan(ctx)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(records) != 1 || records[0].Name != name {
		t.Fatalf("records = %#v, want deterministic tunnel recorded", records)
	}
}

func TestManagerCleanupClearsState(t *testing.T) {
	dataDir := t.TempDir()
	manager := NewManager(dataDir)
	ctx := context.Background()
	if err := manager.Record(ctx, TunnelRecord{Name: "tixipstale", Protocol: "ipip", Config: "stale", RefCount: 3}); err != nil {
		t.Fatalf("record: %v", err)
	}
	records, err := manager.Cleanup(ctx)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(records) != 1 || records[0].Name != "tixipstale" {
		t.Fatalf("cleanup records = %#v, want stale record", records)
	}
	payload, err := os.ReadFile(filepath.Join(dataDir, "iptunnel", "state.json"))
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if string(payload) != "{\n  \"tunnels\": null\n}\n" {
		t.Fatalf("state file after cleanup = %q, want empty tunnel state", payload)
	}
}
