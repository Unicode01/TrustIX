package daemon

import (
	"context"
	"testing"

	"trustix.local/trustix/internal/dataplane"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
)

func TestAppendIPTunnelCleanupPlanIncludesRecordedTunnels(t *testing.T) {
	dataDir := t.TempDir()
	manager := iptunneltransport.NewManager(dataDir)
	if err := manager.Record(context.Background(), iptunneltransport.TunnelRecord{
		Name:     "tixgrplan",
		Protocol: "gre",
		Endpoint: "gre",
		Role:     "listen",
		Config:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,mtu=1400",
		RefCount: 2,
	}); err != nil {
		t.Fatalf("record tunnel: %v", err)
	}
	plan, err := appendIPTunnelCleanupPlan(context.Background(), dataDir, dataplane.CleanupPlan{
		Steps: []dataplane.CleanupStep{{Action: "load_state"}},
	})
	if err != nil {
		t.Fatalf("append ip tunnel cleanup plan: %v", err)
	}
	for _, step := range plan.Steps {
		if step.Action == "delete_ip_tunnel" && step.Target == "tixgrplan" {
			return
		}
	}
	t.Fatalf("cleanup plan steps = %#v, want delete_ip_tunnel for recorded GRE tunnel", plan.Steps)
}
