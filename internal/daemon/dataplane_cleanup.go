package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
)

func CleanupDataplane(ctx context.Context, cfg Config) error {
	desired, err := config.LoadFile(cfg.ConfigPath)
	if err != nil {
		return err
	}
	lock, err := acquireDataDirLock(cfg.DataDir)
	if err != nil {
		return err
	}
	if lock != nil {
		defer lock.Close()
	}

	manager := selectDataplane(cfg.DataplaneMode)
	if manager == nil {
		return fmt.Errorf("unsupported dataplane mode %q", cfg.DataplaneMode)
	}
	if err := manager.Load(ctx); err != nil {
		return fmt.Errorf("load dataplane: %w", err)
	}
	spec := dataplaneAttachSpec(cfg.DataDir, desired)
	if cleaner, ok := manager.(dataplane.Cleaner); ok {
		if err := cleaner.Cleanup(ctx, spec); err != nil {
			return fmt.Errorf("cleanup dataplane: %w", err)
		}
	} else if err := manager.Detach(ctx); err != nil {
		return fmt.Errorf("cleanup dataplane: %w", err)
	}
	if _, err := iptunneltransport.NewManager(cfg.DataDir).Cleanup(ctx); err != nil {
		return fmt.Errorf("cleanup ip tunnels: %w", err)
	}
	return nil
}

func PlanCleanupDataplane(ctx context.Context, cfg Config) (dataplane.CleanupPlan, error) {
	desired, err := config.LoadFile(cfg.ConfigPath)
	if err != nil {
		return dataplane.CleanupPlan{}, err
	}
	lock, err := acquireDataDirLock(cfg.DataDir)
	if err != nil {
		return dataplane.CleanupPlan{}, err
	}
	if lock != nil {
		defer lock.Close()
	}

	manager := selectDataplane(cfg.DataplaneMode)
	if manager == nil {
		return dataplane.CleanupPlan{}, fmt.Errorf("unsupported dataplane mode %q", cfg.DataplaneMode)
	}
	if err := manager.Load(ctx); err != nil {
		return dataplane.CleanupPlan{}, fmt.Errorf("load dataplane: %w", err)
	}
	spec := dataplaneAttachSpec(cfg.DataDir, desired)
	if planner, ok := manager.(dataplane.CleanupPlanner); ok {
		plan, err := planner.PlanCleanup(ctx, spec)
		if err != nil {
			return dataplane.CleanupPlan{}, err
		}
		return appendIPTunnelCleanupPlan(ctx, cfg.DataDir, plan)
	}
	return appendIPTunnelCleanupPlan(ctx, cfg.DataDir, dataplane.CleanupPlan{
		Spec: spec,
		Steps: []dataplane.CleanupStep{{
			Action: "detach",
			Detail: "dataplane does not expose a detailed cleanup planner",
		}},
	})
}

func appendIPTunnelCleanupPlan(ctx context.Context, dataDir string, plan dataplane.CleanupPlan) (dataplane.CleanupPlan, error) {
	records, err := iptunneltransport.NewManager(dataDir).Plan(ctx)
	if err != nil {
		return dataplane.CleanupPlan{}, err
	}
	for _, record := range records {
		plan.Steps = append(plan.Steps, dataplane.CleanupStep{
			Action: "delete_ip_tunnel",
			Target: record.Name,
			Detail: fmt.Sprintf("protocol=%s endpoint=%s role=%s", record.Protocol, record.Endpoint, record.Role),
		})
	}
	return plan, nil
}

func WriteCleanupPlanJSON(w io.Writer, plan dataplane.CleanupPlan) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(plan)
}
