package daemon

import (
	"context"
	"testing"

	"trustix.local/trustix/internal/dataplane"
)

func TestControlViewSnapshotCachesSuccessfulRefreshes(t *testing.T) {
	t.Setenv("TRUSTIX_CONTROL_VIEW_CACHE_TTL", "5s")

	manager := &countingDataplaneManager{NoopManager: dataplane.NewNoopManager()}
	manager.stats = dataplane.Stats{Epoch: 7}
	daemon := &Daemon{
		dataplane: manager,
	}

	first := daemon.controlViewSnapshot()
	second := daemon.controlViewSnapshot()

	if manager.statsCalls != 1 {
		t.Fatalf("dataplane stats calls = %d, want 1", manager.statsCalls)
	}
	if first.DataplaneStats.Epoch != 7 || second.DataplaneStats.Epoch != 7 {
		t.Fatalf("dataplane epoch = %#v %#v, want 7", first.DataplaneStats.Epoch, second.DataplaneStats.Epoch)
	}
	if first.Epoch != second.Epoch {
		t.Fatalf("control view epoch changed across cached reads: %d vs %d", first.Epoch, second.Epoch)
	}
}

func TestControlViewSnapshotRefreshesOnEpochChange(t *testing.T) {
	t.Setenv("TRUSTIX_CONTROL_VIEW_CACHE_TTL", "5s")

	manager := &countingDataplaneManager{NoopManager: dataplane.NewNoopManager()}
	manager.stats = dataplane.Stats{Epoch: 11}
	daemon := &Daemon{
		dataplane: manager,
	}

	first := daemon.controlViewSnapshot()
	daemon.head.Seq++
	manager.stats.Epoch = 12
	second := daemon.controlViewSnapshot()

	if manager.statsCalls != 2 {
		t.Fatalf("dataplane stats calls = %d, want 2 after epoch change", manager.statsCalls)
	}
	if first.Epoch == second.Epoch {
		t.Fatalf("control view epoch did not change across runtime epoch bump: %d", first.Epoch)
	}
	if second.DataplaneStats.Epoch != 12 {
		t.Fatalf("dataplane epoch = %d, want 12", second.DataplaneStats.Epoch)
	}
}

type countingDataplaneManager struct {
	*dataplane.NoopManager
	stats      dataplane.Stats
	statsCalls int
}

func (manager *countingDataplaneManager) Stats(ctx context.Context) (dataplane.Stats, error) {
	manager.statsCalls++
	if err := ctx.Err(); err != nil {
		return dataplane.Stats{}, err
	}
	return manager.stats, nil
}
