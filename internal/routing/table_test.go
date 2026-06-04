package routing

import (
	"net/netip"
	"testing"

	"trustix.local/trustix/internal/core"
)

func TestTableLookupUsesLongestPrefix(t *testing.T) {
	table := NewTable()
	err := table.Replace([]Route{
		{Prefix: "10.0.0.0/8", NextHop: core.IXID("ix-a"), Metric: 100},
		{Prefix: "10.0.1.0/24", NextHop: core.IXID("ix-b"), Metric: 100},
	})
	if err != nil {
		t.Fatalf("replace routes: %v", err)
	}

	decision, ok := table.Lookup(netip.MustParseAddr("10.0.1.42"))
	if !ok {
		t.Fatal("expected route")
	}
	if decision.Route.NextHop != "ix-b" {
		t.Fatalf("next hop = %q, want ix-b", decision.Route.NextHop)
	}
}

func TestTableLookupUsesMetricAsTieBreaker(t *testing.T) {
	table := NewTable()
	err := table.Replace([]Route{
		{Prefix: "10.0.1.0/24", NextHop: core.IXID("ix-a"), Metric: 200},
		{Prefix: "10.0.1.0/24", NextHop: core.IXID("ix-b"), Metric: 100},
	})
	if err != nil {
		t.Fatalf("replace routes: %v", err)
	}

	decision, ok := table.Lookup(netip.MustParseAddr("10.0.1.42"))
	if !ok {
		t.Fatal("expected route")
	}
	if decision.Route.NextHop != "ix-b" {
		t.Fatalf("next hop = %q, want ix-b", decision.Route.NextHop)
	}
}

func TestTableAcceptsBlackholeAndRejectRoutes(t *testing.T) {
	table := NewTable()
	err := table.Replace([]Route{
		{Prefix: "10.66.0.0/16", Kind: RouteBlackhole, Metric: 10},
		{Prefix: "10.66.6.0/24", Kind: RouteReject, Metric: 10},
	})
	if err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	decision, ok := table.Lookup(netip.MustParseAddr("10.66.6.42"))
	if !ok {
		t.Fatal("expected route")
	}
	if decision.Route.Kind != RouteReject {
		t.Fatalf("route kind = %q, want reject", decision.Route.Kind)
	}
}

func TestTableRejectsUnsupportedRouteKind(t *testing.T) {
	table := NewTable()
	err := table.Replace([]Route{{Prefix: "10.66.0.0/16", Kind: RouteKind("throw")}})
	if err == nil {
		t.Fatal("expected unsupported route kind error")
	}
}
