package daemon

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/routing"
)

func TestDNSResolverAnswersLocalIX(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787"},
		desired: config.Desired{
			Domain: config.DomainConfig{ID: "trust.ix"},
			IX:     config.IXConfig{ID: "ix-a", Domain: "trust.ix"},
			LAN: config.LANConfig{
				Iface:     "br-lan",
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
			},
			Management: config.ManagementConfig{
				HostAPI: config.HostManagementAPIConfig{Enabled: true, Listen: "10.0.0.1:8787"},
			},
			DNS: config.DNSConfig{Enabled: true, TTL: "30s"},
		},
		members: make(map[core.IXID]memberRecord),
	}
	cfg, err := daemon.dnsResolverConfig()
	if err != nil {
		t.Fatalf("dns resolver config: %v", err)
	}
	handler := &trustIXDNSHandler{daemon: daemon, config: cfg}
	response := handler.handleDNSQuery(context.Background(), dnsQuestion("ix-a.trust.ix.", mdns.TypeA), "udp")
	if response.Rcode != mdns.RcodeSuccess {
		t.Fatalf("dns rcode = %s", mdns.RcodeToString[response.Rcode])
	}
	assertDNSARecord(t, response, "10.0.0.1")
}

func TestDNSServerLifecycleAnswersUDP(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787"},
		desired: config.Desired{
			Domain: config.DomainConfig{ID: "trust.ix"},
			IX:     config.IXConfig{ID: "ix-a", Domain: "trust.ix"},
			LAN: config.LANConfig{
				Iface:     "br-lan",
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
			},
			Management: config.ManagementConfig{
				HostAPI: config.HostManagementAPIConfig{Enabled: true, Listen: "10.0.0.1:8787"},
			},
			DNS: config.DNSConfig{Enabled: true, Listen: "127.0.0.1:0", TTL: "30s"},
		},
		members: make(map[core.IXID]memberRecord),
	}
	if err := daemon.startDNSServer(context.Background()); err != nil {
		t.Fatalf("start dns server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := daemon.closeDNSServer(ctx); err != nil {
			t.Fatalf("close dns server: %v", err)
		}
	})
	daemon.dnsMu.Lock()
	listen := daemon.dnsServer.UDP.PacketConn.LocalAddr().String()
	daemon.dnsMu.Unlock()

	client := &mdns.Client{Net: "udp", Timeout: time.Second}
	response, _, err := client.Exchange(dnsQuestion("ix-a.trust.ix.", mdns.TypeA), listen)
	if err != nil {
		t.Fatalf("dns exchange: %v", err)
	}
	if response.Rcode != mdns.RcodeSuccess {
		t.Fatalf("dns rcode = %s", mdns.RcodeToString[response.Rcode])
	}
	assertDNSARecord(t, response, "10.0.0.1")
}

func TestDNSResolverDefaultsToLoopbackWhenDNSMasqEnabled(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: "trust.ix"},
			IX:     config.IXConfig{ID: "ix-a", Domain: "trust.ix"},
			LAN: config.LANConfig{
				Iface:     "br-lan",
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
			},
			DNS: config.DNSConfig{Enabled: true, DNSMasq: config.DNSMasqConfig{Enabled: true}},
		},
	}
	cfg, err := daemon.dnsResolverConfig()
	if err != nil {
		t.Fatalf("dns resolver config: %v", err)
	}
	if cfg.Listen != "127.0.0.1:1053" {
		t.Fatalf("dns listen = %q, want loopback dnsmasq target", cfg.Listen)
	}
}

func TestOpenWRTDNSMasqServerForResolver(t *testing.T) {
	server, err := openWRTDNSMasqServerForResolver(dnsResolverConfig{
		Enabled: true,
		Listen:  "127.0.0.1:1053",
		Domain:  "trust.ix",
	})
	if err != nil {
		t.Fatalf("dnsmasq server: %v", err)
	}
	if server != "/trust.ix/127.0.0.1#1053" {
		t.Fatalf("dnsmasq server = %q", server)
	}
	rebindDomain, err := openWRTDNSMasqRebindDomainForResolver(dnsResolverConfig{
		Enabled: true,
		Listen:  "127.0.0.1:1053",
		Domain:  "trust.ix",
	})
	if err != nil {
		t.Fatalf("dnsmasq rebind domain: %v", err)
	}
	if rebindDomain != "trust.ix" {
		t.Fatalf("dnsmasq rebind domain = %q", rebindDomain)
	}
}

func TestOpenWRTDNSMasqServerUsesLoopbackForWildcardListen(t *testing.T) {
	server, err := openWRTDNSMasqServerForResolver(dnsResolverConfig{
		Enabled: true,
		Listen:  "0.0.0.0:1053",
		Domain:  "trust.ix",
	})
	if err != nil {
		t.Fatalf("dnsmasq server: %v", err)
	}
	if server != "/trust.ix/127.0.0.1#1053" {
		t.Fatalf("dnsmasq server = %q", server)
	}
}

func TestOpenWRTDNSMasqUCICommands(t *testing.T) {
	runner := &recordingOpenWRTCommandRunner{}
	ctx := context.Background()
	server := "/trust.ix/127.0.0.1#1053"
	rebindDomain := "trust.ix"
	if err := openWRTDNSMasqDelServer(ctx, runner, "", server); err != nil {
		t.Fatalf("del server: %v", err)
	}
	if err := openWRTDNSMasqDelRebindDomain(ctx, runner, "", rebindDomain); err != nil {
		t.Fatalf("del rebind domain: %v", err)
	}
	if err := openWRTDNSMasqAddServer(ctx, runner, "", server); err != nil {
		t.Fatalf("add server: %v", err)
	}
	if err := openWRTDNSMasqAddRebindDomain(ctx, runner, "", rebindDomain); err != nil {
		t.Fatalf("add rebind domain: %v", err)
	}
	if err := openWRTDNSMasqCommit(ctx, runner); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := openWRTDNSMasqReload(ctx, runner); err != nil {
		t.Fatalf("reload: %v", err)
	}
	want := []string{
		"uci\x00-q\x00del_list\x00dhcp.@dnsmasq[0].server=/trust.ix/127.0.0.1#1053",
		"uci\x00-q\x00del_list\x00dhcp.@dnsmasq[0].rebind_domain=trust.ix",
		"uci\x00-q\x00add_list\x00dhcp.@dnsmasq[0].server=/trust.ix/127.0.0.1#1053",
		"uci\x00-q\x00add_list\x00dhcp.@dnsmasq[0].rebind_domain=trust.ix",
		"uci\x00-q\x00commit\x00dhcp",
		"/etc/init.d/dnsmasq\x00reload",
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("uci calls = %#v, want %#v", runner.calls, want)
	}
}

func TestOpenWRTDNSMasqReloadFallsBackToRestart(t *testing.T) {
	runner := &recordingOpenWRTCommandRunner{
		fail: map[string]error{
			"/etc/init.d/dnsmasq\x00reload": errors.New("reload failed"),
		},
	}
	if err := openWRTDNSMasqReload(context.Background(), runner); err != nil {
		t.Fatalf("reload with fallback: %v", err)
	}
	want := []string{
		"/etc/init.d/dnsmasq\x00reload",
		"/etc/init.d/dnsmasq\x00restart",
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("reload calls = %#v, want %#v", runner.calls, want)
	}
}

func TestDNSResolverAnswersAcceptedRemoteManagementVIP(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.Management.HostAPI.Enabled = true
	desiredA.Management.HostAPI.Listen = "10.0.0.1:8787"
	desiredA.DNS.Enabled = true
	desiredA.DNS.TTL = "30s"
	daemonA := newMembershipTestDaemon(t, desiredA, 1)

	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.Management.HostAPI.Enabled = true
	desiredB.Management.HostAPI.Listen = "10.0.1.200:8787"
	desiredB.RoutePolicy.ExportPrefixes = []core.Prefix{"10.0.1.200/32"}
	daemonB := newMembershipTestDaemon(t, desiredB, 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24", "10.0.1.200/32")

	advertisement, err := daemonB.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-b advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-b advertisement: %v", err)
	}
	route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.200/32")
	if !ok || route.Kind != routing.RouteLocal || route.Source != "management_vip" {
		t.Fatalf("management VIP route = %#v, ok=%t", route, ok)
	}

	cfg, err := daemonA.dnsResolverConfig()
	if err != nil {
		t.Fatalf("dns resolver config: %v", err)
	}
	handler := &trustIXDNSHandler{daemon: daemonA, config: cfg}
	response := handler.handleDNSQuery(context.Background(), dnsQuestion("ix-b.lab.local.", mdns.TypeA), "udp")
	if response.Rcode != mdns.RcodeSuccess {
		t.Fatalf("dns rcode = %s", mdns.RcodeToString[response.Rcode])
	}
	assertDNSARecord(t, response, "10.0.1.200")
}

func TestDNSResolverAnswersRemoteManagementIPCoveredByLANRoute(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.DNS.Enabled = true
	daemonA := newMembershipTestDaemon(t, desiredA, 1)

	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.Management.HostAPI.Enabled = true
	desiredB.Management.HostAPI.Listen = "10.0.1.1:8787"
	daemonB := newMembershipTestDaemon(t, desiredB, 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")

	advertisement, err := daemonB.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-b advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-b advertisement: %v", err)
	}
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.1/32"); ok {
		t.Fatalf("covered management IP should not require a separate VIP route: %#v", daemonA.runtimeRoutes())
	}

	cfg, err := daemonA.dnsResolverConfig()
	if err != nil {
		t.Fatalf("dns resolver config: %v", err)
	}
	handler := &trustIXDNSHandler{daemon: daemonA, config: cfg}
	response := handler.handleDNSQuery(context.Background(), dnsQuestion("ix-b.lab.local.", mdns.TypeA), "udp")
	if response.Rcode != mdns.RcodeSuccess {
		t.Fatalf("dns rcode = %s", mdns.RcodeToString[response.Rcode])
	}
	assertDNSARecord(t, response, "10.0.1.1")
}

func TestDNSResolverRejectsUnknownIX(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: "trust.ix"},
			IX:     config.IXConfig{ID: "ix-a", Domain: "trust.ix"},
			LAN: config.LANConfig{
				Iface:     "br-lan",
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
			},
			DNS: config.DNSConfig{Enabled: true},
		},
		members: make(map[core.IXID]memberRecord),
	}
	cfg, err := daemon.dnsResolverConfig()
	if err != nil {
		t.Fatalf("dns resolver config: %v", err)
	}
	handler := &trustIXDNSHandler{daemon: daemon, config: cfg}
	response := handler.handleDNSQuery(context.Background(), dnsQuestion("ix-missing.trust.ix.", mdns.TypeA), "udp")
	if response.Rcode != mdns.RcodeNameError {
		t.Fatalf("dns rcode = %s, want NXDOMAIN", mdns.RcodeToString[response.Rcode])
	}
}

func TestDNSResolverRefusesExternalWithoutUpstreams(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: "trust.ix"},
			IX:     config.IXConfig{ID: "ix-a", Domain: "trust.ix"},
			LAN: config.LANConfig{
				Iface:     "br-lan",
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
			},
			DNS: config.DNSConfig{Enabled: true},
		},
		members: make(map[core.IXID]memberRecord),
	}
	cfg, err := daemon.dnsResolverConfig()
	if err != nil {
		t.Fatalf("dns resolver config: %v", err)
	}
	if len(cfg.Upstreams) != 0 {
		t.Fatalf("dns upstreams = %#v, want empty split-only resolver", cfg.Upstreams)
	}
	handler := &trustIXDNSHandler{daemon: daemon, config: cfg}
	response := handler.handleDNSQuery(context.Background(), dnsQuestion("example.com.", mdns.TypeA), "udp")
	if response.Rcode != mdns.RcodeRefused {
		t.Fatalf("dns rcode = %s, want REFUSED", mdns.RcodeToString[response.Rcode])
	}
}

func dnsQuestion(name string, qtype uint16) *mdns.Msg {
	msg := new(mdns.Msg)
	msg.SetQuestion(name, qtype)
	return msg
}

func assertDNSARecord(t *testing.T, response *mdns.Msg, want string) {
	t.Helper()
	if len(response.Answer) != 1 {
		t.Fatalf("dns answers = %#v, want one A record", response.Answer)
	}
	record, ok := response.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("dns answer type = %T, want A", response.Answer[0])
	}
	if record.A.String() != want {
		t.Fatalf("dns A = %s, want %s", record.A, want)
	}
}

type recordingOpenWRTCommandRunner struct {
	calls []string
	fail  map[string]error
}

func (runner *recordingOpenWRTCommandRunner) LookPath(file string) (string, error) {
	return file, nil
}

func (runner *recordingOpenWRTCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), "\x00")
	runner.calls = append(runner.calls, key)
	if err := runner.fail[key]; err != nil {
		return []byte("failed"), err
	}
	return nil, nil
}
