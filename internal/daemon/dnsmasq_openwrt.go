package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"trustix.local/trustix/internal/config"
)

const (
	openWRTReleaseFile       = "/etc/openwrt_release"
	openWRTDNSMasqInitScript = "/etc/init.d/dnsmasq"
	openWRTDNSMasqUCISection = "dhcp.@dnsmasq[0]"
	openWRTDNSMasqStateFile  = "openwrt-dnsmasq.json"
)

type dnsMasqStatus struct {
	Enabled      bool   `json:"enabled"`
	Mode         string `json:"mode,omitempty"`
	Server       string `json:"server,omitempty"`
	RebindDomain string `json:"rebind_domain,omitempty"`
	Section      string `json:"section,omitempty"`
	Applied      bool   `json:"applied,omitempty"`
	Error        string `json:"error,omitempty"`
}

type openWRTDNSMasqState struct {
	Section      string `json:"section,omitempty"`
	Server       string `json:"server,omitempty"`
	RebindDomain string `json:"rebind_domain,omitempty"`
}

type openWRTCommandRunner interface {
	LookPath(file string) (string, error)
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type realOpenWRTCommandRunner struct{}

func (realOpenWRTCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (realOpenWRTCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

var openWRTDNSMasqCommands openWRTCommandRunner = realOpenWRTCommandRunner{}

func (daemon *Daemon) syncDNSMasq(ctx context.Context) error {
	if !daemon.desired.DNS.DNSMasq.Enabled {
		return daemon.cleanupOpenWRTDNSMasq(ctx)
	}
	return daemon.applyOpenWRTDNSMasq(ctx)
}

func (daemon *Daemon) cleanupDNSMasq(ctx context.Context) error {
	return daemon.cleanupOpenWRTDNSMasq(ctx)
}

func (daemon *Daemon) applyOpenWRTDNSMasq(ctx context.Context) error {
	if !daemon.desired.DNS.Enabled {
		return fmt.Errorf("openwrt dnsmasq integration requires dns enabled")
	}
	if err := openWRTDNSMasqAvailable(openWRTDNSMasqCommands); err != nil {
		return err
	}
	resolver, err := daemon.dnsResolverConfig()
	if err != nil {
		return err
	}
	server, err := openWRTDNSMasqServerForResolver(resolver)
	if err != nil {
		return err
	}
	rebindDomain, err := openWRTDNSMasqRebindDomainForResolver(resolver)
	if err != nil {
		return err
	}
	statePath := daemon.openWRTDNSMasqStatePath()
	state, err := readOpenWRTDNSMasqState(statePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read openwrt dnsmasq state: %w", err)
	}
	if state.Server != "" && state.Server != server {
		if err := openWRTDNSMasqDelServer(ctx, openWRTDNSMasqCommands, state.Section, state.Server); err != nil {
			return err
		}
	}
	if state.RebindDomain != "" && state.RebindDomain != rebindDomain {
		if err := openWRTDNSMasqDelRebindDomain(ctx, openWRTDNSMasqCommands, state.Section, state.RebindDomain); err != nil {
			return err
		}
	}
	if err := openWRTDNSMasqDelServer(ctx, openWRTDNSMasqCommands, openWRTDNSMasqUCISection, server); err != nil {
		return err
	}
	if err := openWRTDNSMasqDelRebindDomain(ctx, openWRTDNSMasqCommands, openWRTDNSMasqUCISection, rebindDomain); err != nil {
		return err
	}
	if err := openWRTDNSMasqAddServer(ctx, openWRTDNSMasqCommands, openWRTDNSMasqUCISection, server); err != nil {
		return err
	}
	if err := openWRTDNSMasqAddRebindDomain(ctx, openWRTDNSMasqCommands, openWRTDNSMasqUCISection, rebindDomain); err != nil {
		return err
	}
	if err := openWRTDNSMasqCommit(ctx, openWRTDNSMasqCommands); err != nil {
		return err
	}
	if err := openWRTDNSMasqReload(ctx, openWRTDNSMasqCommands); err != nil {
		return err
	}
	return writeOpenWRTDNSMasqState(statePath, openWRTDNSMasqState{
		Section:      openWRTDNSMasqUCISection,
		Server:       server,
		RebindDomain: rebindDomain,
	})
}

func (daemon *Daemon) cleanupOpenWRTDNSMasq(ctx context.Context) error {
	statePath := daemon.openWRTDNSMasqStatePath()
	state, err := readOpenWRTDNSMasqState(statePath)
	if errors.Is(err, os.ErrNotExist) || err == nil && state.Server == "" && state.RebindDomain == "" {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read openwrt dnsmasq state: %w", err)
	}
	if err := openWRTDNSMasqAvailable(openWRTDNSMasqCommands); err != nil {
		return err
	}
	if err := openWRTDNSMasqDelServer(ctx, openWRTDNSMasqCommands, state.Section, state.Server); err != nil {
		return err
	}
	if err := openWRTDNSMasqDelRebindDomain(ctx, openWRTDNSMasqCommands, state.Section, state.RebindDomain); err != nil {
		return err
	}
	if err := openWRTDNSMasqCommit(ctx, openWRTDNSMasqCommands); err != nil {
		return err
	}
	if err := openWRTDNSMasqReload(ctx, openWRTDNSMasqCommands); err != nil {
		return err
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncStateDirectory(filepath.Dir(statePath))
}

func (daemon *Daemon) dnsMasqStatus() dnsMasqStatus {
	status := dnsMasqStatus{
		Enabled: daemon.desired.DNS.DNSMasq.Enabled,
		Mode:    "openwrt_dnsmasq",
		Section: openWRTDNSMasqUCISection,
	}
	if !daemon.desired.DNS.DNSMasq.Enabled {
		return status
	}
	resolver, err := daemon.dnsResolverConfig()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	server, err := openWRTDNSMasqServerForResolver(resolver)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	rebindDomain, err := openWRTDNSMasqRebindDomainForResolver(resolver)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Server = server
	status.RebindDomain = rebindDomain
	if state, err := readOpenWRTDNSMasqState(daemon.openWRTDNSMasqStatePath()); err == nil && state.Server == server && state.RebindDomain == rebindDomain {
		status.Applied = true
	}
	return status
}

func (daemon *Daemon) openWRTDNSMasqStatePath() string {
	dataDir := daemon.cfg.DataDir
	if strings.TrimSpace(dataDir) == "" {
		dataDir = ".trustix"
	}
	return filepath.Join(dataDir, "dns", openWRTDNSMasqStateFile)
}

func openWRTDNSMasqAvailable(runner openWRTCommandRunner) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("openwrt dnsmasq integration is Linux-only")
	}
	if _, err := os.Stat(openWRTReleaseFile); err != nil {
		return fmt.Errorf("openwrt dnsmasq integration requires %s: %w", openWRTReleaseFile, err)
	}
	if _, err := os.Stat(openWRTDNSMasqInitScript); err != nil {
		return fmt.Errorf("openwrt dnsmasq integration requires %s: %w", openWRTDNSMasqInitScript, err)
	}
	if _, err := runner.LookPath("uci"); err != nil {
		return fmt.Errorf("openwrt dnsmasq integration requires uci: %w", err)
	}
	return nil
}

func openWRTDNSMasqServerForResolver(resolver dnsResolverConfig) (string, error) {
	domain, err := openWRTDNSMasqDomainForResolver(resolver)
	if err != nil {
		return "", err
	}
	host, port, err := net.SplitHostPort(resolver.Listen)
	if err != nil {
		return "", fmt.Errorf("parse dns listen %q for dnsmasq: %w", resolver.Listen, err)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		host = "127.0.0.1"
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.IsUnspecified() {
		host = "127.0.0.1"
	}
	if strings.TrimSpace(port) == "" {
		return "", fmt.Errorf("dns listen %q has no port", resolver.Listen)
	}
	return fmt.Sprintf("/%s/%s#%s", domain, host, port), nil
}

func openWRTDNSMasqRebindDomainForResolver(resolver dnsResolverConfig) (string, error) {
	return openWRTDNSMasqDomainForResolver(resolver)
}

func openWRTDNSMasqDomainForResolver(resolver dnsResolverConfig) (string, error) {
	if !resolver.Enabled {
		return "", fmt.Errorf("dns resolver is disabled")
	}
	domain := strings.Trim(strings.TrimSpace(resolver.Domain), ".")
	if domain == "" {
		return "", fmt.Errorf("dns domain is required")
	}
	return domain, nil
}

func openWRTDNSMasqDelServer(ctx context.Context, runner openWRTCommandRunner, section string, server string) error {
	section = openWRTDNSMasqSection(section)
	if strings.TrimSpace(server) == "" {
		return nil
	}
	_, err := runner.Run(ctx, "uci", "-q", "del_list", section+".server="+server)
	if err != nil {
		if openWRTUCIDeleteValueMissing(err) {
			return nil
		}
		return fmt.Errorf("remove openwrt dnsmasq server %q: %w", server, err)
	}
	return nil
}

func openWRTDNSMasqAddServer(ctx context.Context, runner openWRTCommandRunner, section string, server string) error {
	section = openWRTDNSMasqSection(section)
	out, err := runner.Run(ctx, "uci", "-q", "add_list", section+".server="+server)
	if err != nil {
		return fmt.Errorf("add openwrt dnsmasq server %q: %w%s", server, err, commandOutputSuffix(out))
	}
	return nil
}

func openWRTDNSMasqDelRebindDomain(ctx context.Context, runner openWRTCommandRunner, section string, domain string) error {
	section = openWRTDNSMasqSection(section)
	if strings.TrimSpace(domain) == "" {
		return nil
	}
	_, err := runner.Run(ctx, "uci", "-q", "del_list", section+".rebind_domain="+domain)
	if err != nil {
		if openWRTUCIDeleteValueMissing(err) {
			return nil
		}
		return fmt.Errorf("remove openwrt dnsmasq rebind domain %q: %w", domain, err)
	}
	return nil
}

func openWRTUCIDeleteValueMissing(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}

func openWRTDNSMasqAddRebindDomain(ctx context.Context, runner openWRTCommandRunner, section string, domain string) error {
	section = openWRTDNSMasqSection(section)
	if strings.TrimSpace(domain) == "" {
		return nil
	}
	out, err := runner.Run(ctx, "uci", "-q", "add_list", section+".rebind_domain="+domain)
	if err != nil {
		return fmt.Errorf("add openwrt dnsmasq rebind domain %q: %w%s", domain, err, commandOutputSuffix(out))
	}
	return nil
}

func openWRTDNSMasqCommit(ctx context.Context, runner openWRTCommandRunner) error {
	out, err := runner.Run(ctx, "uci", "-q", "commit", "dhcp")
	if err != nil {
		return fmt.Errorf("commit openwrt dnsmasq config: %w%s", err, commandOutputSuffix(out))
	}
	return nil
}

func openWRTDNSMasqReload(ctx context.Context, runner openWRTCommandRunner) error {
	out, err := runner.Run(ctx, openWRTDNSMasqInitScript, "reload")
	if err == nil {
		return nil
	}
	reloadErr := fmt.Errorf("reload openwrt dnsmasq: %w%s", err, commandOutputSuffix(out))
	out, restartErr := runner.Run(ctx, openWRTDNSMasqInitScript, "restart")
	if restartErr != nil {
		return errors.Join(reloadErr, fmt.Errorf("restart openwrt dnsmasq: %w%s", restartErr, commandOutputSuffix(out)))
	}
	return nil
}

func openWRTDNSMasqSection(section string) string {
	section = strings.TrimSpace(section)
	if section == "" {
		return openWRTDNSMasqUCISection
	}
	return section
}

func commandOutputSuffix(output []byte) string {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return ""
	}
	return ": " + trimmed
}

func readOpenWRTDNSMasqState(path string) (openWRTDNSMasqState, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return openWRTDNSMasqState{}, err
	}
	var state openWRTDNSMasqState
	if err := json.Unmarshal(payload, &state); err != nil {
		return openWRTDNSMasqState{}, err
	}
	return state, nil
}

func writeOpenWRTDNSMasqState(path string, state openWRTDNSMasqState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeStateFileAtomic(path, append(payload, '\n'), 0o600)
}

func dnsMasqIntegrationEnabled(desired config.Desired) bool {
	return desired.DNS.Enabled && desired.DNS.DNSMasq.Enabled
}

func dnsMasqIntegrationNeedsRestart(oldDesired, newDesired config.Desired) bool {
	return dnsMasqIntegrationEnabled(oldDesired) != dnsMasqIntegrationEnabled(newDesired) ||
		oldDesired.DNS.DNSMasq != newDesired.DNS.DNSMasq
}
