package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"trustix.local/trustix/internal/buildinfo"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/device"
	"trustix.local/trustix/internal/transport"
	experimentaltcptransport "trustix.local/trustix/internal/transport/experimentaltcp"
	httpconnecttransport "trustix.local/trustix/internal/transport/httpconnect"
	quictransport "trustix.local/trustix/internal/transport/quic"
	securetransport "trustix.local/trustix/internal/transport/secure"
	tcptransport "trustix.local/trustix/internal/transport/tcp"
	udptransport "trustix.local/trustix/internal/transport/udp"
	websockettransport "trustix.local/trustix/internal/transport/websocket"
)

type stringList []string

func (list *stringList) String() string {
	return strings.Join(*list, ",")
}

func (list *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*list = append(*list, value)
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		buildinfo.WriteText(os.Stdout, buildinfo.Snapshot())
		return
	}
	var roots stringList
	var routes stringList
	var suites stringList
	fs := flag.NewFlagSet("trustix-device", flag.ExitOnError)
	configPath := fs.String("config", "", "YAML/JSON trustix-device config file")
	domain := fs.String("domain", "", "TrustIX domain id")
	ix := fs.String("ix", "", "IX id that issued this device certificate")
	endpoint := fs.String("endpoint", "", "IX data endpoint address")
	endpointName := fs.String("endpoint-name", "device-access", "IX data endpoint name")
	protocol := fs.String("transport", "udp", "transport: udp, tcp, quic, websocket, http_connect, experimental_tcp")
	certPath := fs.String("cert", "", "device certificate PEM, including IX intermediate when available")
	keyPath := fs.String("key", "", "device private key PEM")
	serverName := fs.String("server-name", "", "TLS/secure server name; defaults to domain")
	iface := fs.String("iface", "trustix0", "TUN interface name")
	mtu := fs.Int("mtu", 1400, "TUN interface MTU")
	encryption := fs.String("encryption", securetransport.EncryptionSecure, "secure overlay encryption mode")
	keySource := fs.String("crypto-key-source", securetransport.KeySourceAuto, "secure overlay key source")
	statsEvery := fs.Duration("stats-every", 30*time.Second, "periodic stats interval; 0 disables")
	fs.Var(&roots, "ca", "trusted CA PEM; repeat for root/domain CA")
	fs.Var(&routes, "route", "CIDR to route through TrustIX device tunnel; repeatable")
	fs.Var(&suites, "crypto-suite", "secure overlay crypto suite preference; repeatable")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}

	visited := map[string]bool{}
	fs.Visit(func(flag *flag.Flag) {
		visited[flag.Name] = true
	})

	clientCfg, err := loadClientConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if visited["domain"] || *configPath == "" {
		clientCfg.Domain = core.DomainID(strings.TrimSpace(*domain))
	}
	if visited["ix"] || *configPath == "" {
		clientCfg.IX = core.IXID(strings.TrimSpace(*ix))
	}
	if visited["endpoint"] || *configPath == "" {
		clientCfg.Endpoint.Address = strings.TrimSpace(*endpoint)
	}
	if visited["endpoint-name"] || *configPath == "" {
		clientCfg.Endpoint.Name = core.EndpointID(strings.TrimSpace(*endpointName))
	}
	if visited["transport"] || *configPath == "" {
		clientCfg.Endpoint.Transport = transport.Protocol(strings.ToLower(strings.TrimSpace(*protocol)))
	}
	if visited["cert"] || *configPath == "" {
		clientCfg.CertPath = strings.TrimSpace(*certPath)
	}
	if visited["key"] || *configPath == "" {
		clientCfg.KeyPath = strings.TrimSpace(*keyPath)
	}
	if visited["server-name"] || *configPath == "" {
		clientCfg.ServerName = strings.TrimSpace(*serverName)
	}
	if visited["iface"] || *configPath == "" {
		clientCfg.Interface.Name = strings.TrimSpace(*iface)
	}
	if visited["mtu"] || *configPath == "" {
		clientCfg.Interface.MTU = *mtu
	}
	if visited["encryption"] || *configPath == "" {
		encryptionMode := securetransport.NormalizeEncryptionMode(*encryption)
		clientCfg.Encryption = encryptionMode
		clientCfg.Endpoint.Encryption = encryptionMode
	}
	if visited["crypto-key-source"] || *configPath == "" {
		clientCfg.KeySource = strings.TrimSpace(*keySource)
	}
	if visited["stats-every"] || *configPath == "" {
		clientCfg.StatsEvery = *statsEvery
	}
	if visited["ca"] || *configPath == "" {
		clientCfg.TrustRoots = roots
	}
	if visited["route"] || *configPath == "" {
		parsedRoutes, err := device.ParsePrefixes(routes)
		if err != nil {
			fatal(err)
		}
		clientCfg.Interface.Routes = parsedRoutes
	}
	if visited["crypto-suite"] || *configPath == "" {
		clientCfg.CryptoSuites = suites
	}
	if clientCfg.Endpoint.Name == "" {
		clientCfg.Endpoint.Name = core.EndpointID(*endpointName)
	}
	if clientCfg.Endpoint.Transport == "" {
		clientCfg.Endpoint.Transport = transport.ProtocolUDP
	}
	if clientCfg.Encryption == "" {
		clientCfg.Encryption = securetransport.EncryptionSecure
	}
	if clientCfg.Endpoint.Encryption == "" {
		clientCfg.Endpoint.Encryption = clientCfg.Encryption
	}
	if clientCfg.KeySource == "" {
		clientCfg.KeySource = securetransport.KeySourceAuto
	}

	if len(clientCfg.Interface.Routes) == 0 {
		fmt.Fprintln(os.Stderr, "trustix-device: no -route specified; interface will only receive packets explicitly addressed to the leased /32")
	}
	registry := transport.NewRegistry()
	secureOptions := securetransport.Options{
		KeySource:  func() string { return clientCfg.KeySource },
		Encryption: func() string { return securetransport.NormalizeEncryptionMode(clientCfg.Encryption) },
		CryptoSuites: func() []string {
			if len(clientCfg.CryptoSuites) == 0 {
				return securetransport.CryptoSuitesOrDefault(nil)
			}
			return securetransport.CryptoSuitesOrDefault(clientCfg.CryptoSuites)
		},
	}
	mustRegister(registry, securetransport.New(udptransport.New(), secureOptions))
	mustRegister(registry, securetransport.New(tcptransport.New(), secureOptions))
	mustRegister(registry, securetransport.New(quictransport.New(), secureOptions))
	mustRegister(registry, securetransport.New(websockettransport.New(), secureOptions))
	mustRegister(registry, securetransport.New(httpconnecttransport.New(), secureOptions))
	mustRegister(registry, securetransport.New(experimentaltcptransport.New(nil), secureOptions))
	tr, ok := registry.Get(clientCfg.Endpoint.Transport)
	if !ok {
		fatal(fmt.Errorf("unsupported transport %q", clientCfg.Endpoint.Transport))
	}
	clientCfg.Endpoint.Transport = tr.Name()
	clientCfg.DialTransport = tr.Dial
	clientCfg.Logf = func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "trustix-device: "+format+"\n", args...)
	}
	client, err := device.NewClient(clientCfg)
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "trustix-device starting: ix=%s endpoint=%s transport=%s iface=%s\n", clientCfg.IX, clientCfg.Endpoint.Address, tr.Name(), clientCfg.Interface.Name)
	if err := client.Run(ctx); err != nil && err != context.Canceled {
		fatal(err)
	}
}

func loadClientConfig(path string) (device.Config, error) {
	if strings.TrimSpace(path) == "" {
		return device.Config{StatsEvery: 30 * time.Second}, nil
	}
	fileCfg, err := device.LoadFileConfig(path)
	if err != nil {
		return device.Config{}, err
	}
	return fileCfg.ClientConfig()
}

func mustRegister(registry *transport.Registry, tr transport.Transport) {
	if err := registry.Register(tr); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "trustix-device: %v\n", err)
	os.Exit(1)
}
