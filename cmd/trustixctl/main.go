package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/adminauth"
	"trustix.local/trustix/internal/buildinfo"
	"trustix.local/trustix/internal/pki"
)

var commandPaths = map[string]string{
	"status":              "/v1/status",
	"peers":               "/v1/peers",
	"members":             "/v1/control/members",
	"routes":              "/v1/routes",
	"route probe":         "/v1/route/probe",
	"route trace":         "/v1/route/trace",
	"route-policy":        "/v1/route-policy",
	"flows":               "/v1/flows",
	"links":               "/v1/links",
	"device-access":       "/v1/device-access",
	"devices":             "/v1/device-access",
	"endpoints":           "/v1/endpoints",
	"config desired":      "/v1/config/desired",
	"config peers":        "/v1/config/peers",
	"config head":         "/v1/config/head",
	"config log":          "/v1/config/log",
	"config verify":       "/v1/config/verify",
	"config snapshot":     "/v1/config/snapshot",
	"trust show":          "/v1/trust",
	"admissions":          "/v1/admissions",
	"admissions pending":  "/v1/admissions/pending",
	"capture":             "/v1/capture",
	"stats":               "/v1/datapath",
	"datapath":            "/v1/datapath",
	"transports":          "/v1/transports",
	"kernel capabilities": "/v1/kernel/capabilities",
	"kernel-capabilities": "/v1/kernel/capabilities",
	"bpf maps":            "/v1/bpf/maps",
	"doctor":              "/v1/doctor",
	"trace":               "/v1/route/trace",
}

func main() {
	api := os.Getenv("TRUSTIX_API")
	if api == "" {
		api = "http://127.0.0.1:8787"
	}
	targetIX := os.Getenv("TRUSTIX_TARGET_IX")
	adminCert := os.Getenv("TRUSTIX_ADMIN_CERT")
	adminKey := os.Getenv("TRUSTIX_ADMIN_KEY")
	apiTLSCA := os.Getenv("TRUSTIX_API_TLS_CA")
	apiTLSServerName := os.Getenv("TRUSTIX_API_TLS_SERVER_NAME")
	adminCerts := multiValueFlag(splitListEnv(adminCert))
	adminKeys := multiValueFlag(splitListEnv(adminKey))
	apiTLSCAs := multiValueFlag(splitListEnv(apiTLSCA))
	apiTLSInsecureSkipVerify := boolEnv("TRUSTIX_API_TLS_INSECURE_SKIP_VERIFY")

	flags := flag.NewFlagSet("trustixctl", flag.ExitOnError)
	flags.StringVar(&api, "api", api, "trustixd management API base URL")
	flags.StringVar(&targetIX, "target-ix", targetIX, "target IX id for cross-IX management proxy requests")
	flags.Var(&adminCerts, "admin-cert", "admin certificate for signed management API requests; repeat for threshold policies")
	flags.Var(&adminKeys, "admin-key", "admin private key for signed management API requests; repeat for threshold policies")
	flags.Var(&apiTLSCAs, "api-tls-ca", "CA certificate for HTTPS management API verification; repeat to add multiple roots")
	flags.StringVar(&apiTLSServerName, "api-tls-server-name", apiTLSServerName, "server name for HTTPS management API certificate verification")
	flags.BoolVar(&apiTLSInsecureSkipVerify, "api-tls-insecure-skip-verify", apiTLSInsecureSkipVerify, "skip HTTPS management API certificate verification")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	client := apiClient{
		baseURL:                  api,
		targetIX:                 strings.TrimSpace(targetIX),
		adminCertPaths:           []string(adminCerts),
		adminKeyPaths:            []string(adminKeys),
		apiTLSCAPaths:            []string(apiTLSCAs),
		apiTLSServerName:         strings.TrimSpace(apiTLSServerName),
		apiTLSInsecureSkipVerify: apiTLSInsecureSkipVerify,
	}

	args := flags.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(2)
	}
	if len(args) == 1 && args[0] == "version" {
		buildinfo.WriteText(os.Stdout, buildinfo.Snapshot())
		return
	}

	if len(args) >= 2 && args[0] == "config" {
		if handled, err := handleConfigCommand(client, args[1:]); handled {
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(args) >= 2 && (args[0] == "member" || args[0] == "members") {
		if handled, err := handleMemberCommand(client, args[1:]); handled {
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(args) >= 1 && args[0] == "trust" {
		if handled, err := handleTrustCommand(client, args[1:]); handled {
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(args) >= 1 && args[0] == "admissions" {
		if handled, err := handleAdmissionsCommand(client, args[1:]); handled {
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(args) >= 1 && args[0] == "capture" {
		if handled, err := handleCaptureCommand(client, args[1:]); handled {
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(args) >= 1 && (args[0] == "device-access" || args[0] == "devices") {
		if handled, err := handleDeviceAccessCommand(client, args[1:]); handled {
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(args) >= 1 && args[0] == "route" {
		if handled, err := handleRouteCommand(client, args[1:]); handled {
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(args) >= 1 && args[0] == "trace" {
		if handled, err := handleTraceCommand(client, args[1:]); handled {
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	command := resolveCommand(args)
	path, ok := commandPaths[command]
	if !ok {
		fmt.Fprintf(os.Stderr, "trustixctl: unknown command %q\n\n", strings.Join(args, " "))
		printUsage()
		os.Exit(2)
	}

	if err := client.getAndPrint(path); err != nil {
		fmt.Fprintf(os.Stderr, "trustixctl: %v\n", err)
		os.Exit(1)
	}
}

type apiClient struct {
	baseURL                  string
	targetIX                 string
	adminCertPaths           []string
	adminKeyPaths            []string
	apiTLSCAPaths            []string
	apiTLSServerName         string
	apiTLSInsecureSkipVerify bool
}

type multiValueFlag []string

func (flagValue *multiValueFlag) String() string {
	return strings.Join(*flagValue, ",")
}

func (flagValue *multiValueFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		*flagValue = append(*flagValue, value)
	}
	return nil
}

func splitListEnv(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func boolEnv(name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false
	}
	value, err := strconv.ParseBool(raw)
	return err == nil && value
}

func handleConfigCommand(client apiClient, args []string) (bool, error) {
	switch args[0] {
	case "export":
		flags := flag.NewFlagSet("config export", flag.ContinueOnError)
		var out string
		flags.StringVar(&out, "out", "", "output archive path; defaults to server filename")
		if err := flags.Parse(args[1:]); err != nil {
			return true, err
		}
		if flags.NArg() != 0 {
			return true, fmt.Errorf("usage: trustixctl config export [-out file]")
		}
		body, err := json.Marshal(configExportCLIRequest{})
		if err != nil {
			return true, err
		}
		return true, client.postAndSave("/v1/config/export", body, "application/json", out)
	case "backup":
		flags := flag.NewFlagSet("config backup", flag.ContinueOnError)
		var out string
		var includePrivateKeys bool
		flags.StringVar(&out, "out", "", "output archive path; defaults to server filename")
		flags.BoolVar(&includePrivateKeys, "include-private-keys", false, "include configured private key files in the backup archive")
		if err := flags.Parse(args[1:]); err != nil {
			return true, err
		}
		if flags.NArg() != 0 || !includePrivateKeys {
			return true, fmt.Errorf("usage: trustixctl config backup -include-private-keys [-out file]")
		}
		body, err := json.Marshal(configExportCLIRequest{IncludePrivateKeys: true})
		if err != nil {
			return true, err
		}
		return true, client.postAndSave("/v1/config/export", body, "application/json", out)
	case "restore":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl config restore <archive.tar.gz>")
		}
		return true, client.postFileAndPrint("/v1/config/restore-archive", args[1], "application/gzip")
	case "validate":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl config validate <file>")
		}
		return true, client.postConfigFileAndPrint("/v1/config/validate", args[1])
	case "apply":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl config apply <file>")
		}
		return true, client.postConfigFileAndPrint("/v1/config/apply", args[1])
	case "rollback":
		if len(args) > 2 {
			return true, fmt.Errorf("usage: trustixctl config rollback [seq]")
		}
		var body []byte
		if len(args) == 2 {
			seq, err := strconv.ParseUint(args[1], 10, 64)
			if err != nil || seq == 0 {
				return true, fmt.Errorf("invalid rollback seq %q", args[1])
			}
			body, err = json.Marshal(struct {
				Seq uint64 `json:"seq"`
			}{Seq: seq})
			if err != nil {
				return true, err
			}
		}
		return true, client.postAndPrint("/v1/config/rollback", body, "application/json")
	case "rejoin":
		if len(args) < 2 || len(args) > 3 {
			return true, fmt.Errorf("usage: trustixctl config rejoin <control_api> [ix_id]")
		}
		request := struct {
			ControlAPI string `json:"control_api"`
			IXID       string `json:"ix_id,omitempty"`
		}{
			ControlAPI: args[1],
		}
		if len(args) == 3 {
			request.IXID = args[2]
		}
		body, err := json.Marshal(request)
		if err != nil {
			return true, err
		}
		return true, client.postAndPrint("/v1/config/rejoin", body, "application/json")
	case "restore-backup":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl config restore-backup <backup-path>")
		}
		body, err := json.Marshal(struct {
			Path string `json:"path"`
		}{Path: args[1]})
		if err != nil {
			return true, err
		}
		return true, client.postAndPrint("/v1/config/restore-backup", body, "application/json")
	case "verify":
		if len(args) != 1 {
			return true, fmt.Errorf("usage: trustixctl config verify")
		}
		return true, client.getAndPrint("/v1/config/verify")
	case "snapshot":
		if len(args) != 1 {
			return true, fmt.Errorf("usage: trustixctl config snapshot")
		}
		return true, client.getAndPrint("/v1/config/snapshot")
	case "log":
		if len(args) > 3 {
			return true, fmt.Errorf("usage: trustixctl config log [from [to]]")
		}
		query := url.Values{}
		if len(args) >= 2 {
			if _, err := parsePositiveUint(args[1]); err != nil {
				return true, fmt.Errorf("invalid config log from seq %q", args[1])
			}
			query.Set("from", args[1])
		}
		if len(args) == 3 {
			if _, err := parsePositiveUint(args[2]); err != nil {
				return true, fmt.Errorf("invalid config log to seq %q", args[2])
			}
			query.Set("to", args[2])
		}
		return true, client.getAndPrintPath("/v1/config/log", query)
	case "event":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl config event <seq>")
		}
		if _, err := parsePositiveUint(args[1]); err != nil {
			return true, fmt.Errorf("invalid config event seq %q", args[1])
		}
		query := url.Values{}
		query.Set("from", args[1])
		query.Set("to", args[1])
		return true, client.getAndPrintPath("/v1/config/log", query)
	default:
		return false, nil
	}
}

type configExportCLIRequest struct {
	IncludePrivateKeys bool `json:"include_private_keys,omitempty"`
}

func handleTrustCommand(client apiClient, args []string) (bool, error) {
	if len(args) == 0 {
		return true, client.getAndPrint("/v1/trust")
	}
	switch args[0] {
	case "show":
		if len(args) != 1 {
			return true, fmt.Errorf("usage: trustixctl trust show")
		}
		return true, client.getAndPrint("/v1/trust")
	case "policy", "admins":
		if len(args) != 1 {
			return true, fmt.Errorf("usage: trustixctl trust %s", args[0])
		}
		return true, client.getAndPrint("/v1/trust/policy")
	case "apply-policy":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl trust apply-policy <json-file>")
		}
		payload, err := os.ReadFile(args[1])
		if err != nil {
			return true, fmt.Errorf("read policy %q: %w", args[1], err)
		}
		return true, client.postAndPrint("/v1/trust/policy", payload, "application/json")
	case "roots":
		if len(args) == 1 {
			return true, client.getAndPrint("/v1/trust/roots")
		}
		if len(args) != 3 {
			return true, fmt.Errorf("usage: trustixctl trust roots [add <cert>|remove <fingerprint_or_cert>]")
		}
		switch args[1] {
		case "add":
			payload, err := os.ReadFile(args[2])
			if err != nil {
				return true, fmt.Errorf("read trust root %q: %w", args[2], err)
			}
			body, err := json.Marshal(struct {
				CertificatePEM string `json:"certificate_pem"`
			}{CertificatePEM: string(payload)})
			if err != nil {
				return true, err
			}
			return true, client.postAndPrint("/v1/trust/roots/add", body, "application/json")
		case "remove":
			fingerprint, err := fingerprintFromPathOrValue(args[2])
			if err != nil {
				return true, err
			}
			body, err := json.Marshal(struct {
				Fingerprint string `json:"fingerprint"`
			}{Fingerprint: fingerprint})
			if err != nil {
				return true, err
			}
			return true, client.postAndPrint("/v1/trust/roots/remove", body, "application/json")
		default:
			return true, fmt.Errorf("usage: trustixctl trust roots [add <cert>|remove <fingerprint_or_cert>]")
		}
	case "revoke":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl trust revoke <cert_or_fingerprint>")
		}
		fingerprint, err := fingerprintFromPathOrValue(args[1])
		if err != nil {
			return true, err
		}
		body, err := json.Marshal(struct {
			Fingerprint string `json:"fingerprint"`
		}{Fingerprint: fingerprint})
		if err != nil {
			return true, err
		}
		return true, client.postAndPrint("/v1/trust/revoke", body, "application/json")
	case "unrevoke":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl trust unrevoke <fingerprint>")
		}
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(args[1])
		if err != nil {
			return true, err
		}
		body, err := json.Marshal(struct {
			Fingerprint string `json:"fingerprint"`
		}{Fingerprint: fingerprint})
		if err != nil {
			return true, err
		}
		return true, client.postAndPrint("/v1/trust/unrevoke", body, "application/json")
	default:
		return false, nil
	}
}

func handleMemberCommand(client apiClient, args []string) (bool, error) {
	switch args[0] {
	case "delete", "remove", "rm":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl members delete <ix_id>")
		}
		return true, client.deleteAndPrint("/v1/control/members/" + url.PathEscape(args[1]))
	default:
		return false, nil
	}
}

func handleAdmissionsCommand(client apiClient, args []string) (bool, error) {
	if len(args) == 0 || len(args) == 1 && args[0] == "list" {
		return true, client.getAndPrint("/v1/admissions")
	}
	switch args[0] {
	case "pending":
		if len(args) == 1 {
			return true, client.getAndPrint("/v1/admissions/pending")
		}
		if len(args) == 2 {
			return true, client.getAndPrint("/v1/admissions/pending/" + url.PathEscape(args[1]))
		}
		return true, fmt.Errorf("usage: trustixctl admissions pending [ix_id]")
	case "show":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl admissions show <ix_id>")
		}
		return true, client.getAndPrint("/v1/admissions/" + url.PathEscape(args[1]))
	case "approve":
		flags := flag.NewFlagSet("admissions approve", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var ixID string
		var ixCert string
		var controlAPI string
		var effectiveAt string
		var prefixes multiValueFlag
		var routeAuths multiValueFlag
		flags.StringVar(&ixID, "ix", "", "IX id to approve")
		flags.StringVar(&ixCert, "ix-cert", "", "IX certificate path or SHA256 fingerprint")
		flags.Var(&prefixes, "prefix", "allowed LAN prefix; repeat to allow multiple prefixes")
		flags.Var(&routeAuths, "route-auth", "route authorization certificate path or SHA256 fingerprint; repeat to pin multiple certificates")
		flags.StringVar(&controlAPI, "control-api", "", "optional pinned control API URL")
		flags.StringVar(&effectiveAt, "effective-at", "", "optional RFC3339 effective time")
		if err := flags.Parse(args[1:]); err != nil {
			return true, fmt.Errorf("usage: trustixctl admissions approve -ix <ix_id> -ix-cert <cert_or_fingerprint> [-prefix cidr ...] [-route-auth cert_or_fingerprint ...] [-control-api url] [-effective-at rfc3339]")
		}
		if flags.NArg() != 0 || ixID == "" || ixCert == "" {
			return true, fmt.Errorf("usage: trustixctl admissions approve -ix <ix_id> -ix-cert <cert_or_fingerprint> [-prefix cidr ...] [-route-auth cert_or_fingerprint ...] [-control-api url] [-effective-at rfc3339]")
		}
		ixFingerprint, err := fingerprintFromPathOrValue(ixCert)
		if err != nil {
			return true, err
		}
		routeFingerprints := make([]string, 0, len(routeAuths))
		for _, raw := range routeAuths {
			fingerprint, err := fingerprintFromPathOrValue(raw)
			if err != nil {
				return true, err
			}
			routeFingerprints = append(routeFingerprints, fingerprint)
		}
		request := struct {
			IXID                  string    `json:"ix_id"`
			IXCertFingerprint     string    `json:"ix_cert_fingerprint"`
			AllowedPrefixes       []string  `json:"allowed_prefixes,omitempty"`
			RouteAuthFingerprints []string  `json:"route_auth_fingerprints,omitempty"`
			ControlAPI            string    `json:"control_api,omitempty"`
			EffectiveAt           time.Time `json:"effective_at,omitempty"`
		}{
			IXID:                  ixID,
			IXCertFingerprint:     ixFingerprint,
			AllowedPrefixes:       []string(prefixes),
			RouteAuthFingerprints: routeFingerprints,
			ControlAPI:            strings.TrimSpace(controlAPI),
		}
		if effectiveAt != "" {
			parsed, err := time.Parse(time.RFC3339, effectiveAt)
			if err != nil {
				return true, fmt.Errorf("invalid -effective-at %q: %w", effectiveAt, err)
			}
			request.EffectiveAt = parsed
		}
		body, err := json.Marshal(request)
		if err != nil {
			return true, err
		}
		return true, client.postAndPrint("/v1/admissions/approve", body, "application/json")
	case "approve-pending":
		flags := flag.NewFlagSet("admissions approve-pending", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var controlAPI string
		var effectiveAt string
		var prefixes multiValueFlag
		var routeAuths multiValueFlag
		flags.Var(&prefixes, "prefix", "allowed LAN prefix override; repeat to allow multiple prefixes")
		flags.Var(&routeAuths, "route-auth", "route authorization certificate path or SHA256 fingerprint override; repeat to pin multiple certificates")
		flags.StringVar(&controlAPI, "control-api", "", "optional pinned control API URL override")
		flags.StringVar(&effectiveAt, "effective-at", "", "optional RFC3339 effective time")
		parseArgs := args[1:]
		var ixID string
		if len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
			ixID = parseArgs[0]
			parseArgs = parseArgs[1:]
		}
		if err := flags.Parse(parseArgs); err != nil {
			return true, fmt.Errorf("usage: trustixctl admissions approve-pending <ix_id> [-prefix cidr ...] [-route-auth cert_or_fingerprint ...] [-control-api url] [-effective-at rfc3339]")
		}
		switch {
		case ixID != "" && flags.NArg() != 0:
			return true, fmt.Errorf("usage: trustixctl admissions approve-pending <ix_id> [-prefix cidr ...] [-route-auth cert_or_fingerprint ...] [-control-api url] [-effective-at rfc3339]")
		case ixID == "" && flags.NArg() == 1:
			ixID = flags.Arg(0)
		case ixID == "":
			return true, fmt.Errorf("usage: trustixctl admissions approve-pending <ix_id> [-prefix cidr ...] [-route-auth cert_or_fingerprint ...] [-control-api url] [-effective-at rfc3339]")
		}
		routeFingerprints := make([]string, 0, len(routeAuths))
		for _, raw := range routeAuths {
			fingerprint, err := fingerprintFromPathOrValue(raw)
			if err != nil {
				return true, err
			}
			routeFingerprints = append(routeFingerprints, fingerprint)
		}
		request := struct {
			IXID                  string    `json:"ix_id"`
			AllowedPrefixes       []string  `json:"allowed_prefixes,omitempty"`
			RouteAuthFingerprints []string  `json:"route_auth_fingerprints,omitempty"`
			ControlAPI            string    `json:"control_api,omitempty"`
			EffectiveAt           time.Time `json:"effective_at,omitempty"`
		}{
			IXID:                  ixID,
			AllowedPrefixes:       []string(prefixes),
			RouteAuthFingerprints: routeFingerprints,
			ControlAPI:            strings.TrimSpace(controlAPI),
		}
		if effectiveAt != "" {
			parsed, err := time.Parse(time.RFC3339, effectiveAt)
			if err != nil {
				return true, fmt.Errorf("invalid -effective-at %q: %w", effectiveAt, err)
			}
			request.EffectiveAt = parsed
		}
		body, err := json.Marshal(request)
		if err != nil {
			return true, err
		}
		return true, client.postAndPrint("/v1/admissions/approve-pending", body, "application/json")
	case "revoke":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl admissions revoke <ix_id>")
		}
		body, err := json.Marshal(struct {
			IXID string `json:"ix_id"`
		}{IXID: args[1]})
		if err != nil {
			return true, err
		}
		return true, client.postAndPrint("/v1/admissions/revoke", body, "application/json")
	default:
		return false, nil
	}
}

func handleCaptureCommand(client apiClient, args []string) (bool, error) {
	flags := flag.NewFlagSet("capture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var limit int
	var hook string
	var peer string
	var src string
	var dst string
	flags.IntVar(&limit, "limit", 0, "maximum packet events to return")
	flags.StringVar(&hook, "hook", "", "capture hook filter")
	flags.StringVar(&peer, "peer", "", "next-hop peer filter")
	flags.StringVar(&src, "src", "", "source IP filter")
	flags.StringVar(&dst, "dst", "", "destination IP filter")
	if err := flags.Parse(args); err != nil {
		return true, fmt.Errorf("usage: trustixctl capture [-limit n] [-hook hook] [-peer ix_id] [-src ip] [-dst ip]")
	}
	if flags.NArg() != 0 {
		return true, fmt.Errorf("usage: trustixctl capture [-limit n] [-hook hook] [-peer ix_id] [-src ip] [-dst ip]")
	}
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if hook != "" {
		query.Set("hook", hook)
	}
	if peer != "" {
		query.Set("peer", peer)
	}
	if src != "" {
		query.Set("src", src)
	}
	if dst != "" {
		query.Set("dst", dst)
	}
	return true, client.getAndPrintPath("/v1/capture", query)
}

func handleDeviceAccessCommand(client apiClient, args []string) (bool, error) {
	if len(args) == 0 || len(args) == 1 && (args[0] == "list" || args[0] == "ls") {
		return true, client.getAndPrint("/v1/device-access")
	}
	switch args[0] {
	case "show", "get":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: trustixctl device-access show <device|peer|address|fingerprint>")
		}
		return true, client.getAndPrint("/v1/device-access/" + url.PathEscape(args[1]))
	case "revoke":
		flags := flag.NewFlagSet("device-access revoke", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var ix string
		var fingerprint string
		flags.StringVar(&ix, "ix", "", "issuer IX id; defaults to local IX when revoking by device")
		flags.StringVar(&fingerprint, "fingerprint", "", "device certificate SHA256 fingerprint")
		if err := flags.Parse(args[1:]); err != nil {
			return true, fmt.Errorf("usage: trustixctl device-access revoke <device> [-ix ix_id] | trustixctl device-access revoke -fingerprint sha256")
		}
		device := ""
		switch flags.NArg() {
		case 0:
		case 1:
			device = flags.Arg(0)
		default:
			return true, fmt.Errorf("usage: trustixctl device-access revoke <device> [-ix ix_id] | trustixctl device-access revoke -fingerprint sha256")
		}
		request := struct {
			Device      string `json:"device,omitempty"`
			IX          string `json:"ix,omitempty"`
			Fingerprint string `json:"fingerprint,omitempty"`
		}{
			Device:      strings.TrimSpace(device),
			IX:          strings.TrimSpace(ix),
			Fingerprint: strings.TrimSpace(fingerprint),
		}
		if request.Device == "" && request.Fingerprint == "" {
			return true, fmt.Errorf("usage: trustixctl device-access revoke <device> [-ix ix_id] | trustixctl device-access revoke -fingerprint sha256")
		}
		if request.Fingerprint != "" {
			normalized, err := pki.NormalizeCertificateFingerprintSHA256(request.Fingerprint)
			if err != nil {
				return true, err
			}
			request.Fingerprint = normalized
		}
		body, err := json.Marshal(request)
		if err != nil {
			return true, err
		}
		return true, client.postAndPrint("/v1/device-access/revoke", body, "application/json")
	default:
		return false, nil
	}
}

func handleRouteCommand(client apiClient, args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "probe":
		return handleRouteProbeCommand(client, args[1:])
	case "trace":
		return handleTraceCommand(client, args[1:])
	default:
		return false, nil
	}
}

func handleRouteProbeCommand(client apiClient, args []string) (bool, error) {
	query, err := parseRouteDiagnosticArgs(args, false)
	if err != nil {
		return true, fmt.Errorf("usage: trustixctl route probe <dst> [-src ip] [-proto n] [-sport n] [-dport n]")
	}
	return true, client.getAndPrintPath("/v1/route/probe", query)
}

func handleTraceCommand(client apiClient, args []string) (bool, error) {
	query, err := parseRouteDiagnosticArgs(args, true)
	if err != nil {
		return true, fmt.Errorf("usage: trustixctl trace <dst> [-max-hops n] [-src ip] [-proto n] [-sport n] [-dport n]")
	}
	return true, client.getAndPrintPath("/v1/route/trace", query)
}

func parseRouteDiagnosticArgs(args []string, allowMaxHops bool) (url.Values, error) {
	query := url.Values{}
	dst := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.TrimSpace(arg) == "" {
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			if dst != "" {
				return nil, fmt.Errorf("too many destinations")
			}
			dst = arg
			continue
		}
		name := strings.TrimLeft(arg, "-")
		value := ""
		if parts := strings.SplitN(name, "=", 2); len(parts) == 2 {
			name, value = parts[0], parts[1]
		} else {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing value for -%s", name)
			}
			i++
			value = args[i]
		}
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("empty value for -%s", name)
		}
		switch name {
		case "src":
			query.Set("src", value)
		case "proto":
			if _, err := strconv.ParseUint(value, 10, 8); err != nil {
				return nil, fmt.Errorf("invalid proto %q", value)
			}
			query.Set("proto", value)
		case "sport":
			if _, err := strconv.ParseUint(value, 10, 16); err != nil {
				return nil, fmt.Errorf("invalid sport %q", value)
			}
			query.Set("sport", value)
		case "dport":
			if _, err := strconv.ParseUint(value, 10, 16); err != nil {
				return nil, fmt.Errorf("invalid dport %q", value)
			}
			query.Set("dport", value)
		case "max-hops", "max_hops":
			if !allowMaxHops {
				return nil, fmt.Errorf("unsupported flag -%s", name)
			}
			if _, err := strconv.ParseUint(value, 10, 16); err != nil {
				return nil, fmt.Errorf("invalid max-hops %q", value)
			}
			query.Set("max_hops", value)
		default:
			return nil, fmt.Errorf("unsupported flag -%s", name)
		}
	}
	if dst == "" {
		return nil, fmt.Errorf("destination is required")
	}
	query.Set("dst", dst)
	return query, nil
}

func fingerprintFromPathOrValue(raw string) (string, error) {
	if _, err := os.Stat(raw); err == nil {
		cert, _, err := pki.LoadCertificate(raw)
		if err != nil {
			return "", err
		}
		return pki.CertificateFingerprintSHA256(cert), nil
	}
	return pki.NormalizeCertificateFingerprintSHA256(raw)
}

func parsePositiveUint(raw string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("value must be greater than zero")
	}
	return value, nil
}

func resolveCommand(args []string) string {
	if len(args) >= 2 {
		twoPart := args[0] + " " + args[1]
		if _, ok := commandPaths[twoPart]; ok {
			return twoPart
		}
	}
	return args[0]
}

func (client apiClient) getAndPrint(path string) error {
	return client.getAndPrintPath(path, nil)
}

func (client apiClient) getAndPrintPath(path string, query url.Values) error {
	path = client.managementPath(path)
	requestURL, err := buildURL(client.baseURL, path, query)
	if err != nil {
		return err
	}
	httpClient, err := client.httpClient(5 * time.Second)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("GET %s: %w", requestURL, err)
	}
	if err := client.signRequest(req, nil); err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", requestURL, err)
	}
	defer resp.Body.Close()
	return printResponse("GET", requestURL, resp)
}

func (client apiClient) postConfigFileAndPrint(path, configPath string) error {
	payload, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config %q: %w", configPath, err)
	}
	format := "yaml"
	contentType := "application/x-yaml"
	if strings.EqualFold(filepath.Ext(configPath), ".json") {
		format = "json"
		contentType = "application/json"
	}
	requestPath := path + "?format=" + url.QueryEscape(format)
	return client.postAndPrint(requestPath, payload, contentType)
}

func (client apiClient) postFileAndPrint(path, filePath, contentType string) error {
	payload, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file %q: %w", filePath, err)
	}
	return client.postAndPrint(path, payload, contentType)
}

func (client apiClient) postAndPrint(path string, body []byte, contentType string) error {
	path = client.managementPath(path)
	requestURL, err := buildURL(client.baseURL, path, nil)
	if err != nil {
		return err
	}
	httpClient, err := client.httpClient(15 * time.Second)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST %s: %w", requestURL, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if err := client.signRequest(req, body); err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", requestURL, err)
	}
	defer resp.Body.Close()
	return printResponse("POST", requestURL, resp)
}

func (client apiClient) postAndSave(path string, body []byte, contentType, outPath string) error {
	path = client.managementPath(path)
	requestURL, err := buildURL(client.baseURL, path, nil)
	if err != nil {
		return err
	}
	httpClient, err := client.httpClient(60 * time.Second)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST %s: %w", requestURL, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if err := client.signRequest(req, body); err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", requestURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("POST %s returned %s; read error body: %w", requestURL, resp.Status, readErr)
		}
		return fmt.Errorf("POST %s returned %s: %s", requestURL, resp.Status, strings.TrimSpace(string(responseBody)))
	}
	if outPath == "" {
		outPath = contentDispositionFilename(resp.Header.Get("Content-Disposition"))
		if outPath == "" {
			outPath = "trustix-config-export.tar.gz"
		}
	}
	if outPath == "-" {
		_, err := io.Copy(os.Stdout, resp.Body)
		return err
	}
	outPath = filepath.Clean(outPath)
	dir := filepath.Dir(outPath)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(outPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp output in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmp, hasher), resp.Body)
	closeErr := tmp.Close()
	if copyErr != nil {
		return fmt.Errorf("write archive %q: %w", outPath, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close temp archive %q: %w", tmpName, closeErr)
	}
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("output file %q already exists", outPath)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat output file %q: %w", outPath, err)
	}
	if err := os.Rename(tmpName, outPath); err != nil {
		return fmt.Errorf("save archive %q: %w", outPath, err)
	}
	result := struct {
		Saved  string `json:"saved"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	}{
		Saved:  outPath,
		Bytes:  written,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
	}
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("format save result: %w", err)
	}
	fmt.Println(string(payload))
	return nil
}

func (client apiClient) deleteAndPrint(path string) error {
	path = client.managementPath(path)
	requestURL, err := buildURL(client.baseURL, path, nil)
	if err != nil {
		return err
	}
	httpClient, err := client.httpClient(15 * time.Second)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodDelete, requestURL, nil)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", requestURL, err)
	}
	if err := client.signRequest(req, nil); err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", requestURL, err)
	}
	defer resp.Body.Close()
	return printResponse("DELETE", requestURL, resp)
}

func (client apiClient) managementPath(path string) string {
	if client.targetIX == "" {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "/v1/management/ix/" + url.PathEscape(client.targetIX) + path
}

func (client apiClient) httpClient(timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig, err := client.tlsConfig()
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

func (client apiClient) tlsConfig() (*tls.Config, error) {
	if len(client.apiTLSCAPaths) == 0 && client.apiTLSServerName == "" && !client.apiTLSInsecureSkipVerify {
		return nil, nil
	}
	conf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         client.apiTLSServerName,
		InsecureSkipVerify: client.apiTLSInsecureSkipVerify,
	}
	if len(client.apiTLSCAPaths) == 0 {
		return conf, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	for _, path := range client.apiTLSCAPaths {
		cert, _, err := pki.LoadCertificate(path)
		if err != nil {
			return nil, fmt.Errorf("load API TLS CA %q: %w", path, err)
		}
		roots.AddCert(cert)
	}
	conf.RootCAs = roots
	return conf, nil
}

func (client apiClient) signRequest(req *http.Request, body []byte) error {
	if len(client.adminCertPaths) == 0 && len(client.adminKeyPaths) == 0 {
		return nil
	}
	if len(client.adminCertPaths) == 0 || len(client.adminKeyPaths) == 0 || len(client.adminCertPaths) != len(client.adminKeyPaths) {
		return fmt.Errorf("matching -admin-cert and -admin-key values are required for signed management API requests")
	}
	for i := range client.adminCertPaths {
		bundle, err := pki.LoadBundle(client.adminCertPaths[i], client.adminKeyPaths[i])
		if err != nil {
			return err
		}
		timestamp := time.Now().UTC().Format(time.RFC3339Nano)
		signingBytes := adminauth.SigningBytes(req.Method, req.URL.RequestURI(), timestamp, body)
		signature, err := pki.Sign(bundle.Key, signingBytes)
		if err != nil {
			return err
		}
		req.Header.Add(adminauth.HeaderCert, base64.StdEncoding.EncodeToString(bundle.Cert.Raw))
		req.Header.Add(adminauth.HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		req.Header.Add(adminauth.HeaderTimestamp, timestamp)
	}
	return nil
}

func contentDispositionFilename(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(header)
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(params["filename"])
	if name == "" {
		name = strings.TrimSpace(params["filename*"])
	}
	if name == "" || strings.ContainsAny(name, `/\`) {
		return ""
	}
	return name
}

func buildURL(apiBase, path string, query url.Values) (string, error) {
	base, err := url.Parse(apiBase)
	if err != nil {
		return "", fmt.Errorf("parse api url: %w", err)
	}
	relative, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("parse api path: %w", err)
	}
	requestURL := base.ResolveReference(relative)
	if query != nil {
		values := requestURL.Query()
		for key, list := range query {
			for _, value := range list {
				values.Add(key, value)
			}
		}
		requestURL.RawQuery = values.Encode()
	}
	return requestURL.String(), nil
}

func printResponse(method, requestURL string, resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s returned %s: %s", method, requestURL, resp.Status, strings.TrimSpace(string(body)))
	}

	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		fmt.Print(string(body))
		return nil
	}
	encoded, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return fmt.Errorf("format response: %w", err)
	}
	fmt.Println(string(encoded))
	return nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: trustixctl [-api http://127.0.0.1:8787] [-api-tls-ca root.pem] [-api-tls-server-name name] [-api-tls-insecure-skip-verify] [-target-ix ix-b] [-admin-cert certs/admin-1.crt -admin-key certs/admin-1.key ...] <version|status|peers|members|members delete <ix_id>|routes|route probe <dst> [-src ip] [-proto n] [-sport n] [-dport n]|trace <dst> [-max-hops n] [-src ip] [-proto n] [-sport n] [-dport n]|route-policy|flows|links|device-access [list]|device-access show <device|peer|address|fingerprint>|device-access revoke <device> [-ix ix_id]|device-access revoke -fingerprint sha256|endpoints|trust show|trust policy|trust admins|trust apply-policy <json-file>|trust roots [add <cert>|remove <fingerprint_or_cert>]|trust revoke <cert_or_fingerprint>|trust unrevoke <fingerprint>|admissions [list]|admissions pending [ix_id]|admissions show <ix_id>|admissions approve -ix <ix_id> -ix-cert <cert_or_fingerprint> [-prefix cidr ...] [-route-auth cert_or_fingerprint ...] [-control-api url] [-effective-at rfc3339]|admissions approve-pending <ix_id> [-prefix cidr ...] [-route-auth cert_or_fingerprint ...] [-control-api url] [-effective-at rfc3339]|admissions revoke <ix_id>|config desired|config peers|config head|config log [from [to]]|config event <seq>|config snapshot|config export [-out file]|config backup -include-private-keys [-out file]|config restore <archive.tar.gz>|config validate <file>|config apply <file>|config rollback [seq]|config rejoin <control_api> [ix_id]|capture [-limit n] [-hook hook] [-peer ix_id] [-src ip] [-dst ip]|stats|datapath|transports|bpf maps|doctor>")
}
