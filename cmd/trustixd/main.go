package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"syscall"
	"time"

	"trustix.local/trustix/internal/buildassets"
	"trustix.local/trustix/internal/buildinfo"
	"trustix.local/trustix/internal/daemon"
)

func main() {
	cfg := daemon.DefaultConfig()

	flag.StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "path to desired configuration")
	flag.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "directory for TrustIX runtime state")
	flag.StringVar(&cfg.APIAddr, "api", cfg.APIAddr, "local management API listen address")
	flag.StringVar(&cfg.PeerAPIAddr, "peer-api", cfg.PeerAPIAddr, "mTLS peer control-plane API listen address")
	flag.StringVar(&cfg.DataplaneMode, "dataplane", cfg.DataplaneMode, "dataplane mode: noop, linux, or auto")
	flag.BoolVar(&cfg.APIAdminAuth, "api-admin-auth", cfg.APIAdminAuth, "require Admin certificate signatures for management API write requests")
	showVersion := flag.Bool("version", false, "print build version and embedded asset metadata")
	checkConfig := flag.Bool("check-config", false, "validate configuration and runtime inputs without starting")
	cleanupDataplane := flag.Bool("cleanup-dataplane", false, "clean TrustIX-managed dataplane state from config/data-dir and exit")
	cleanupDataplaneDryRun := flag.Bool("cleanup-dataplane-dry-run", false, "print TrustIX-managed dataplane cleanup plan as JSON and exit")
	repairDataplane := flag.Bool("repair-dataplane", false, "clean stale TrustIX-managed dataplane state before starting")
	flag.Parse()
	if *showVersion {
		buildinfo.WriteText(os.Stdout, buildassets.BuildInfo())
		return
	}
	if *checkConfig {
		if *cleanupDataplane || *cleanupDataplaneDryRun || *repairDataplane {
			fmt.Fprintln(os.Stderr, "trustixd: -check-config cannot be combined with dataplane cleanup or repair")
			os.Exit(2)
		}
		checked, err := daemon.CheckConfig(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trustixd: config check failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("trustixd config valid: config=%q domain=%q ix=%q dataplane=%q api=%q peer-api=%q\n",
			checked.ConfigPath,
			checked.DomainID,
			checked.IXID,
			checked.DataplaneMode,
			checked.APIAddr,
			checked.PeerAPIAddr,
		)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *cleanupDataplaneDryRun {
		plan, err := daemon.PlanCleanupDataplane(ctx, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trustixd: %v\n", err)
			os.Exit(1)
		}
		if err := daemon.WriteCleanupPlanJSON(os.Stdout, plan); err != nil {
			fmt.Fprintf(os.Stderr, "trustixd: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *cleanupDataplane || *repairDataplane {
		fmt.Fprintf(os.Stderr, "trustixd cleanup dataplane: config=%q data-dir=%q dataplane=%q\n", cfg.ConfigPath, cfg.DataDir, cfg.DataplaneMode)
		if err := daemon.CleanupDataplane(ctx, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "trustixd: %v\n", err)
			os.Exit(1)
		}
		if *cleanupDataplane {
			return
		}
	}

	stopCPUProfile := startCPUProfileFromEnv()
	defer stopCPUProfile()

	d, err := daemon.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustixd: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "trustixd starting: config=%q data-dir=%q api=%q peer-api=%q dataplane=%q\n", cfg.ConfigPath, cfg.DataDir, cfg.APIAddr, cfg.PeerAPIAddr, cfg.DataplaneMode)
	if err := d.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		fmt.Fprintf(os.Stderr, "trustixd: %v\n", err)
		os.Exit(1)
	}
}

func startCPUProfileFromEnv() func() {
	dir := os.Getenv("TRUSTIX_CPU_PROFILE_DIR")
	if dir == "" {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "trustixd: create cpu profile dir %q: %v\n", dir, err)
		return func() {}
	}
	name := fmt.Sprintf("trustixd-%d-%s.pprof", os.Getpid(), time.Now().UTC().Format("20060102T150405Z"))
	path := filepath.Join(dir, name)
	file, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustixd: create cpu profile %q: %v\n", path, err)
		return func() {}
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		fmt.Fprintf(os.Stderr, "trustixd: start cpu profile %q: %v\n", path, err)
		return func() {}
	}
	fmt.Fprintf(os.Stderr, "trustixd cpu profile: %s\n", path)
	return func() {
		pprof.StopCPUProfile()
		_ = file.Close()
	}
}
