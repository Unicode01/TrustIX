package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	runtimeProfileDirEnv    = "TRUSTIX_RUNTIME_PROFILE_DIR"
	mutexProfileFractionEnv = "TRUSTIX_MUTEX_PROFILE_FRACTION"
	blockProfileRateEnv     = "TRUSTIX_BLOCK_PROFILE_RATE"
)

func startProfilesFromEnv() func() {
	stopCPU := startCPUProfileFromEnv()
	stopRuntime := startRuntimeProfilesFromEnv()
	var once sync.Once
	return func() {
		once.Do(func() {
			stopCPU()
			stopRuntime()
		})
	}
}

func startCPUProfileFromEnv() func() {
	dir := strings.TrimSpace(os.Getenv("TRUSTIX_CPU_PROFILE_DIR"))
	if dir == "" {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "trustixd: create cpu profile dir %q: %v\n", dir, err)
		return func() {}
	}
	path, file, err := createProfileFile(dir, "cpu")
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustixd: create cpu profile: %v\n", err)
		return func() {}
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close cpu profile %q: %w", path, closeErr))
		}
		fmt.Fprintf(os.Stderr, "trustixd: start cpu profile %q: %v\n", path, err)
		return func() {}
	}
	fmt.Fprintf(os.Stderr, "trustixd cpu profile: %s\n", path)
	return func() {
		pprof.StopCPUProfile()
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "trustixd: close cpu profile %q: %v\n", path, err)
		}
	}
}

func startRuntimeProfilesFromEnv() func() {
	dir := strings.TrimSpace(os.Getenv(runtimeProfileDirEnv))
	if dir == "" {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "trustixd: create runtime profile dir %q: %v\n", dir, err)
		return func() {}
	}

	mutexFraction := profileRateFromEnv(mutexProfileFractionEnv)
	blockRate := profileRateFromEnv(blockProfileRateEnv)
	previousMutexFraction := 0
	if mutexFraction > 0 {
		previousMutexFraction = runtime.SetMutexProfileFraction(mutexFraction)
	}
	if blockRate > 0 {
		runtime.SetBlockProfileRate(blockRate)
	}

	return func() {
		if mutexFraction > 0 {
			runtime.SetMutexProfileFraction(previousMutexFraction)
		}
		if blockRate > 0 {
			runtime.SetBlockProfileRate(0)
		}
		runtime.GC()
		writeRuntimeProfile(dir, "heap")
		if mutexFraction > 0 {
			writeRuntimeProfile(dir, "mutex")
		}
		if blockRate > 0 {
			writeRuntimeProfile(dir, "block")
		}
	}
}

func profileRateFromEnv(name string) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		fmt.Fprintf(os.Stderr, "trustixd: ignore invalid %s=%q; expected a positive integer\n", name, raw)
		return 0
	}
	return value
}

func writeRuntimeProfile(dir, name string) {
	profile := pprof.Lookup(name)
	if profile == nil {
		fmt.Fprintf(os.Stderr, "trustixd: runtime profile %q is unavailable\n", name)
		return
	}
	path, file, err := createProfileFile(dir, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustixd: create %s profile: %v\n", name, err)
		return
	}
	writeErr := profile.WriteTo(file, 0)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		fmt.Fprintf(os.Stderr, "trustixd: write %s profile %q: %v\n", name, path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "trustixd %s profile: %s\n", name, path)
}

func createProfileFile(dir, component string) (string, *os.File, error) {
	name := fmt.Sprintf(
		"trustixd-%d-%s-%s.pprof",
		os.Getpid(),
		time.Now().UTC().Format("20060102T150405.000000000Z"),
		component,
	)
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, fmt.Errorf("create profile %q: %w", path, err)
	}
	return path, file, nil
}
