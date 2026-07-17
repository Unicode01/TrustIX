//go:build linux

package kernelmodule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/config"
)

const (
	moduleBuildSHAParam = "build_sha256"

	reloadOnUpgradeAuto   = "auto"
	reloadOnUpgradeNever  = "never"
	reloadOnUpgradeAlways = "always"
)

func (manager *Manager) ensureLocked(ctx context.Context, module config.KernelModuleConfig) (Status, error) {
	if err := ctx.Err(); err != nil {
		return manager.status, err
	}
	mode := normalizeMode(module.Mode)
	status := manager.inspectLocked(module, mode)
	source := manager.resolveModuleSource(module)
	switch mode {
	case ModeDisabled:
		if status.Loaded && manager.loadedByUs {
			if err := manager.unloadLocked(ctx, module, mode, "module disabled by desired config"); err != nil {
				status = manager.inspectLocked(module, mode)
				status.Managed = true
				status.State = "error"
				status.Reason = err.Error()
				manager.status = status
				return status, nil
			}
			status = manager.inspectLocked(module, mode)
			status.State = "unloaded"
			status.Reason = "module unloaded after desired config disabled lifecycle"
			manager.status = status
			return status, nil
		}
		status.State = ModeDisabled
		status.Reason = "module lifecycle is disabled"
		manager.status = status
		return status, nil
	case ModeAuto, ModeRequired:
		if status.Loaded {
			reloaded, upgradeState, upgradeReason, reloadErr := manager.reloadLoadedModuleForUpgradeLocked(ctx, module, source, status)
			if reloadErr != nil {
				status = manager.inspectLocked(module, mode)
				status.Managed = manager.loadedByUs
				status.State = "error"
				status.UpgradeState = upgradeState
				status.Reason = appendStatusReason(upgradeReason, reloadErr.Error())
				manager.status = status
				if mode == ModeRequired {
					return status, fmt.Errorf("%s is required but could not be upgraded: %w", manager.name, reloadErr)
				}
				return status, nil
			}
			if !reloaded {
				parameterReloaded, parameterState, parameterReason, parameterErr := manager.reloadLoadedModuleForParameterChangeLocked(ctx, module, source, status)
				if parameterErr != nil {
					status = manager.inspectLocked(module, mode)
					status.Managed = manager.loadedByUs
					status.State = "error"
					status.UpgradeState = parameterState
					status.Reason = appendStatusReason(parameterReason, parameterErr.Error())
					manager.status = status
					if mode == ModeRequired {
						return status, fmt.Errorf("%s is required but could not be reloaded with desired parameters: %w", manager.name, parameterErr)
					}
					return status, nil
				}
				if parameterReloaded {
					reloaded = true
					upgradeState = parameterState
					upgradeReason = appendStatusReason(upgradeReason, parameterReason)
				} else if parameterState != "" {
					upgradeState = parameterState
					upgradeReason = appendStatusReason(upgradeReason, parameterReason)
				}
			}
			parameterNotes := applyLoadedModuleParameters(manager.name, module.Parameters)
			status = manager.inspectLocked(module, mode)
			if manager.loadedByUs {
				status.Managed = true
				status.State = "loaded_by_trustix"
				if status.Reason == "" {
					status.Reason = "module was loaded by this trustixd process"
				}
			} else {
				status.State = "loaded"
				if status.Reason == "" {
					status.Reason = "module is already loaded"
				}
			}
			if len(parameterNotes) > 0 {
				status.Reason = strings.TrimSpace(status.Reason + "; " + strings.Join(parameterNotes, "; "))
			}
			if reloaded {
				status.UpgradeState = "reloaded"
				status.Reason = appendStatusReason(status.Reason, upgradeReason)
			} else if upgradeState != "" {
				status.UpgradeState = upgradeState
				status.Reason = appendStatusReason(status.Reason, upgradeReason)
			}
			manager.status = status
			return status, nil
		}
		if source.unavailable() {
			status.State = "unavailable"
			status.Reason = source.err.Error()
			manager.status = status
			if mode == ModeRequired {
				return status, fmt.Errorf("%s is required but not loaded: %s", manager.name, status.Reason)
			}
			return status, nil
		}
		status.Path = source.label
		status.SHA256 = moduleSourceSHA256(source)
		if err := loadModuleSource(source, module.Parameters); err != nil {
			status = manager.inspectLocked(module, mode)
			status.State = "error"
			status.Path = source.label
			status.Reason = fmt.Sprintf("load module %q: %v", source.label, err)
			manager.status = status
			if mode == ModeRequired {
				return status, fmt.Errorf("%s is required but could not be loaded: %w", manager.name, err)
			}
			return status, nil
		}
		manager.loadedByUs = true
		status = manager.inspectLocked(module, mode)
		status.Managed = true
		status.State = "loaded_by_trustix"
		loadedAt := time.Now().UTC()
		status.LoadedAt = &loadedAt
		status.UpgradeState = "loaded"
		status.Reason = "module loaded by trustixd"
		manager.status = status
		return status, nil
	default:
		status.State = "error"
		status.Reason = "unsupported module mode"
		manager.status = status
		return status, fmt.Errorf("%s mode %q is unsupported", manager.name, module.Mode)
	}
}

func (manager *Manager) closeLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status := manager.status
	if status.Name == "" {
		status = manager.inspectLocked(config.KernelModuleConfig{}, ModeDisabled)
	}
	if !manager.loadedByUs || !status.UnloadOnExit {
		return nil
	}
	if !status.Loaded {
		manager.loadedByUs = false
		return nil
	}
	module := config.KernelModuleConfig{
		Mode:            status.Mode,
		Path:            status.Path,
		Parameters:      status.Parameters,
		ReloadOnUpgrade: status.ReloadOnUpgrade,
		UnloadOnExit:    status.UnloadOnExit,
	}
	if err := manager.unloadLocked(ctx, module, status.Mode, "module unloaded by trustixd"); err != nil {
		manager.status = manager.inspectLocked(module, status.Mode)
		manager.status.Managed = true
		manager.status.State = "error"
		manager.status.Reason = err.Error()
		return err
	}
	manager.status = manager.inspectLocked(module, status.Mode)
	manager.status.State = "unloaded"
	manager.status.Reason = "module unloaded by trustixd"
	return nil
}

func (manager *Manager) unloadLocked(ctx context.Context, module config.KernelModuleConfig, mode string, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.DeleteModule(manager.name, unix.O_NONBLOCK); err != nil {
		return fmt.Errorf("unload %s: %w", manager.name, err)
	}
	manager.loadedByUs = false
	manager.status = manager.inspectLocked(module, mode)
	manager.status.State = "unloaded"
	manager.status.Reason = reason
	return nil
}

func (manager *Manager) inspectLocked(module config.KernelModuleConfig, mode string) Status {
	source := manager.resolveModuleSource(module)
	status := Status{
		Name:            manager.name,
		Mode:            mode,
		Path:            source.label,
		Parameters:      module.Parameters,
		ReloadOnUpgrade: effectiveReloadOnUpgrade(module.ReloadOnUpgrade),
		Managed:         manager.loadedByUs,
		UnloadOnExit:    module.UnloadOnExit,
	}
	status.SHA256 = moduleSourceSHA256(source)
	loaded, refCount, usedBy := procModuleStatus(manager.name)
	status.Loaded = loaded
	status.RefCount = refCount
	status.UsedBy = usedBy
	if loadedSHA, ok := readModuleParamString(manager.name, moduleBuildSHAParam); ok {
		status.LoadedSHA256 = loadedSHA
	}
	status.InitState = readTrimmed(filepath.Join("/sys/module", manager.name, "initstate"))
	status.Version = readTrimmed(filepath.Join("/sys/module", manager.name, "version"))
	status.ABIVersion = inspectModuleABIVersion(manager.name, loaded)
	var moduleBTFMissing bool
	status.Features, moduleBTFMissing = inspectTrustIXCryptoFeatures(manager.name, loaded)
	status = completeCapabilityStatus(status)
	status.UpgradeState = loadedModuleUpgradeState(source, status)
	if moduleBTFMissing {
		status.Reason = appendStatusReason(status.Reason, "module BTF is unavailable; kfunc capabilities are disabled")
	}
	switch {
	case mode == ModeDisabled:
		status.State = ModeDisabled
	case loaded && manager.loadedByUs:
		status.State = "loaded_by_trustix"
	case loaded:
		status.State = "loaded"
	default:
		status.State = "unavailable"
	}
	return status
}

func (manager *Manager) reloadLoadedModuleForUpgradeLocked(ctx context.Context, module config.KernelModuleConfig, source moduleSource, status Status) (bool, string, string, error) {
	if err := ctx.Err(); err != nil {
		return false, status.UpgradeState, "", err
	}
	policy := effectiveReloadOnUpgrade(module.ReloadOnUpgrade)
	upgradeState := loadedModuleUpgradeState(source, status)
	upgradeReason := loadedModuleUpgradeReason(source, status, upgradeState)
	switch policy {
	case reloadOnUpgradeNever:
		return false, upgradeState, upgradeReason, nil
	}
	if source.unavailable() || moduleSourceSHA256(source) == "" {
		return false, upgradeState, upgradeReason, nil
	}
	if policy != reloadOnUpgradeAlways && !moduleSourceSupportsBuildSHA(source) {
		return false, upgradeState, upgradeReason, nil
	}
	shouldReload := policy == reloadOnUpgradeAlways || upgradeState == "missing_loaded_fingerprint" || upgradeState == "mismatch"
	if !shouldReload {
		return false, upgradeState, upgradeReason, nil
	}
	if status.RefCount > 0 {
		return false, upgradeState, upgradeReason, fmt.Errorf("loaded module ref_count=%d; refusing automatic upgrade reload while it is in use", status.RefCount)
	}
	if err := unix.DeleteModule(manager.name, unix.O_NONBLOCK); err != nil {
		return false, upgradeState, upgradeReason, fmt.Errorf("unload old module: %w", err)
	}
	manager.loadedByUs = false
	if err := loadModuleSource(source, module.Parameters); err != nil {
		return false, "reload_failed", upgradeReason, fmt.Errorf("load upgraded module %q: %w", source.label, err)
	}
	manager.loadedByUs = true
	return true, "reloaded", upgradeReason, nil
}

func (manager *Manager) reloadLoadedModuleForParameterChangeLocked(ctx context.Context, module config.KernelModuleConfig, source moduleSource, status Status) (bool, string, string, error) {
	if err := ctx.Err(); err != nil {
		return false, "", "", err
	}
	parameters := loadParametersWithBuildSHA(source, module.Parameters)
	mismatches := loadedModuleLoadTimeParameterMismatches(manager.name, source, parameters)
	if len(mismatches) == 0 {
		return false, "", "", nil
	}
	reason := "loaded module has different load-time parameters: " + strings.Join(mismatches, ", ")
	if source.unavailable() || moduleSourceSHA256(source) == "" {
		return false, "parameter_mismatch", reason, nil
	}
	if status.RefCount > 0 {
		return false, "parameter_mismatch", reason, fmt.Errorf("loaded module ref_count=%d; refusing parameter reload while it is in use", status.RefCount)
	}
	if err := unix.DeleteModule(manager.name, unix.O_NONBLOCK); err != nil {
		return false, "parameter_reload_failed", reason, fmt.Errorf("unload old module: %w", err)
	}
	manager.loadedByUs = false
	if err := loadModuleSource(source, module.Parameters); err != nil {
		return false, "parameter_reload_failed", reason, fmt.Errorf("load module %q with desired parameters: %w", source.label, err)
	}
	manager.loadedByUs = true
	return true, "reloaded_parameters", reason, nil
}

func effectiveReloadOnUpgrade(raw string) string {
	switch config.NormalizeKernelModuleReloadOnUpgrade(raw) {
	case reloadOnUpgradeNever:
		return reloadOnUpgradeNever
	case reloadOnUpgradeAlways:
		return reloadOnUpgradeAlways
	default:
		return reloadOnUpgradeAuto
	}
}

func loadedModuleUpgradeState(source moduleSource, status Status) string {
	if !status.Loaded {
		return "not_loaded"
	}
	sourceSHA := moduleSourceSHA256(source)
	if source.unavailable() || sourceSHA == "" {
		return "unknown_target_fingerprint"
	}
	if !moduleSourceSupportsBuildSHA(source) {
		return "target_fingerprint_unsupported"
	}
	if status.LoadedSHA256 == "" {
		return "missing_loaded_fingerprint"
	}
	if status.LoadedSHA256 != sourceSHA {
		return "mismatch"
	}
	return "current"
}

func loadedModuleUpgradeReason(source moduleSource, status Status, state string) string {
	switch state {
	case "current":
		return "loaded module fingerprint matches target module"
	case "not_loaded":
		return "module is not loaded"
	case "unknown_target_fingerprint":
		if source.err != nil {
			return source.err.Error()
		}
		return "target module fingerprint is unavailable"
	case "target_fingerprint_unsupported":
		return "target module does not expose build_sha256; upgrade matching is disabled for this module payload"
	case "missing_loaded_fingerprint":
		return "loaded module does not expose build_sha256; treating it as an upgrade candidate"
	case "mismatch":
		return "loaded module fingerprint differs from target module"
	default:
		return ""
	}
}

const (
	trustIXKernelFeatureCryptoAEADBit    = 1 << 0
	trustIXKernelFeatureDeviceAEADBit    = 1 << 1
	trustIXKernelFeatureKfuncTCBit       = 1 << 2
	trustIXKernelFeatureKfuncXDPBit      = 1 << 3
	trustIXKernelFeatureDirectAESNIBit   = 1 << 4
	trustIXKernelFeatureDirectVAESBit    = 1 << 5
	trustIXKernelFeatureGSOSKBBit        = 1 << 6
	trustIXKernelFeatureFullDatapathBit  = 1 << 7
	trustIXKernelFeatureRouteTCPKfuncBit = 1 << 8
	trustIXKernelFeatureRouteTCPXmitBit  = 1 << 9
)

func inspectModuleABIVersion(name string, loaded bool) int {
	if !loaded {
		return 0
	}
	if value, ok := readModuleParamUint64(name, "abi_version"); ok {
		return int(value)
	}
	return 0
}

func inspectTrustIXCryptoFeatures(name string, loaded bool) ([]string, bool) {
	if !loaded {
		return nil, false
	}
	switch name {
	case "trustix_datapath":
		if query, err := ProbeDatapath(TrustIXDatapathDevicePath); err == nil {
			return query.Features, false
		}
	case "trustix_datapath_helpers":
		if query, err := ProbeDatapath(TrustIXDatapathHelpersDevicePath); err == nil {
			return query.Features, false
		}
	}
	if value, ok := readModuleParamUint64(name, "features"); ok {
		return filterModuleFeaturesByRuntimeBTF(name, moduleFeatureMaskToNames(value))
	}
	return nil, false
}

var moduleBTFAvailable = defaultModuleBTFAvailable

func defaultModuleBTFAvailable(name string) bool {
	info, err := os.Stat(filepath.Join("/sys/kernel/btf", name))
	return err == nil && !info.IsDir()
}

func filterModuleFeaturesByRuntimeBTF(name string, features []string) ([]string, bool) {
	if len(features) == 0 {
		return features, false
	}
	if moduleBTFAvailable(name) {
		return features, false
	}
	switch name {
	case "trustix_datapath_helpers":
		if featureListHasAny(features, FeatureGSOSKB, FeatureRouteTCPKfunc, FeatureRouteTCPXmit) {
			return nil, true
		}
	case "trustix_crypto":
		filtered := removeFeatureNames(features, FeatureKfuncTC, FeatureKfuncXDP)
		if len(filtered) != len(features) {
			return filtered, true
		}
	}
	return features, false
}

func featureListHasAny(features []string, candidates ...string) bool {
	for _, feature := range features {
		for _, candidate := range candidates {
			if feature == candidate {
				return true
			}
		}
	}
	return false
}

func removeFeatureNames(features []string, remove ...string) []string {
	if len(features) == 0 || len(remove) == 0 {
		return features
	}
	removeSet := make(map[string]struct{}, len(remove))
	for _, feature := range remove {
		removeSet[feature] = struct{}{}
	}
	out := make([]string, 0, len(features))
	for _, feature := range features {
		if _, blocked := removeSet[feature]; blocked {
			continue
		}
		out = append(out, feature)
	}
	return normalizeCapabilityFeatures(out)
}

func appendStatusReason(current, note string) string {
	current = strings.TrimSpace(current)
	note = strings.TrimSpace(note)
	if current == "" {
		return note
	}
	if note == "" || strings.Contains(current, note) {
		return current
	}
	return current + "; " + note
}

func moduleFeatureMaskToNames(mask uint64) []string {
	var features []string
	if mask&trustIXKernelFeatureCryptoAEADBit != 0 {
		features = append(features, FeatureCryptoAEAD)
	}
	if mask&trustIXKernelFeatureDeviceAEADBit != 0 {
		features = append(features, FeatureDeviceAEAD)
	}
	if mask&trustIXKernelFeatureKfuncTCBit != 0 {
		features = append(features, FeatureKfuncTC)
	}
	if mask&trustIXKernelFeatureKfuncXDPBit != 0 {
		features = append(features, FeatureKfuncXDP)
	}
	if mask&trustIXKernelFeatureDirectAESNIBit != 0 {
		features = append(features, FeatureDirectAESNI)
	}
	if mask&trustIXKernelFeatureDirectVAESBit != 0 {
		features = append(features, FeatureDirectVAES)
	}
	if mask&trustIXKernelFeatureGSOSKBBit != 0 {
		features = append(features, FeatureGSOSKB)
	}
	if mask&trustIXKernelFeatureFullDatapathBit != 0 {
		features = append(features, FeatureFullDatapath)
	}
	if mask&trustIXKernelFeatureRouteTCPKfuncBit != 0 {
		features = append(features, FeatureRouteTCPKfunc)
	}
	if mask&trustIXKernelFeatureRouteTCPXmitBit != 0 {
		features = append(features, FeatureRouteTCPXmit)
	}
	return normalizeCapabilityFeatures(features)
}

type moduleSource struct {
	label   string
	path    string
	payload []byte
	sha256  string
	err     error
}

var embeddedModuleSHA256Cache sync.Map

func (source moduleSource) unavailable() bool {
	return source.err != nil || (source.path == "" && len(source.payload) == 0)
}

func (manager *Manager) resolveModuleSource(module config.KernelModuleConfig) moduleSource {
	path := strings.TrimSpace(module.Path)
	embedded := manager.embedded
	if embedded.name == "" {
		embedded = embeddedModuleForName(manager.name)
	}
	if path == "" || strings.EqualFold(path, "embedded") || strings.EqualFold(path, embedded.label) {
		var payload []byte
		if embedded.read != nil {
			payload = embedded.read()
		}
		if !looksLikeELF(payload) {
			return moduleSource{
				label: embedded.label,
				err:   fmt.Errorf("module is not loaded and no embedded %s ELF is present", embedded.name),
			}
		}
		return moduleSource{
			label:   embedded.label,
			payload: payload,
			sha256:  cachedEmbeddedModuleSHA256(embedded.label, payload),
		}
	}
	return moduleSource{label: path, path: path}
}

func loadModuleSource(source moduleSource, parameters string) error {
	parameters = loadParametersWithBuildSHA(source, parameters)
	if source.path != "" {
		return loadModuleFile(source.path, parameters)
	}
	if len(source.payload) == 0 {
		return fmt.Errorf("embedded module payload is empty")
	}
	return loadModuleBytes(source.payload, parameters)
}

func moduleSourceSHA256(source moduleSource) string {
	if source.sha256 != "" {
		return source.sha256
	}
	switch {
	case source.path != "":
		return fileSHA256(source.path)
	case len(source.payload) > 0:
		return bytesSHA256(source.payload)
	default:
		return ""
	}
}

func cachedEmbeddedModuleSHA256(label string, payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	if cached, ok := embeddedModuleSHA256Cache.Load(label); ok {
		if sha, ok := cached.(string); ok && sha != "" {
			return sha
		}
	}
	sha := bytesSHA256(payload)
	if sha != "" {
		embeddedModuleSHA256Cache.Store(label, sha)
	}
	return sha
}

func moduleSourceSupportsBuildSHA(source moduleSource) bool {
	payload, ok := moduleSourceBytes(source)
	if !ok {
		return false
	}
	return bytes.Contains(payload, []byte("parm="+moduleBuildSHAParam+":"))
}

func moduleSourceBytes(source moduleSource) ([]byte, bool) {
	switch {
	case len(source.payload) > 0:
		return source.payload, true
	case source.path != "":
		payload, err := os.ReadFile(source.path)
		if err != nil {
			return nil, false
		}
		return payload, true
	default:
		return nil, false
	}
}

func loadParametersWithBuildSHA(source moduleSource, parameters string) string {
	parameters = removeModuleParameter(parameters, moduleBuildSHAParam)
	sourceSHA := moduleSourceSHA256(source)
	if sourceSHA == "" || !moduleSourceSupportsBuildSHA(source) {
		return parameters
	}
	return setModuleParameter(parameters, moduleBuildSHAParam, sourceSHA)
}

func loadModuleFile(path, parameters string) (resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close kernel module %q: %w", path, err))
		}
	}()
	if err := unix.FinitModule(int(file.Fd()), parameters, 0); err == nil {
		return nil
	} else if errors.Is(err, unix.EEXIST) {
		return nil
	} else if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.ENOTSUP) {
		return err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return loadModuleBytes(payload, parameters)
}

func loadModuleBytes(payload []byte, parameters string) error {
	if err := unix.InitModule(payload, parameters); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func applyLoadedModuleParameters(name, parameters string) []string {
	var notes []string
	for key, value := range parseModuleParameters(parameters) {
		if key == moduleBuildSHAParam {
			continue
		}
		path := filepath.Join("/sys/module", name, "parameters", key)
		current, err := os.ReadFile(path)
		if err != nil {
			notes = append(notes, fmt.Sprintf("parameter %s is unavailable: %v", key, err))
			continue
		}
		desired := normalizeModuleParameterValue(value)
		if normalizeModuleParameterValue(string(current)) == desired {
			continue
		}
		if err := os.WriteFile(path, []byte(desired), 0); err != nil {
			if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
				notes = append(notes, fmt.Sprintf("parameter %s remains %q; requested %q but sysfs is read-only", key, strings.TrimSpace(string(current)), desired))
				continue
			}
			notes = append(notes, fmt.Sprintf("parameter %s remains %q; requested %q: %v", key, strings.TrimSpace(string(current)), desired, err))
			continue
		}
	}
	return notes
}

func loadedModuleLoadTimeParameterMismatches(name string, source moduleSource, parameters string) []string {
	parsed := parseModuleParameters(parameters)
	if len(parsed) == 0 {
		return nil
	}
	out := make([]string, 0)
	for key, value := range parsed {
		if key == moduleBuildSHAParam {
			continue
		}
		path := filepath.Join("/sys/module", name, "parameters", key)
		info, statErr := os.Stat(path)
		current, readErr := os.ReadFile(path)
		if statErr != nil || readErr != nil {
			if moduleSourceSupportsParameter(source, key) {
				out = append(out, key+" unavailable")
			}
			continue
		}
		if info.Mode().Perm()&0222 != 0 {
			continue
		}
		desired := normalizeModuleParameterValue(value)
		if normalizeModuleParameterValue(string(current)) != desired {
			out = append(out, fmt.Sprintf("%s=%q current=%q", key, desired, strings.TrimSpace(string(current))))
		}
	}
	return out
}

func moduleSourceSupportsParameter(source moduleSource, key string) bool {
	payload, ok := moduleSourceBytes(source)
	if !ok || strings.TrimSpace(key) == "" {
		return false
	}
	return bytes.Contains(payload, []byte("parm="+strings.TrimSpace(key)+":"))
}

func parseModuleParameters(parameters string) map[string]string {
	fields := strings.Fields(parameters)
	if len(fields) == 0 {
		return nil
	}
	parsed := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" {
			continue
		}
		parsed[key] = value
	}
	return parsed
}

func setModuleParameter(parameters, key, value string) string {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return strings.TrimSpace(parameters)
	}
	parameters = removeModuleParameter(parameters, key)
	if parameters == "" {
		return key + "=" + value
	}
	return parameters + " " + key + "=" + value
}

func removeModuleParameter(parameters, key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return strings.TrimSpace(parameters)
	}
	fields := strings.Fields(parameters)
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		existing, _, ok := strings.Cut(field, "=")
		if ok && strings.TrimSpace(existing) == key {
			continue
		}
		out = append(out, field)
	}
	return strings.Join(out, " ")
}

func normalizeModuleParameterValue(value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "1", "y", "yes", "true", "on", "enabled":
		return "Y"
	case "0", "n", "no", "false", "off", "disabled":
		return "N"
	default:
		return value
	}
}

func procModuleStatus(name string) (bool, int, []string) {
	payload, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false, 0, nil
	}
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != name {
			continue
		}
		refCount, _ := strconv.Atoi(fields[2])
		var usedBy []string
		if len(fields) >= 4 {
			rawUsedBy := strings.TrimSuffix(fields[3], ",")
			if rawUsedBy != "-" && rawUsedBy != "" {
				for _, part := range strings.Split(rawUsedBy, ",") {
					if part = strings.TrimSpace(part); part != "" {
						usedBy = append(usedBy, part)
					}
				}
			}
		}
		return true, refCount, usedBy
	}
	return false, 0, nil
}

func readTrimmed(path string) string {
	payload, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(payload))
}

func readModuleParamBool(name, param string) bool {
	value, ok := readModuleParamUint64(name, param)
	return ok && value != 0
}

func readModuleParamUint64(name, param string) (uint64, bool) {
	payload, err := os.ReadFile(filepath.Join("/sys/module", name, "parameters", param))
	if err != nil {
		return 0, false
	}
	value := strings.TrimSpace(string(payload))
	switch strings.ToLower(value) {
	case "y", "yes", "true", "on", "enabled":
		return 1, true
	case "n", "no", "false", "off", "disabled":
		return 0, true
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func readModuleParamString(name, param string) (string, bool) {
	payload, err := os.ReadFile(filepath.Join("/sys/module", name, "parameters", param))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(payload)), true
}

func fileSHA256(path string) string {
	payload, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return bytesSHA256(payload)
}

func bytesSHA256(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func looksLikeELF(payload []byte) bool {
	return len(payload) >= 4 && payload[0] == 0x7f && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'F'
}
