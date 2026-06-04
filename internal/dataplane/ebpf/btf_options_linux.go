//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

const (
	bpfKernelBTFEnv       = "TRUSTIX_BPF_KERNEL_BTF"
	bpfExtraBTFEnv        = "TRUSTIX_BPF_EXTRA_BTF"
	bpfBTFStrictEnv       = "TRUSTIX_BPF_BTF_STRICT"
	bpfBTFStrictKernelEnv = "TRUSTIX_BPF_KERNEL_BTF_STRICT"
	bpfBTFStrictExtraEnv  = "TRUSTIX_BPF_EXTRA_BTF_STRICT"
)

var (
	configuredKernelBTFOnce sync.Once
	configuredKernelBTFSpec *btf.Spec
	configuredKernelBTFErr  error

	configuredExtraBTFOnce  sync.Once
	configuredExtraBTFSpecs []*btf.Spec
	configuredExtraBTFErr   error
)

func newBPFCollectionWithOptions(spec *cebpf.CollectionSpec, options cebpf.CollectionOptions) (*cebpf.Collection, error) {
	programOptions, err := programOptionsWithConfiguredBTF(options.Programs)
	if err != nil {
		return nil, err
	}
	options.Programs = programOptions
	return cebpf.NewCollectionWithOptions(spec, options)
}

func newBPFProgramWithOptions(spec *cebpf.ProgramSpec, options cebpf.ProgramOptions) (*cebpf.Program, error) {
	programOptions, err := programOptionsWithConfiguredBTF(options)
	if err != nil {
		return nil, err
	}
	return cebpf.NewProgramWithOptions(spec, programOptions)
}

func programOptionsWithConfiguredBTF(options cebpf.ProgramOptions) (cebpf.ProgramOptions, error) {
	if options.KernelTypes == nil {
		kernelTypes, err := configuredKernelBTF()
		if err != nil {
			return options, err
		}
		if kernelTypes != nil {
			options.KernelTypes = kernelTypes
		}
	}
	extraTypes, err := configuredExtraBTF()
	if err != nil {
		return options, err
	}
	if len(extraTypes) > 0 {
		options.ExtraRelocationTargets = append(options.ExtraRelocationTargets, extraTypes...)
	}
	return options, nil
}

func configuredKernelBTF() (*btf.Spec, error) {
	paths := configuredBTFPaths(os.Getenv(bpfKernelBTFEnv))
	if len(paths) == 0 {
		return nil, nil
	}
	configuredKernelBTFOnce.Do(func() {
		for _, path := range paths {
			spec, err := btf.LoadSpec(path)
			if err == nil {
				configuredKernelBTFSpec = spec
				configuredKernelBTFErr = nil
				return
			}
			if configuredBTFStrict(bpfBTFStrictKernelEnv) || !errors.Is(err, os.ErrNotExist) {
				configuredKernelBTFErr = fmt.Errorf("load external kernel BTF from %s entry %q: %w", bpfKernelBTFEnv, path, err)
				return
			}
		}
	})
	return configuredKernelBTFSpec, configuredKernelBTFErr
}

func configuredExtraBTF() ([]*btf.Spec, error) {
	paths := configuredBTFPaths(os.Getenv(bpfExtraBTFEnv))
	if len(paths) == 0 {
		return nil, nil
	}
	configuredExtraBTFOnce.Do(func() {
		for _, path := range paths {
			spec, err := btf.LoadSpec(path)
			if err != nil {
				if configuredBTFStrict(bpfBTFStrictExtraEnv) || !errors.Is(err, os.ErrNotExist) {
					configuredExtraBTFErr = fmt.Errorf("load external relocation BTF from %s entry %q: %w", bpfExtraBTFEnv, path, err)
					return
				}
				continue
			}
			configuredExtraBTFSpecs = append(configuredExtraBTFSpecs, spec)
		}
	})
	return configuredExtraBTFSpecs, configuredExtraBTFErr
}

func configuredBTFPaths(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "auto") {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == rune(os.PathListSeparator) || r == ',' || r == ';'
	})
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		path := strings.TrimSpace(part)
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func configuredBTFStrict(specificEnv string) bool {
	return truthyEnv(os.Getenv(specificEnv)) || truthyEnv(os.Getenv(bpfBTFStrictEnv))
}

func truthyEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on", "strict", "required", "require":
		return true
	default:
		return false
	}
}
