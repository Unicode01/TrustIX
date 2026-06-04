package buildinfo

import (
	"fmt"
	"io"
	"runtime"
	"sort"
)

var (
	Version = "dev"
	Commit  = "unknown"
	BuiltAt = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuiltAt   string `json:"built_at"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	Assets    Assets `json:"assets,omitempty"`
}

type Assets struct {
	EmbeddedKOs map[string]AssetInfo `json:"embedded_kos,omitempty"`
	EBPF        map[string]AssetInfo `json:"ebpf,omitempty"`
}

type AssetInfo struct {
	Name     string `json:"name,omitempty"`
	Embedded bool   `json:"embedded"`
	Present  bool   `json:"present"`
	SHA256   string `json:"sha256,omitempty"`
	Size     int64  `json:"size,omitempty"`
	ELF      bool   `json:"elf,omitempty"`
}

func Snapshot() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuiltAt:   BuiltAt,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
	}
}

func SnapshotWithAssets(assets Assets) Info {
	info := Snapshot()
	info.Assets = assets
	return info
}

func WriteText(w io.Writer, info Info) {
	_, _ = fmt.Fprintf(w, "version=%s\n", info.Version)
	_, _ = fmt.Fprintf(w, "commit=%s\n", info.Commit)
	_, _ = fmt.Fprintf(w, "built_at=%s\n", info.BuiltAt)
	_, _ = fmt.Fprintf(w, "go_version=%s\n", info.GoVersion)
	_, _ = fmt.Fprintf(w, "platform=%s/%s\n", info.GOOS, info.GOARCH)
	if len(info.Assets.EmbeddedKOs) > 0 {
		names := make([]string, 0, len(info.Assets.EmbeddedKOs))
		for name := range info.Assets.EmbeddedKOs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			writeAssetText(w, "asset.embedded_kos."+name, info.Assets.EmbeddedKOs[name])
		}
	}
	if len(info.Assets.EBPF) == 0 {
		return
	}
	names := make([]string, 0, len(info.Assets.EBPF))
	for name := range info.Assets.EBPF {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writeAssetText(w, "asset.ebpf."+name, info.Assets.EBPF[name])
	}
}

func writeAssetText(w io.Writer, prefix string, asset AssetInfo) {
	_, _ = fmt.Fprintf(w, "%s.present=%t\n", prefix, asset.Present)
	_, _ = fmt.Fprintf(w, "%s.embedded=%t\n", prefix, asset.Embedded)
	if asset.Size > 0 {
		_, _ = fmt.Fprintf(w, "%s.size=%d\n", prefix, asset.Size)
	}
	if asset.SHA256 != "" {
		_, _ = fmt.Fprintf(w, "%s.sha256=%s\n", prefix, asset.SHA256)
	}
	_, _ = fmt.Fprintf(w, "%s.elf=%t\n", prefix, asset.ELF)
}
