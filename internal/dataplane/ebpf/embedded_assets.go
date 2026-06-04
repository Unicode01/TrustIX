package ebpf

type EmbeddedAsset struct {
	Name    string
	Present bool
	SHA256  string
	Size    int64
	ELF     bool
}
