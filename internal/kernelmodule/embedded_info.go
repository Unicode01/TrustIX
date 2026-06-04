package kernelmodule

type EmbeddedAsset struct {
	Name    string
	Present bool
	SHA256  string
	Size    int64
	ELF     bool
}

type embeddedModuleAsset struct {
	name  string
	label string
	read  func() []byte
}
