package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKernelCryptoBatchSealUsesCallerSpecificSIMDPolicy(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_crypto", "trustix_crypto.c"))
	if err != nil {
		t.Fatalf("read trustix_crypto.c: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		"u32 slot_id, u64 generation, bool datapath,",
		"datapath ? READ_ONCE(trustix_datapath_simd_fastpath)",
		"READ_ONCE(trustix_kfunc_simd_fastpath)",
		"datapath ? trustix_aead_datapath_fpu_begin()",
		"trustix_aead_fpu_begin()",
		"&snapshot, &ops[i], datapath, &used_vaes",
		"slot_id, 0, false,",
		"slot_id, generation, true, ops, count",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_crypto.c missing batch-seal policy contract %q", want)
		}
	}
}

func TestKernelCryptoDatapathSelftestDoesNotPolluteRuntimeErrors(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_crypto", "trustix_crypto.c"))
	if err != nil {
		t.Fatalf("read trustix_crypto.c: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		"trustix_kernel_direct_open_replay_batch_checked(",
		"u64 replay_floor, u32 replay_window, bool record_error)",
		"if (record_error)",
		"replay_floor, replay_window,\n\t\ttrue);",
		"replay_floor, replay_window, true);",
		"replay_floor, 128, false);",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_crypto.c missing selftest telemetry isolation contract %q", want)
		}
	}
}

func TestKernelCryptoDirectSlotsAreOwnedByTheCallingFile(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_crypto", "trustix_crypto.c"))
	if err != nil {
		t.Fatalf("read trustix_crypto.c: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		"#define TRUSTIX_AEAD_IOC_DIRECT_FLAG_OWNER BIT(2)",
		"#define TRUSTIX_AEAD_MODULE_ABI_VERSION 5",
		"struct trustix_aead_file *owner;",
		"DECLARE_BITMAP(direct_slots, TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS);",
		"__set_bit(actual_slot, slot->owner->direct_slots);",
		"trustix_aead_direct_clear_owned(state);",
		"direct_owner_release_slots",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_crypto.c missing direct-slot owner contract %q", want)
		}
	}

	goPayload, err := os.ReadFile(filepath.Join("..", "internal", "kernelmodule", "aead_ioctl_linux.go"))
	if err != nil {
		t.Fatalf("read aead_ioctl_linux.go: %v", err)
	}
	goSource := string(goPayload)
	for _, want := range []string{
		"trustIXAEADDirectFlagOwner       = uint32(1 << 2)",
		"func openAEADDirectOwnerFile(path string) (*os.File, error)",
		"flags := trustIXAEADDirectFlagOwner",
		"ABI v4 and older do not understand the owner flag",
	} {
		if !strings.Contains(goSource, want) {
			t.Fatalf("aead_ioctl_linux.go missing process-owned slot contract %q", want)
		}
	}
}

func TestKernelCryptoGenerationAwareCallsTreatRetiredSlotsAsStale(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_crypto", "trustix_crypto.c"))
	if err != nil {
		t.Fatalf("read trustix_crypto.c: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		"if (ret == -ESTALE)\n\t\treturn;",
		"if (ret == -ENOENT && generation)\n\t\t\tret = -ESTALE;",
		"if (!slot)\n\t\tret = -ESTALE;\n\telse if (slot->generation != generation)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_crypto.c missing retired-slot stale contract %q", want)
		}
	}
}

func TestKernelCryptoBPFContextUsesAllocatableSynchronousProvider(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_crypto", "trustix_crypto.c"))
	if err != nil {
		t.Fatalf("read trustix_crypto.c: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		`"gcm_base(ctr(aes-generic),ghash-generic)"`,
		"return crypto_alloc_aead(TRUSTIX_GENERIC_GCM_AES, 0,",
		"struct crypto_aead *tfm = trustix_alloc_kernel(algo);",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_crypto.c missing BPF provider allocation contract %q", want)
		}
	}

	start := strings.Index(source, "static struct crypto_aead *trustix_alloc_kernel")
	if start < 0 {
		t.Fatal("trustix_crypto.c missing BPF provider allocator start")
	}
	end := strings.Index(source[start:], "static struct crypto_aead *trustix_alloc_waitable_aead")
	if end < 0 {
		t.Fatal("trustix_crypto.c missing BPF provider allocator end")
	}
	allocator := source[start : start+end]
	if strings.Contains(allocator, "TRUSTIX_INTERNAL_GCM_AES") {
		t.Fatal("BPF provider allocator must not request an internal crypto algorithm")
	}
}
