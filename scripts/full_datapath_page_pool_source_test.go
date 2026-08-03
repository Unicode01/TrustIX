package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullDatapathOuterGSOPagePoolCompatibilityAndFallback(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath.c: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		"LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)",
		"#include <net/page_pool/helpers.h>",
		"#include <net/page_pool.h>",
		"trustix_datapath_tx_plaintext_outer_gso_page_pool = true",
		"page_pool_create_percpu(params, cpu)",
		"page_pool_create(params)",
		"page_pool_dev_alloc_pages(pool)",
		"skb_mark_for_recycle(skb)",
		"trustix_datapath_alloc_tx_outer_gso_page_pool_skb_locked",
		"if (likely(READ_ONCE(\n\t\t    trustix_datapath_tx_plaintext_outer_gso_page_pool)))",
		"skb = alloc_skb(LL_MAX_HEADER + outer_len, GFP_ATOMIC)",
		"trustix_datapath_tx_plaintext_outer_gso_page_pool_errors",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_datapath.c missing outer-GSO page-pool guard %q", want)
		}
	}

	exitStart := strings.Index(source, "static void __exit trustix_datapath_exit")
	if exitStart < 0 {
		t.Fatal("trustix_datapath.c missing module exit function")
	}
	exitSource := source[exitStart:]
	detach := strings.Index(exitSource, "trustix_datapath_hook_detach_all();")
	synchronize := strings.Index(exitSource, "synchronize_net();")
	destroy := strings.Index(exitSource, "trustix_datapath_destroy_tx_outer_gso_page_pools();")
	if detach < 0 || synchronize < 0 || destroy < 0 || detach >= synchronize || synchronize >= destroy {
		t.Fatal("outer-GSO page pools must be destroyed after hook detach and synchronize_net")
	}
}
