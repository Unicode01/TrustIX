package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullDatapathRXGSOPageFragCacheFallbackAndDrain(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath.c: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		"static bool trustix_datapath_rx_worker_stream_coalesce_page_frag_cache = true;",
		"DEFINE_PER_CPU(struct page_frag_cache",
		"page_frag_alloc(cache, PAGE_SIZE, GFP_ATOMIC)",
		"page_frag_free(addr)",
		"__page_frag_cache_drain(virt_to_head_page(cache->va)",
		"trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_fallbacks",
		"page = alloc_page(GFP_ATOMIC)",
		"skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_datapath.c missing RX-GSO page-frag cache guard %q", want)
		}
	}
	exitStart := strings.Index(source, "static void __exit trustix_datapath_exit")
	if exitStart < 0 {
		t.Fatal("trustix_datapath.c missing module exit function")
	}
	exitSource := source[exitStart:]
	freeState := strings.Index(exitSource, "trustix_datapath_free_state();")
	drain := strings.Index(exitSource, "trustix_datapath_rx_worker_drain_page_frag_caches();")
	if freeState < 0 || drain < 0 || freeState >= drain {
		t.Fatal("RX-GSO page-frag caches must drain after worker state teardown")
	}
}
