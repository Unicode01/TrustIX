package daemon

import "testing"

func TestPaginateSliceBounds(t *testing.T) {
	items := []int{1, 2, 3, 4}
	page, total, truncated := paginateSlice(items, 1, 2)
	if total != 4 || !truncated || len(page) != 2 || page[0] != 2 || page[1] != 3 {
		t.Fatalf("page=%v total=%d truncated=%t, want [2 3] total=4 truncated", page, total, truncated)
	}

	page, total, truncated = paginateSlice(items, 2, 0)
	if total != 4 || truncated || len(page) != 2 || page[0] != 3 || page[1] != 4 {
		t.Fatalf("unlimited page=%v total=%d truncated=%t, want [3 4] total=4 not truncated", page, total, truncated)
	}

	page, total, truncated = paginateSlice(items, 9, 2)
	if total != 4 || !truncated || len(page) != 0 {
		t.Fatalf("beyond page=%v total=%d truncated=%t, want empty total=4 truncated", page, total, truncated)
	}
}
