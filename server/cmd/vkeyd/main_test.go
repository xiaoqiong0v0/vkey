package main

import "testing"

// TestResolvePurgeMode 验证 purge 的模式决策：默认 dry-run，--dry-run 优先于 --yes。
func TestResolvePurgeMode(t *testing.T) {
	tests := []struct {
		name     string
		dryRun   bool
		yes      bool
		wantDel  bool
		wantNote bool
	}{
		{name: "默认 dry-run", dryRun: false, yes: false, wantDel: false, wantNote: false},
		{name: "显式 dry-run", dryRun: true, yes: false, wantDel: false, wantNote: false},
		{name: "yes 才删除", dryRun: false, yes: true, wantDel: true, wantNote: false},
		{name: "同时给出时以 dry-run 为准", dryRun: true, yes: true, wantDel: false, wantNote: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doDelete, note := resolvePurgeMode(tc.dryRun, tc.yes)
			if doDelete != tc.wantDel {
				t.Fatalf("doDelete = %v，期望 %v", doDelete, tc.wantDel)
			}
			if (note != "") != tc.wantNote {
				t.Fatalf("note = %q，期望非空=%v", note, tc.wantNote)
			}
		})
	}
}

// TestShortID 验证 id 前缀截断。
func TestShortID(t *testing.T) {
	if got := shortID("abcdefghijkl"); got != "abcdefgh…" {
		t.Fatalf("shortID = %q", got)
	}
	if got := shortID("short"); got != "short" {
		t.Fatalf("shortID = %q", got)
	}
}
