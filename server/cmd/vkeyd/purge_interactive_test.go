package main

import (
	"bufio"
	"strings"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// testPurgeTargets 造 3 条墓碑摘要（分属两个用户，含跨用户同名 id）。
func testPurgeTargets() []store.PurgeTarget {
	return []store.PurgeTarget{
		{UserID: "user-alice", ID: "aaaaaaaa-1", Kind: "totp", RPID: "a.example", DeletedAt: 200, Version: 3},
		{UserID: "user-bob", ID: "bbbbbbbb-2", Kind: "totp", RPID: "b.example", DeletedAt: 300, Version: 4},
		{UserID: "user-alice", ID: "cccccccc-3", Kind: "totp", RPID: "c.example", DeletedAt: 400, Version: 5},
	}
}

// TestPurgeSelectionInitial 验证初始状态：光标在首行、全部未勾选。
func TestPurgeSelectionInitial(t *testing.T) {
	sel := newPurgeSelection(testPurgeTargets())
	if sel.cursor != 0 {
		t.Fatalf("cursor = %d，期望 0", sel.cursor)
	}
	if got := sel.count(); got != 0 {
		t.Fatalf("已选 = %d，期望 0", got)
	}
	if got := len(sel.refs()); got != 0 {
		t.Fatalf("refs 长度 = %d，期望 0", got)
	}
}

// TestPurgeSelectionMove 验证光标移动与环绕。
func TestPurgeSelectionMove(t *testing.T) {
	sel := newPurgeSelection(testPurgeTargets())
	sel.move(1)
	if sel.cursor != 1 {
		t.Fatalf("下移后 cursor = %d，期望 1", sel.cursor)
	}
	sel.move(-1)
	if sel.cursor != 0 {
		t.Fatalf("上移后 cursor = %d，期望 0", sel.cursor)
	}
	sel.move(-1)
	if sel.cursor != 2 {
		t.Fatalf("首行上移后 cursor = %d，期望 2（环绕）", sel.cursor)
	}
	sel.move(1)
	if sel.cursor != 0 {
		t.Fatalf("末行下移后 cursor = %d，期望 0（环绕）", sel.cursor)
	}
}

// TestPurgeSelectionMoveEmpty 验证空列表时移动不 panic。
func TestPurgeSelectionMoveEmpty(t *testing.T) {
	sel := newPurgeSelection(nil)
	sel.move(1)
	sel.toggle()
	if sel.cursor != 0 || sel.count() != 0 {
		t.Fatalf("空列表不应改变状态: cursor=%d count=%d", sel.cursor, sel.count())
	}
}

// TestPurgeSelectionToggle 验证空格勾选只作用于光标行。
func TestPurgeSelectionToggle(t *testing.T) {
	sel := newPurgeSelection(testPurgeTargets())
	sel.toggle() // 勾选第 1 行
	sel.move(2)  // 移到第 3 行
	sel.toggle() // 勾选第 3 行
	if got := sel.count(); got != 2 {
		t.Fatalf("已选 = %d，期望 2", got)
	}
	if refs := sel.refs(); len(refs) != 2 || refs[0].ID != "aaaaaaaa-1" || refs[1].ID != "cccccccc-3" {
		t.Fatalf("refs = %v，期望按原始顺序 [aaaaaaaa-1 cccccccc-3]", refs)
	}
	if refs := sel.refs(); len(refs) != 2 || refs[0].UserID != "user-alice" {
		t.Fatalf("refs 缺少 user 归属: %v", refs)
	}
	// 再次切换第 3 行 → 取消勾选。
	sel.toggle()
	if refs := sel.refs(); len(refs) != 1 || refs[0].ID != "aaaaaaaa-1" {
		t.Fatalf("取消勾选后 refs = %v", refs)
	}
	if got := len(sel.selected()); got != 1 || sel.selected()[0].ID != "aaaaaaaa-1" {
		t.Fatalf("selected = %+v", sel.selected())
	}
}

// TestPurgeSelectionToggleAll 验证 a 键：未全选时全选，已全选时清空。
func TestPurgeSelectionToggleAll(t *testing.T) {
	sel := newPurgeSelection(testPurgeTargets())
	sel.toggleAll()
	if got := sel.count(); got != 3 {
		t.Fatalf("全选后已选 = %d，期望 3", got)
	}
	sel.toggleAll()
	if got := sel.count(); got != 0 {
		t.Fatalf("再次全选后已选 = %d，期望 0（全不选）", got)
	}
	// 部分选中时按 a 应为全选（而不是清空）。
	sel.toggle()
	sel.toggleAll()
	if got := sel.count(); got != 3 {
		t.Fatalf("部分选中后 a 的已选 = %d，期望 3", got)
	}
}

// TestPurgeSelectionToggleAllEmpty 验证空列表全选不 panic。
func TestPurgeSelectionToggleAllEmpty(t *testing.T) {
	sel := newPurgeSelection(nil)
	sel.toggleAll()
	if sel.count() != 0 {
		t.Fatalf("空列表全选后已选 = %d，期望 0", sel.count())
	}
}

// TestRenderPurgeSelect 验证渲染：光标行 `> `、勾选标记、字段齐全。
func TestRenderPurgeSelect(t *testing.T) {
	sel := newPurgeSelection(testPurgeTargets())
	sel.toggle() // 勾选第 1 行
	out := renderPurgeSelect(sel, 24)

	if !strings.Contains(out, "共 3 条，已选 1 条") {
		t.Fatalf("缺少计数行：\n%q", out)
	}
	if !strings.Contains(out, "> [x] user-ali…/aaaaaaaa… totp a.example 200 3") {
		t.Fatalf("缺少光标+勾选行：\n%q", out)
	}
	if !strings.Contains(out, "  [ ] user-bob/bbbbbbbb… totp b.example 300 4") {
		t.Fatalf("缺少未勾选行：\n%q", out)
	}
}

// TestRenderPurgeSelectWindow 验证列表超过窗口高度时只显示窗口内条目并给出范围。
func TestRenderPurgeSelectWindow(t *testing.T) {
	targets := make([]store.PurgeTarget, 0, 20)
	for i := 0; i < 20; i++ {
		targets = append(targets, store.PurgeTarget{
			ID:        shortID("id-" + string(rune('a'+i))),
			Kind:      "totp",
			RPID:      "x.example",
			DeletedAt: 100,
			Version:   int64(i + 1),
		})
	}
	sel := newPurgeSelection(targets)
	sel.move(10) // 光标移到第 11 条
	out := renderPurgeSelect(sel, 8)
	// 8 行终端 → 6 行内容窗口，光标居中。
	if !strings.Contains(out, "（显示第 8-13 条）") {
		t.Fatalf("缺少窗口范围提示：\n%q", out)
	}
	lines := strings.Split(strings.TrimSuffix(out, crlf), crlf)
	// 2 行表头（首行前置清屏序列）+ 6 行条目。
	if got := len(lines); got != purgeHeaderLines+6 {
		t.Fatalf("行数 = %d，期望 %d", got, purgeHeaderLines+6)
	}
}

// TestReadPurgeKey 验证按键解码（方向键转义序列、j/k、空格、a、回车、Ctrl+C）。
func TestReadPurgeKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  purgeKey
	}{
		{name: "下箭头", input: "\x1b[B", want: purgeKeyDown},
		{name: "上箭头", input: "\x1b[A", want: purgeKeyUp},
		{name: "j", input: "j", want: purgeKeyDown},
		{name: "k", input: "k", want: purgeKeyUp},
		{name: "空格", input: " ", want: purgeKeyToggle},
		{name: "a", input: "a", want: purgeKeyAll},
		{name: "回车", input: "\r", want: purgeKeyEnter},
		{name: "换行", input: "\n", want: purgeKeyEnter},
		{name: "Ctrl+C", input: "\x03", want: purgeKeyAbort},
		{name: "左箭头忽略", input: "\x1b[D", want: purgeKeyOther},
		{name: "单独 Esc", input: "\x1bx", want: purgeKeyOther},
		{name: "其它字符忽略", input: "z", want: purgeKeyOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPurgeKey(bufio.NewReader(strings.NewReader(tc.input)))
			if err != nil {
				t.Fatalf("readPurgeKey: %v", err)
			}
			if got != tc.want {
				t.Fatalf("key = %v，期望 %v", got, tc.want)
			}
		})
	}
}

// TestReadPurgeKeyEOF 验证读到 EOF 时返回错误。
func TestReadPurgeKeyEOF(t *testing.T) {
	if _, err := readPurgeKey(bufio.NewReader(strings.NewReader(""))); err == nil {
		t.Fatal("EOF 时应返回错误")
	}
}
