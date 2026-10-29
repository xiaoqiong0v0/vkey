package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// purge 交互式勾选相关的提示文案。
const (
	msgPurgeNoTTY       = "当前没有终端，无法交互；确认后用 --yes"
	msgPurgeNoSelection = "未选择任何条目"
	msgPurgeCancelled   = "已取消，未做任何修改"
	msgPurgeAborted     = "已中断，未做任何修改"
	msgPurgeConfirm     = "删除以上 %d 条？(y/N) "
)

// 交互式界面的 ANSI 控制序列与行尾。
const (
	ansiClearScreen = "\x1b[2J\x1b[H"
	ansiHideCursor  = "\x1b[?25l"
	ansiShowCursor  = "\x1b[?25h"
	crlf            = "\r\n"
)

// purgeHeaderLines 是勾选界面中固定占用的行数（操作提示 + 计数）。
const purgeHeaderLines = 2

// defaultPurgeRows 是拿不到终端尺寸时假定的行数。
const defaultPurgeRows = 24

// purgeKey 是交互式勾选界面识别出的按键。
type purgeKey int

const (
	// purgeKeyOther 是未处理的按键。
	purgeKeyOther purgeKey = iota
	purgeKeyUp
	purgeKeyDown
	purgeKeyToggle
	purgeKeyAll
	purgeKeyEnter
	// purgeKeyAbort 是 Ctrl+C（raw 模式下不会产生 SIGINT，按中断处理）。
	purgeKeyAbort
)

// purgeSelection 是交互式勾选状态（纯数据操作，便于单测）。
type purgeSelection struct {
	targets []store.PurgeTarget
	picked  []bool
	cursor  int
}

// newPurgeSelection 创建全部未勾选、光标在首行的选择集。
func newPurgeSelection(targets []store.PurgeTarget) *purgeSelection {
	return &purgeSelection{targets: targets, picked: make([]bool, len(targets))}
}

// move 把光标移动 delta 行（越界时环绕）。
func (s *purgeSelection) move(delta int) {
	n := len(s.targets)
	if n == 0 {
		return
	}
	s.cursor = ((s.cursor+delta)%n + n) % n
}

// toggle 切换光标所在行的勾选状态。
func (s *purgeSelection) toggle() {
	if s.cursor < 0 || s.cursor >= len(s.targets) {
		return
	}
	s.picked[s.cursor] = !s.picked[s.cursor]
}

// toggleAll 全选 / 全不选：已全选则清空，否则全选。
func (s *purgeSelection) toggleAll() {
	all := len(s.targets) > 0 && s.count() == len(s.targets)
	for i := range s.picked {
		s.picked[i] = !all
	}
}

// count 返回已勾选的条数。
func (s *purgeSelection) count() int {
	n := 0
	for _, ok := range s.picked {
		if ok {
			n++
		}
	}
	return n
}

// selected 按原始顺序返回已勾选的条目。
func (s *purgeSelection) selected() []store.PurgeTarget {
	out := make([]store.PurgeTarget, 0, s.count())
	for i, ok := range s.picked {
		if ok {
			out = append(out, s.targets[i])
		}
	}
	return out
}

// refs 返回已勾选条目的主键对 (user_id, id)（保持原始顺序）。
func (s *purgeSelection) refs() []store.PurgeRef {
	out := make([]store.PurgeRef, 0, s.count())
	for i, ok := range s.picked {
		if ok {
			out = append(out, store.PurgeRef{UserID: s.targets[i].UserID, ID: s.targets[i].ID})
		}
	}
	return out
}

// renderPurgeSelect 把勾选界面渲染为整屏文本（每行以 CRLF 结尾）。
//
// 参数：sel 为选择状态；rows 为终端行数（<=0 时按 defaultPurgeRows 处理）。
func renderPurgeSelect(sel *purgeSelection, rows int) string {
	if rows <= 0 {
		rows = defaultPurgeRows
	}
	height := rows - purgeHeaderLines
	if height < 1 {
		height = 1
	}
	start, end := purgeWindow(len(sel.targets), sel.cursor, height)

	var b strings.Builder
	b.WriteString(ansiClearScreen)
	fmt.Fprintf(&b, "选择要物理删除的墓碑：↑/↓ 或 k/j 移动，空格勾选，a 全选/全不选，回车确认%s", crlf)
	scope := fmt.Sprintf("共 %d 条，已选 %d 条", len(sel.targets), sel.count())
	if end-start < len(sel.targets) {
		scope += fmt.Sprintf("（显示第 %d-%d 条）", start+1, end)
	}
	b.WriteString(scope + crlf)
	for i := start; i < end; i++ {
		t := sel.targets[i]
		cursor := "  "
		if i == sel.cursor {
			cursor = "> "
		}
		box := "[ ]"
		if sel.picked[i] {
			box = "[x]"
		}
		fmt.Fprintf(&b, "%s%s %s/%s %s %s %d %d%s",
			cursor, box, shortID(t.UserID), shortID(t.ID), t.Kind, t.RPID, t.DeletedAt, t.Version, crlf)
	}
	return b.String()
}

// purgeWindow 计算可视窗口 [start, end)，尽量让光标居中。
func purgeWindow(total, cursor, height int) (int, int) {
	if total <= height {
		return 0, total
	}
	start := cursor - height/2
	if start < 0 {
		start = 0
	}
	if start > total-height {
		start = total - height
	}
	return start, start + height
}

// isTerminal 判断文件是否连接着终端。
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// readPurgeKey 从 raw 模式终端读取一个按键。
//
// 返回：识别出的按键。读取失败返回 error（EOF 等），Ctrl+C 返回 purgeKeyAbort。
func readPurgeKey(r *bufio.Reader) (purgeKey, error) {
	b, err := r.ReadByte()
	if err != nil {
		return purgeKeyOther, err
	}
	switch b {
	case 0x03: // Ctrl+C
		return purgeKeyAbort, nil
	case '\r', '\n':
		return purgeKeyEnter, nil
	case ' ':
		return purgeKeyToggle, nil
	case 'a', 'A':
		return purgeKeyAll, nil
	case 'k', 'K':
		return purgeKeyUp, nil
	case 'j', 'J':
		return purgeKeyDown, nil
	case 0x1b: // ESC：可能是方向键 ESC [ A / ESC [ B，也可能是单独的 Esc
		second, err := r.ReadByte()
		if err != nil || second != '[' {
			return purgeKeyOther, nil
		}
		third, err := r.ReadByte()
		if err != nil {
			return purgeKeyOther, nil
		}
		switch third {
		case 'A':
			return purgeKeyUp, nil
		case 'B':
			return purgeKeyDown, nil
		default:
			return purgeKeyOther, nil
		}
	default:
		return purgeKeyOther, nil
	}
}

// purgeInteractive 在终端上交互式勾选墓碑并确认删除。
//
// 流程：raw 模式勾选（↑/↓ 或 k/j 移动、空格勾选、a 全选/全不选、回车结束）
// → 恢复终端 → 列出已勾选摘要并询问 `(y/N)` → y 时单事务删除。
// 取消、未勾选或中断都不写库，返回 nil（退出码 0）。
func purgeInteractive(ctx context.Context, st *store.Store, stdin *os.File, stdout io.Writer) error {
	targets, err := st.PurgePending(ctx)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Fprintf(stdout, "%s\n", msgNoTombstone)
		return nil
	}

	sel := newPurgeSelection(targets)
	reader := bufio.NewReader(stdin)
	fd := int(stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("purge: 无法进入交互模式: %w", err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		fmt.Fprint(stdout, ansiShowCursor)
		_ = term.Restore(fd, state)
	}

	fmt.Fprint(stdout, ansiHideCursor)
	aborted := false
	for {
		rows := defaultPurgeRows
		if _, h, sizeErr := term.GetSize(fd); sizeErr == nil && h > 0 {
			rows = h
		}
		fmt.Fprint(stdout, renderPurgeSelect(sel, rows))

		key, err := readPurgeKey(reader)
		if err != nil {
			// 读到 EOF（终端被关闭等）等价于中断。
			aborted = true
			break
		}
		switch key {
		case purgeKeyUp:
			sel.move(-1)
		case purgeKeyDown:
			sel.move(1)
		case purgeKeyToggle:
			sel.toggle()
		case purgeKeyAll:
			sel.toggleAll()
		case purgeKeyAbort:
			aborted = true
		}
		if key == purgeKeyEnter || aborted {
			break
		}
	}
	restore()
	if aborted {
		fmt.Fprintf(stdout, "\r\n%s\r\n", msgPurgeAborted)
		return nil
	}
	fmt.Fprint(stdout, ansiClearScreen)

	chosen := sel.selected()
	if len(chosen) == 0 {
		fmt.Fprintf(stdout, "%s\n", msgPurgeNoSelection)
		return nil
	}
	fmt.Fprintf(stdout, "将物理删除以下 %d 条：\n", len(chosen))
	for _, t := range chosen {
		fmt.Fprintf(stdout, "  user=%s id=%s %s %s %d %d\n", shortID(t.UserID), shortID(t.ID), t.Kind, t.RPID, t.DeletedAt, t.Version)
	}
	fmt.Fprintf(stdout, msgPurgeConfirm, len(chosen))

	answer, err := reader.ReadString('\n')
	if err != nil && strings.TrimSpace(answer) == "" {
		fmt.Fprintf(stdout, "\n%s\n", msgPurgeCancelled)
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		fmt.Fprintf(stdout, "%s\n", msgPurgeCancelled)
		return nil
	}

	n, err := st.PurgeIDs(ctx, sel.refs())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "已物理删除 %d 条\n", n)
	return nil
}
