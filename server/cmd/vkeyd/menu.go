package main

// 本文件实现 vkeyd 的交互式控制台（一个薄壳）：
//
//	vkeyd --db <path>        # 无子命令且 stdin 是终端时进入
//	vkeyd menu --db <path>   # 显式进入
//
// 菜单只负责读输入与展示结果，写库操作全部复用既有实现
// （userListRun / userAddRun / applyUpdateFlags / setPolicy / store.*），
// 不在此重复业务逻辑。约束：不打印 master_key、token 或 verifier 明文；
// `user add` 的一次性开户码由既有实现输出，属于预期。

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// 交互式控制台的固定取值。
const (
	// defaultMenuDBPath 是未给 --db 时的缺省数据库路径。
	defaultMenuDBPath = "./data/vkeyd.db"
	// menuLastChoice 是主菜单最大编号（用于解析与越界判定）。
	menuLastChoice = 6
	// menuConfirmHint 是危险操作二次确认的提示（只认 yes / y）。
	menuConfirmHint = "（输入 yes 或 y 确认，其它任意输入取消）: "
)

// 各子菜单的最大编号（0 一律为返回）。
const (
	userMenuLastChoice     = 5
	policyMenuLastChoice   = 7
	updateMenuLastChoice   = 2
	maintMenuLastChoice    = 2
	minVersionCode         = 1
	menuAskBackHint        = "选择编号: "
	msgMenuCancelled       = "已取消，未做任何修改"
	msgMenuInvalidChoice   = "无效选择 %q：请输入 0-%d 的编号"
	msgMenuExited          = "已退出"
	msgMenuNoQuotaChanged  = "未修改任何配额"
	msgMenuPathUnchanged   = "数据库路径保持不变"
	msgMenuUpdateNotConfig = "vkeyd: 更新信息尚未配置完整（需要 version_code 与 sha256），GET /api/v1/update/android 返回 204"
)

// menuMode 是 `vkeyd` 无子命令 / `vkeyd menu` 的处理方式。
type menuMode int

const (
	// menuModeInteractive 进入交互式控制台（stdin 是终端）。
	menuModeInteractive menuMode = iota
	// menuModeUsage 只打印 usage 并退出（非终端，避免脚本卡死）。
	menuModeUsage
)

// resolveMenuEntry 决定是否进入交互菜单（纯函数，便于单测）。
//
// 参数：isTTY 表示 stdin 是否连接终端。
// 返回：menuModeInteractive（终端）或 menuModeUsage（非终端）。
func resolveMenuEntry(isTTY bool) menuMode {
	if isTTY {
		return menuModeInteractive
	}
	return menuModeUsage
}

// parseChoice 解析菜单编号：空行、非数字、负数或超过 max 都视为非法。
//
// 参数：raw 为用户输入的一行；max 为该菜单允许的最大编号。
// 返回：合法时返回编号与 true，否则返回 0 与 false。
func parseChoice(raw string, max int) (int, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > max {
		return 0, false
	}
	return n, true
}

// parseMenuChoice 解析主菜单编号（0-6）；等价 parseChoice(raw, menuLastChoice)。
func parseMenuChoice(raw string) (int, bool) {
	return parseChoice(raw, menuLastChoice)
}

// parseConfirm 解析危险操作的二次确认：只认 y / yes（忽略大小写与首尾空白）。
func parseConfirm(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// menu 是一次交互式控制台会话的状态。
//
// 数据库句柄按操作打开/关闭（见 withStore），因此「修改数据库路径」立即生效，
// 也不会在菜单等待输入期间长期占用数据库。
type menu struct {
	dbPath string
	in     *bufio.Reader
	out    io.Writer
	errOut io.Writer
}

// runMenuEntry 处理 `vkeyd --db <path>` 与 `vkeyd menu --db <path>` 两种入口。
//
// 非终端时打印 usage 后返回错误（不进入菜单，避免脚本/CI 卡死）。
func runMenuEntry(args []string) error {
	flagSet := flag.NewFlagSet("menu", flag.ContinueOnError)
	flagSet.SetOutput(os.Stderr)
	dbPath := flagSet.String("db", "", "sqlite 数据库路径（缺省 ./data/vkeyd.db）")
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	if flagSet.NArg() > 0 {
		usage(os.Stderr)
		return fmt.Errorf("menu: 未知参数 %q", flagSet.Arg(0))
	}
	if resolveMenuEntry(isTerminal(os.Stdin)) == menuModeUsage {
		usage(os.Stderr)
		return errors.New("stdin 不是终端，未进入交互菜单；请使用子命令（vkeyd help 查看）")
	}
	return runMenu(*dbPath)
}

// runMenu 进入交互式控制台；dbPath 为空时取 defaultMenuDBPath。
func runMenu(dbPath string) error {
	if strings.TrimSpace(dbPath) == "" {
		dbPath = defaultMenuDBPath
	}
	m := &menu{
		dbPath: dbPath,
		in:     bufio.NewReader(os.Stdin),
		out:    os.Stdout,
		errOut: os.Stderr,
	}
	return m.loop()
}

// loop 是主菜单循环：非法输入提示后重绘，0 退出。
func (m *menu) loop() error {
	for {
		m.printMain()
		raw, err := m.readline()
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintf(m.out, "\n%s\n", msgMenuExited)
				return nil
			}
			return err
		}
		choice, ok := parseMenuChoice(raw)
		if !ok {
			fmt.Fprintf(m.out, msgMenuInvalidChoice+"\n", raw, menuLastChoice)
			continue
		}
		switch choice {
		case 0:
			fmt.Fprintln(m.out, msgMenuExited)
			return nil
		case 1:
			if m.runSub(m.overview) {
				return nil
			}
		case 2:
			if m.runSub(m.userMenu) {
				return nil
			}
		case 3:
			if m.runSub(m.policyMenu) {
				return nil
			}
		case 4:
			if m.runSub(m.updateMenu) {
				return nil
			}
		case 5:
			if m.runSub(m.maintenanceMenu) {
				return nil
			}
		case 6:
			if m.runSub(m.changeDBPath) {
				return nil
			}
		}
	}
}

// printMain 绘制主菜单。
func (m *menu) printMain() {
	fmt.Fprintf(m.out, "\nvkeyd 控制台  db=%s\n", m.dbPath)
	fmt.Fprintln(m.out, "  1) 概览")
	fmt.Fprintln(m.out, "  2) 用户管理")
	fmt.Fprintln(m.out, "  3) 策略设置")
	fmt.Fprintln(m.out, "  4) 更新信息")
	fmt.Fprintln(m.out, "  5) 维护")
	fmt.Fprintln(m.out, "  6) 修改数据库路径")
	fmt.Fprintln(m.out, "  0) 退出")
	fmt.Fprint(m.out, menuAskBackHint)
}

// runSub 执行一个子流程：io.EOF 视为退出整个菜单，其它错误打印后回到主菜单。
//
// 返回：true 表示应当退出控制台。
func (m *menu) runSub(fn func() error) (stop bool) {
	if err := fn(); err != nil {
		if errors.Is(err, io.EOF) {
			fmt.Fprintf(m.out, "\n%s\n", msgMenuExited)
			return true
		}
		fmt.Fprintf(m.errOut, "错误: %v\n", err)
	}
	return false
}

// report 打印非退出型错误（结果已由具体操作写到 out）。
func (m *menu) report(err error) {
	if err != nil {
		fmt.Fprintf(m.errOut, "错误: %v\n", err)
	}
}

// ask 打印提示并读取一行（去掉首尾空白，含 Windows 行尾的 \r）。
func (m *menu) ask(label string) (string, error) {
	fmt.Fprint(m.out, label)
	return m.readline()
}

// readline 读取一行；EOF 且无内容时返回 io.EOF。
func (m *menu) readline() (string, error) {
	line, err := m.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" && errors.Is(err, io.EOF) {
		return "", io.EOF
	}
	return trimmed, nil
}

// withStore 打开当前 dbPath 指向的库执行 fn，返回前关闭。
func (m *menu) withStore(fn func(ctx context.Context, st *store.Store) error) error {
	st, err := store.Open(m.dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	return fn(context.Background(), st)
}

// overview 展示用户数、条目数、user_mode、enroll_ttl 与更新配置摘要。
func (m *menu) overview() error {
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		users, err := st.ListUsers(ctx)
		if err != nil {
			return err
		}
		items, devices, err := st.Counts(ctx)
		if err != nil {
			return err
		}
		mode, err := st.UserMode(ctx)
		if err != nil {
			return err
		}
		ttl, err := st.EnrollTTLSeconds(ctx)
		if err != nil {
			return err
		}
		quotas, err := st.Quotas(ctx)
		if err != nil {
			return err
		}
		info, err := st.UpdateInfo(ctx)
		if err != nil {
			return err
		}
		tombstones, err := st.PurgePending(ctx)
		if err != nil {
			return err
		}

		disabled := 0
		for _, u := range users {
			if u.DisabledAt != 0 {
				disabled++
			}
		}
		requireMasterPW := false
		if u, err := st.FirstUser(ctx); err == nil {
			requireMasterPW = u.RequireMasterPW
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		fmt.Fprintf(m.out, "数据库: %s\n", m.dbPath)
		fmt.Fprintf(m.out, "用户数: %d（停用 %d）\n", len(users), disabled)
		fmt.Fprintf(m.out, "条目数: %d（墓碑 %d）  设备数: %d\n", items, len(tombstones), devices)
		fmt.Fprintf(m.out, "user_mode: %s\n", mode)
		fmt.Fprintf(m.out, "require_master_pw: %t\n", requireMasterPW)
		fmt.Fprintf(m.out, "enroll_ttl: %s\n", formatDuration(ttl))
		fmt.Fprintf(m.out, "配额: items=%s bytes=%s devices=%s（-1=不限制）\n",
			quotaText(quotas.MaxItems), quotaText(quotas.MaxBytes), quotaText(quotas.MaxDevices))
		fmt.Fprintf(m.out, "更新: source=%s repo=%s asset=%s\n", info.Source, info.Repo, info.Asset)
		fmt.Fprintf(m.out, "      version_code=%d version_name=%s configured=%t\n",
			info.VersionCode, info.VersionName, info.Configured)
		fmt.Fprintf(m.out, "      auto_check=%t check_interval=%ds last_checked_at=%d\n",
			info.AutoCheck, info.CheckInterval, info.LastCheckedAt)
		if info.LastCheckError != "" {
			fmt.Fprintf(m.out, "      last_check_error=%s\n", info.LastCheckError)
		}
		return nil
	})
}

// quotaText 把配额值折算为展示文本（负数表示不限制）。
func quotaText(v int64) string {
	if v < 0 {
		return "不限制"
	}
	return strconv.FormatInt(v, 10)
}

// userMenu 是用户管理子菜单；任一操作完成后返回主菜单。
func (m *menu) userMenu() error {
	for {
		fmt.Fprintf(m.out, "\n用户管理（db=%s）\n", m.dbPath)
		fmt.Fprintln(m.out, "  1) 列表")
		fmt.Fprintln(m.out, "  2) 开户（签发一次性开户码，可设 ttl / domain）")
		fmt.Fprintln(m.out, "  3) 启用")
		fmt.Fprintln(m.out, "  4) 停用")
		fmt.Fprintln(m.out, "  5) 删除（级联，需二次确认）")
		fmt.Fprintln(m.out, "  0) 返回主菜单")
		raw, err := m.ask(menuAskBackHint)
		if err != nil {
			return err
		}
		choice, ok := parseChoice(raw, userMenuLastChoice)
		if !ok {
			fmt.Fprintf(m.out, msgMenuInvalidChoice+"\n", raw, userMenuLastChoice)
			continue
		}
		switch choice {
		case 0:
			return nil
		case 1:
			return m.withStore(func(ctx context.Context, st *store.Store) error {
				return userListRun(ctx, st, m.out)
			})
		case 2:
			return m.userAdd()
		case 3:
			return m.userToggle(false)
		case 4:
			return m.userToggle(true)
		case 5:
			return m.userDelete()
		}
	}
}

// userAdd 交互式开户：用户名必填，ttl / domain 可直接回车取默认。
func (m *menu) userAdd() error {
	username, err := m.ask("用户名: ")
	if err != nil {
		return err
	}
	if err := validateCLIUsername(username); err != nil {
		return err
	}
	ttlRaw, err := m.ask("有效期 ttl（回车=服务端默认，如 2h）: ")
	if err != nil {
		return err
	}
	domain, err := m.ask("对外域名 domain（回车=输出相对路径）: ")
	if err != nil {
		return err
	}

	explicitTTL := ttlRaw != ""
	var ttl time.Duration
	if explicitTTL {
		d, err := time.ParseDuration(ttlRaw)
		if err != nil {
			return fmt.Errorf("ttl 必须是 Go duration（如 30m），实际 %q", ttlRaw)
		}
		if d <= 0 {
			return errors.New("ttl 必须为正数")
		}
		ttl = d
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		effective, err := resolveEnrollTTL(ctx, st, ttl, explicitTTL)
		if err != nil {
			return err
		}
		return userAddRun(ctx, st, username, domain, effective, time.Now(), m.out, m.errOut)
	})
}

// resolveMenuUser 按「用户名或 id」定位账号（先用户名，再 id）。
func resolveMenuUser(ctx context.Context, st *store.Store, ref string) (*store.User, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("缺少用户名或 id")
	}
	u, err := st.UserByUsername(ctx, ref)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	u, err = st.UserByID(ctx, ref)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return nil, fmt.Errorf("账号不存在（%s）", ref)
}

// userToggle 启用/停用账号（数据保留，与 `vkeyd user enable|disable` 一致）。
func (m *menu) userToggle(disable bool) error {
	label, status := "启用", "enabled"
	if disable {
		label, status = "停用", "disabled"
	}
	ref, err := m.ask(label + "：用户名或 id: ")
	if err != nil {
		return err
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		u, err := resolveMenuUser(ctx, st, ref)
		if err != nil {
			return err
		}
		disabledAt := int64(0)
		if disable {
			disabledAt = time.Now().Unix()
		}
		if err := st.SetUserDisabled(ctx, u.ID, disabledAt); err != nil {
			return err
		}
		fmt.Fprintf(m.out, "user id=%s username=%s status=%s\n", u.ID, u.Username, status)
		if disable {
			fmt.Fprintln(m.errOut, "vkeyd: 该用户全部设备立即返回 401；数据保留，可在菜单里重新启用")
		}
		return nil
	})
}

// userDelete 级联删除账号：先展示将删除的行数，输入 yes/y 才执行。
func (m *menu) userDelete() error {
	ref, err := m.ask("删除：用户名或 id: ")
	if err != nil {
		return err
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		u, err := resolveMenuUser(ctx, st, ref)
		if err != nil {
			return err
		}
		usage, err := st.DeleteUserPreview(ctx, u.ID)
		if err != nil {
			return err
		}
		fmt.Fprintf(m.out, "user id=%s username=%s created_at=%d status=%s\n",
			usage.UserID, usage.Username, usage.CreatedAt, userStatus(usage.DisabledAt))
		fmt.Fprintf(m.out, "将删除 items=%d conflicts=%d devices=%d pairs=%d audits=%d enroll_codes=%d\n",
			usage.Items, usage.Conflicts, usage.Devices, usage.Pairs, usage.Audits, usage.Codes)
		fmt.Fprintln(m.errOut, "vkeyd: 以上为 dry-run 统计，尚未写库；级联删除不可逆")
		answer, err := m.ask("确认删除该账号？" + menuConfirmHint)
		if err != nil {
			return err
		}
		if !parseConfirm(answer) {
			fmt.Fprintln(m.out, msgMenuCancelled)
			return nil
		}
		deleted, err := st.DeleteUserCascade(ctx, u.ID)
		if err != nil {
			return err
		}
		fmt.Fprintf(m.out, "已删除 user id=%s username=%s items=%d conflicts=%d devices=%d pairs=%d audits=%d enroll_codes=%d\n",
			deleted.UserID, deleted.Username, deleted.Items, deleted.Conflicts,
			deleted.Devices, deleted.Pairs, deleted.Audits, deleted.Codes)
		return nil
	})
}

// policyMenu 是策略设置子菜单；任一操作完成后返回主菜单。
func (m *menu) policyMenu() error {
	for {
		fmt.Fprintf(m.out, "\n策略设置（db=%s）\n", m.dbPath)
		fmt.Fprintln(m.out, "  1) user_mode（single|admin）")
		fmt.Fprintln(m.out, "  2) 开户码有效期 enroll-ttl（如 30m）")
		fmt.Fprintln(m.out, "  3) 强制主密码 require-master-pw（true|false）")
		fmt.Fprintln(m.out, "  4) 更新来源 update-source（github|local）")
		fmt.Fprintln(m.out, "  5) 惰性更新检查 update-auto-check（true|false）")
		fmt.Fprintln(m.out, "  6) 惰性检查间隔 update-check-interval（秒）")
		fmt.Fprintln(m.out, "  7) 每用户配额（items / bytes / devices）")
		fmt.Fprintln(m.out, "  0) 返回主菜单")
		raw, err := m.ask(menuAskBackHint)
		if err != nil {
			return err
		}
		choice, ok := parseChoice(raw, policyMenuLastChoice)
		if !ok {
			fmt.Fprintf(m.out, msgMenuInvalidChoice+"\n", raw, policyMenuLastChoice)
			continue
		}
		switch choice {
		case 0:
			return nil
		case 1:
			return m.policyUserMode()
		case 2:
			return m.policyEnrollTTL()
		case 3:
			return m.policyRequireMasterPW()
		case 4:
			return m.policyUpdateField("update-source（github|local）: ", "Source")
		case 5:
			return m.policyUpdateField("update-auto-check（true|false）: ", "AutoCheck")
		case 6:
			return m.policyUpdateField("update-check-interval（秒，0=每次请求都检查）: ", "CheckInterval")
		case 7:
			return m.policyQuotas()
		}
	}
}

// policyUserMode 设置 user_mode。
func (m *menu) policyUserMode() error {
	v, err := m.ask("user_mode（single|admin）: ")
	if err != nil {
		return err
	}
	if v != policy.UserModeSingle && v != policy.UserModeAdmin {
		return fmt.Errorf("user_mode 必须是 %s 或 %s，实际 %q", policy.UserModeSingle, policy.UserModeAdmin, v)
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		if err := st.SetUserMode(ctx, v); err != nil {
			return err
		}
		fmt.Fprintf(m.out, "user_mode 已设置为 %s\n", v)
		return nil
	})
}

// policyEnrollTTL 设置开户码默认有效期。
func (m *menu) policyEnrollTTL() error {
	raw, err := m.ask("enroll-ttl（Go duration，如 30m / 2h）: ")
	if err != nil {
		return err
	}
	if raw == "" {
		return errors.New("enroll-ttl 不能为空")
	}
	seconds, err := parseEnrollTTL(raw)
	if err != nil {
		return err
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		if err := st.SetEnrollTTLSeconds(ctx, seconds); err != nil {
			return err
		}
		fmt.Fprintf(m.out, "enroll_ttl 已设置为 %s\n", formatDuration(seconds))
		return nil
	})
}

// policyRequireMasterPW 设置唯一账号的强制主密码策略。
func (m *menu) policyRequireMasterPW() error {
	raw, err := m.ask("require_master_pw（true|false）: ")
	if err != nil {
		return err
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("require_master_pw 必须是 true 或 false，实际 %q", raw)
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		if err := setPolicy(ctx, st, v); err != nil {
			return err
		}
		fmt.Fprintf(m.out, "require_master_pw 已设置为 %t\n", v)
		return nil
	})
}

// policyUpdateField 设置单个更新信息项（校验与写入复用 applyUpdateFlags）。
//
// 参数：label 为输入提示；field 取 "Source" / "AutoCheck" / "CheckInterval"。
func (m *menu) policyUpdateField(label, field string) error {
	raw, err := m.ask(label)
	if err != nil {
		return err
	}
	if raw == "" {
		return errors.New("取值不能为空")
	}
	var values updateFlagValues
	switch field {
	case "Source":
		values.Source = raw
	case "AutoCheck":
		values.AutoCheck = raw
	case "CheckInterval":
		values.CheckInterval = raw
	default:
		return fmt.Errorf("未知更新字段 %q", field)
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		return applyUpdateFlags(ctx, st, values)
	})
}

// policyQuotas 依次修改 items / bytes / devices 三项配额，空输入保持不变。
func (m *menu) policyQuotas() error {
	items, err := m.ask("max-items-per-user（回车不改，-1=不限制）: ")
	if err != nil {
		return err
	}
	maxBytes, err := m.ask("max-bytes-per-user（回车不改，支持 20MiB，-1=不限制）: ")
	if err != nil {
		return err
	}
	devices, err := m.ask("max-devices-per-user（回车不改，-1=不限制）: ")
	if err != nil {
		return err
	}
	if items == "" && maxBytes == "" && devices == "" {
		fmt.Fprintln(m.out, msgMenuNoQuotaChanged)
		return nil
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		apply := func(label, raw, key string) error {
			if raw == "" {
				return nil
			}
			v, err := parseQuotaValue(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
			if err := st.SetQuota(ctx, key, v); err != nil {
				return err
			}
			fmt.Fprintf(m.out, "%s 已设置为 %d\n", label, v)
			return nil
		}
		if err := apply("max-items-per-user", items, store.MetaKeyMaxItemsPerUser); err != nil {
			return err
		}
		if err := apply("max-bytes-per-user", maxBytes, store.MetaKeyMaxBytesPerUser); err != nil {
			return err
		}
		return apply("max-devices-per-user", devices, store.MetaKeyMaxDevicesPerUser)
	})
}

// updateMenu 是更新信息子菜单；任一操作完成后返回主菜单。
func (m *menu) updateMenu() error {
	for {
		fmt.Fprintf(m.out, "\n更新信息（db=%s）\n", m.dbPath)
		fmt.Fprintln(m.out, "  1) 查看")
		fmt.Fprintln(m.out, "  2) 写入 version_code + sha256 + version_name")
		fmt.Fprintln(m.out, "  0) 返回主菜单")
		raw, err := m.ask(menuAskBackHint)
		if err != nil {
			return err
		}
		choice, ok := parseChoice(raw, updateMenuLastChoice)
		if !ok {
			fmt.Fprintf(m.out, msgMenuInvalidChoice+"\n", raw, updateMenuLastChoice)
			continue
		}
		switch choice {
		case 0:
			return nil
		case 1:
			return m.updateView()
		case 2:
			return m.updateWrite()
		}
	}
}

// updateView 按 `update show` 的 key=value 口径展示更新信息。
func (m *menu) updateView() error {
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		info, err := st.UpdateInfo(ctx)
		if err != nil {
			return err
		}
		ttl, err := st.EnrollTTLSeconds(ctx)
		if err != nil {
			return err
		}
		printUpdateInfo(m.out, info, ttl)
		if !info.Configured {
			fmt.Fprintln(m.errOut, msgMenuUpdateNotConfig)
		}
		return nil
	})
}

// updateWrite 手动写入版本信息（校验与写入复用 applyUpdateFlags）。
func (m *menu) updateWrite() error {
	codeRaw, err := m.ask("version_code（正整数）: ")
	if err != nil {
		return err
	}
	code, err := strconv.ParseInt(codeRaw, 10, 64)
	if err != nil || code < minVersionCode {
		return fmt.Errorf("version_code 必须是正整数，实际 %q", codeRaw)
	}
	sha, err := m.ask("sha256（64 位十六进制）: ")
	if err != nil {
		return err
	}
	if !store.IsSHA256Hex(sha) {
		return fmt.Errorf("sha256 必须是 64 位十六进制，实际 %q", sha)
	}
	name, err := m.ask("version_name（如 0.3.2，可空）: ")
	if err != nil {
		return err
	}
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		return applyUpdateFlags(ctx, st, updateFlagValues{
			VersionCode: strconv.FormatInt(code, 10),
			SHA256:      sha,
			VersionName: name,
		})
	})
}

// maintenanceMenu 是维护子菜单；任一操作完成后返回主菜单。
func (m *menu) maintenanceMenu() error {
	for {
		fmt.Fprintf(m.out, "\n维护（db=%s）\n", m.dbPath)
		fmt.Fprintln(m.out, "  1) 物理删除墓碑 purge（先列清单，再确认）")
		fmt.Fprintln(m.out, "  2) 查看数据目录大小")
		fmt.Fprintln(m.out, "  0) 返回主菜单")
		raw, err := m.ask(menuAskBackHint)
		if err != nil {
			return err
		}
		choice, ok := parseChoice(raw, maintMenuLastChoice)
		if !ok {
			fmt.Fprintf(m.out, msgMenuInvalidChoice+"\n", raw, maintMenuLastChoice)
			continue
		}
		switch choice {
		case 0:
			return nil
		case 1:
			return m.purgeTombstones()
		case 2:
			return m.dataDirSize()
		}
	}
}

// purgeTombstones 先 dry-run 列出墓碑，输入 yes/y 后才物理删除。
func (m *menu) purgeTombstones() error {
	return m.withStore(func(ctx context.Context, st *store.Store) error {
		n, err := purgeList(ctx, st, m.out)
		if err != nil {
			return err
		}
		if n == 0 {
			fmt.Fprintln(m.out, msgNoTombstone)
			return nil
		}
		fmt.Fprintf(m.out, "合计：%d 条（未写库）\n", n)
		answer, err := m.ask("确认物理删除以上墓碑？" + menuConfirmHint)
		if err != nil {
			return err
		}
		if !parseConfirm(answer) {
			fmt.Fprintln(m.out, msgMenuCancelled)
			return nil
		}
		return purgeDeleteAllTo(ctx, st, m.out)
	})
}

// dataDirSize 统计数据库所在目录的大小。
func (m *menu) dataDirSize() error {
	dir := filepath.Dir(m.dbPath)
	size, files, err := dirUsage(dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(m.out, "数据目录: %s\n", dir)
	fmt.Fprintf(m.out, "大小: %s（%d 字节，%d 个文件）\n", formatBytes(size), size, files)
	return nil
}

// changeDBPath 修改本次会话使用的数据库路径（回车保持不变）。
func (m *menu) changeDBPath() error {
	raw, err := m.ask(fmt.Sprintf("新的数据库路径（回车保留 %s）: ", m.dbPath))
	if err != nil {
		return err
	}
	if raw == "" {
		fmt.Fprintln(m.out, msgMenuPathUnchanged)
		return nil
	}
	m.dbPath = raw
	fmt.Fprintf(m.out, "数据库路径已切换为 %s\n", m.dbPath)
	return nil
}

// dirUsage 统计目录下普通文件的总字节数与文件数；目录不存在时返回 0。
func dirUsage(dir string) (size int64, files int, err error) {
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	if !info.IsDir() {
		return info.Size(), 1, nil
	}
	err = filepath.WalkDir(dir, func(_ string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		fi, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		size += fi.Size()
		files++
		return nil
	})
	return size, files, err
}

// formatBytes 把字节数格式化为人类可读文本（按 1024 进制）。
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	value := float64(n)
	i := -1
	for value >= unit && i < len(units)-1 {
		value /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", value, units[i])
}
