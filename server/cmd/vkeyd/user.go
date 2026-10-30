package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// 本文件实现 `vkeyd user ...` 子命令（多用户/admin 模式的运维入口）：
//
//	vkeyd user add <username> [--db <path>] [--ttl 30m] [--domain <域名>]
//	vkeyd user list [--db <path>]
//	vkeyd user disable <username>|--id <id> [--db <path>]
//	vkeyd user enable  <username>|--id <id> [--db <path>]
//	vkeyd user delete  <username>|--id <id> [--db <path>] [--yes]
//	vkeyd user revoke  <code_id> [--db <path>]
//
// 开户码有效期默认取 meta 键 enroll.ttl_seconds（未配置时回落
// policy.EnrollTTLSeconds）；显式给出 --ttl 时以命令行为准。
//
// 约定：stdout 只输出结果行（key=value，便于脚本解析），提示一律走 stderr；
// 开户码明文只在 `user add` 的 stdout 出现一次，不进日志。

// runUser 是 `user` 子命令的分发入口。
func runUser(args []string) error {
	if len(args) == 0 {
		return errors.New("user: 用法 `vkeyd user add|list|disable|enable|delete|revoke ...`（见 vkeyd help）")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return runUserAdd(rest)
	case "list", "ls":
		return runUserList(rest)
	case "disable":
		return runUserToggle(rest, true)
	case "enable":
		return runUserToggle(rest, false)
	case "delete":
		return runUserDelete(rest)
	case "revoke":
		return runUserRevoke(rest)
	default:
		return fmt.Errorf("user: 未知子命令 %q", sub)
	}
}

// newUserFlagSet 构造统一风格的 flag.FlagSet（错误提示走 stderr）。
func newUserFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// splitUserArgs 把「位置参数在前、开关在后」的写法拆开：
// Go 的 flag 包遇到第一个非 flag 参数即停止解析，而契约要求
// `vkeyd user add <username> [--db <path>] [--ttl 30m]` 这种顺序。
//
// 参数：valueFlags 声明哪些开关带独立取值（`--k=v` 形式无需声明）。
// 返回：(可供 flag.Parse 的开关串, 位置参数列表)。
func splitUserArgs(args []string, valueFlags map[string]bool) ([]string, []string) {
	flags := make([]string, 0, len(args))
	positional := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			continue // --k=v 自带取值
		}
		if valueFlags[name] && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return flags, positional
}

// openUserStore 打开 --db 指向的库；缺参数时给出统一错误。
func openUserStore(cmdName, dbPath string) (*store.Store, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("%s: 缺少 --db", cmdName)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// validateCLIUsername 校验开户用户名：非空、无空白字符、长度受协议约束。
func validateCLIUsername(username string) error {
	if username == "" {
		return errors.New("用户名不能为空")
	}
	if strings.ContainsAny(username, " \t\r\n") {
		return errors.New("用户名不能包含空白字符")
	}
	if len(username) > policy.MaxUsernameBytes {
		return fmt.Errorf("用户名超过 %d 字节", policy.MaxUsernameBytes)
	}
	return nil
}

// runUserAdd 处理 `user add`：admin 模式下签发一次性开户码。
func runUserAdd(args []string) error {
	fs := newUserFlagSet("user add")
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	ttl := fs.Duration("ttl", 0, "开户码有效期（Go duration；缺省取 enroll.ttl_seconds，未配置时 30m）")
	domain := fs.String("domain", "", "对外域名（生成开户链接用，与 `serve --domain` 同源；缺省输出相对路径）")
	flagArgs, positional := splitUserArgs(args, map[string]bool{"db": true, "ttl": true, "domain": true})
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("user add: 用法 `vkeyd user add <username> [--db <path>] [--ttl 30m] [--domain <域名>]`")
	}
	username := positional[0]
	if err := validateCLIUsername(username); err != nil {
		return fmt.Errorf("user add: %w", err)
	}
	// 显式给出 --ttl 时以命令行为准；未给出则取服务端配置。
	ttlSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "ttl" {
			ttlSet = true
		}
	})
	if ttlSet && *ttl <= 0 {
		return errors.New("user add: --ttl 必须为正数")
	}

	st, err := openUserStore("user add", *dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	effectiveTTL, err := resolveEnrollTTL(ctx, st, *ttl, ttlSet)
	if err != nil {
		return err
	}
	if err := userAddRun(ctx, st, username, *domain, effectiveTTL, time.Now(), os.Stdout, os.Stderr); err != nil {
		return err
	}
	return nil
}

// resolveEnrollTTL 决定本次签发的开户码有效期。
//
// 优先级：显式 --ttl > meta 键 enroll.ttl_seconds > policy.EnrollTTLSeconds。
func resolveEnrollTTL(ctx context.Context, st *store.Store, ttl time.Duration, explicit bool) (time.Duration, error) {
	if explicit {
		return ttl, nil
	}
	secs, err := st.EnrollTTLSeconds(ctx)
	if err != nil {
		return 0, fmt.Errorf("user add: 读取开户码默认有效期失败: %w", err)
	}
	return time.Duration(secs) * time.Second, nil
}

// userAddRun 执行开户码签发并写出结果（out 为 stdout 形态，hint 为 stderr 提示）。
//
// 与 runUserAdd 分离以便测试注入 writer；single 模式在此直接拒绝。
// domain 为对外域名（可带 scheme），空值时 join_url 退化为相对路径并给出提示。
func userAddRun(ctx context.Context, st *store.Store, username, domain string, ttl time.Duration, now time.Time, out, hint io.Writer) error {
	mode, err := st.UserMode(ctx)
	if err != nil {
		return fmt.Errorf("user add: 读取用户模式失败: %w", err)
	}
	if mode != policy.UserModeAdmin {
		return fmt.Errorf("user add: 当前为 %s 模式，不能开户；请先执行 `vkeyd policy set --db <path> --user-mode admin` 切换到 admin 模式", mode)
	}

	code, plain, err := st.CreateEnrollCode(ctx, username, int64(ttl.Seconds()), now.Unix())
	if err != nil {
		return fmt.Errorf("user add: %w", err)
	}

	// stdout 固定 key=value 五行，顺序稳定、便于脚本解析。
	fmt.Fprintf(out, "username=%s\n", username)
	fmt.Fprintf(out, "code=%s\n", plain)
	fmt.Fprintf(out, "code_id=%s\n", code.ID)
	fmt.Fprintf(out, "expires_at=%d\n", code.ExpiresAt)
	fmt.Fprintf(out, "join_url=%s\n", joinURL(domain, plain))
	if strings.TrimSpace(domain) == "" {
		fmt.Fprintf(hint, "vkeyd: 未指定 --domain，join_url 为相对路径；发给他人的完整链接 = 服务器域名 + join_url"+
			"（也可加 --domain <域名> 重新执行，口径与 `serve --domain` 一致）\n")
	}

	// 等价调用示例（本轮不生成网页；客户端也可直接用 code 走 API）。
	fmt.Fprintf(hint, "vkeyd: 开户码有效期 %s、单次使用；撤销：vkeyd user revoke --db <path> %s\n", ttl, code.ID)
	fmt.Fprintf(hint, "vkeyd: 等价 URL 调用（master_key 由客户端本地生成，verifier=HKDF(master_key,\"%s\")，服务端永不接触 master_key）：\n", username)
	fmt.Fprintf(hint, "  curl -X POST https://<server>/api/v1/auth/enroll -H 'Content-Type: application/json' \\\n    -d '{\"code\":\"%s\",\"username\":\"%s\",\"verifier\":\"<base64url(32B)>\",\"device\":{\"name\":\"<设备名>\",\"platform\":\"<android|linux>\",\"pubkey\":\"<base64url(32B)>'}}'\n",
		plain, username)
	return nil
}

// runUserList 处理 `user list`：列出全部账号与待用开户码。
func runUserList(args []string) error {
	fs := newUserFlagSet("user list")
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openUserStore("user list", *dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	return userListRun(ctx, st, os.Stdout)
}

// userListRun 写出账号与开户码清单（stdout，每行一类 key=value）。
func userListRun(ctx context.Context, st *store.Store, out io.Writer) error {
	users, err := st.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("user list: %w", err)
	}
	if len(users) == 0 {
		fmt.Fprintln(out, "（库中尚无账号）")
	}
	for _, u := range users {
		status := "active"
		if u.DisabledAt != 0 {
			status = "disabled"
		}
		fmt.Fprintf(out, "user id=%s username=%s created_at=%d devices=%d items=%d status=%s\n",
			u.ID, u.Username, u.CreatedAt, u.Devices, u.Items, status)
	}

	codes, err := st.ListPendingEnrollCodes(ctx)
	if err != nil {
		return fmt.Errorf("user list: %w", err)
	}
	for _, c := range codes {
		bound := c.Username
		if bound == "" {
			bound = "-"
		}
		fmt.Fprintf(out, "pending_code id=%s username=%s expires_at=%d\n", c.ID, bound, c.ExpiresAt)
	}
	if len(codes) == 0 {
		fmt.Fprintln(out, "（无待用开户码）")
	}
	return nil
}

// runUserToggle 处理 `user disable|enable`：切换账号停用标记（数据保留）。
func runUserToggle(args []string, disable bool) error {
	action := "enable"
	if disable {
		action = "disable"
	}
	fs := newUserFlagSet("user " + action)
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	idFlag := fs.String("id", "", "按账号 id 指定（与 <username> 二选一）")
	flagArgs, positional := splitUserArgs(args, map[string]bool{"db": true, "id": true})
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	st, err := openUserStore("user "+action, *dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	u, err := resolveUserRef(ctx, st, "user "+action, *idFlag, positional)
	if err != nil {
		return err
	}
	disabledAt := int64(0)
	if disable {
		disabledAt = time.Now().Unix()
	}
	if err := st.SetUserDisabled(ctx, u.ID, disabledAt); err != nil {
		return fmt.Errorf("user %s: %w", action, err)
	}
	status := "enabled"
	if disable {
		status = "disabled"
	}
	fmt.Printf("user id=%s username=%s status=%s\n", u.ID, u.Username, status)
	if disable {
		fmt.Fprintf(os.Stderr, "vkeyd: 该用户全部设备立即返回 401；数据保留，`vkeyd user enable` 可恢复\n")
	}
	return nil
}

// runUserDelete 处理 `user delete`：级联删除（无 --yes 时只打印将删除的行数）。
func runUserDelete(args []string) error {
	fs := newUserFlagSet("user delete")
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	idFlag := fs.String("id", "", "按账号 id 指定（与 <username> 二选一）")
	yes := fs.Bool("yes", false, "确认执行不可逆的级联删除")
	flagArgs, positional := splitUserArgs(args, map[string]bool{"db": true, "id": true})
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	st, err := openUserStore("user delete", *dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	u, err := resolveUserRef(ctx, st, "user delete", *idFlag, positional)
	if err != nil {
		return err
	}

	if !*yes {
		// dry-run：只统计、不删除；必须二次确认后才动数据。
		usage, err := st.DeleteUserPreview(ctx, u.ID)
		if err != nil {
			return fmt.Errorf("user delete: %w", err)
		}
		return userDeleteDryRun(os.Stdout, os.Stderr, usage)
	}

	usage, err := st.DeleteUserCascade(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("user delete: %w", err)
	}
	fmt.Printf("deleted user id=%s username=%s items=%d conflicts=%d devices=%d pairs=%d audits=%d enroll_codes=%d\n",
		usage.UserID, usage.Username, usage.Items, usage.Conflicts, usage.Devices, usage.Pairs, usage.Audits, usage.Codes)
	return nil
}

// userDeleteDryRun 打印「将删除什么」但不写库（stdout 计数 + stderr 确认提示）。
func userDeleteDryRun(out, hint io.Writer, usage *store.UserUsage) error {
	fmt.Fprintf(out, "user id=%s username=%s created_at=%d status=%s\n",
		usage.UserID, usage.Username, usage.CreatedAt, userStatus(usage.DisabledAt))
	fmt.Fprintf(out, "will_delete items=%d conflicts=%d devices=%d pairs=%d audits=%d enroll_codes=%d\n",
		usage.Items, usage.Conflicts, usage.Devices, usage.Pairs, usage.Audits, usage.Codes)
	fmt.Fprintf(hint, "vkeyd: 未做任何修改。级联删除不可逆，确认无误后加 --yes 重新执行\n")
	return nil
}

// userStatus 把 disabled_at 折算成展示状态。
func userStatus(disabledAt int64) string {
	if disabledAt != 0 {
		return "disabled"
	}
	return "active"
}

// runUserRevoke 处理 `user revoke <code_id>`：撤销一条未使用的开户码。
func runUserRevoke(args []string) error {
	fs := newUserFlagSet("user revoke")
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	flagArgs, positional := splitUserArgs(args, map[string]bool{"db": true})
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("user revoke: 用法 `vkeyd user revoke <code_id> [--db <path>]`")
	}
	st, err := openUserStore("user revoke", *dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	codeID := positional[0]
	if err := st.RevokeEnrollCode(ctx, codeID, time.Now().Unix()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("user revoke: 开户码不存在、已使用或已撤销（id=%s）", codeID)
		}
		return fmt.Errorf("user revoke: %w", err)
	}
	fmt.Printf("revoked code_id=%s\n", codeID)
	return nil
}

// joinURL 拼接开户落地页链接。
//
// domain 空 → 相对路径 `/join?c=<CODE>`（由调用方另行提示补全域名）；
// 不含 scheme 时默认 https，末尾 `/` 去掉——与 `serve --domain` 的取值口径一致。
func joinURL(domain, plain string) string {
	d := strings.TrimSpace(domain)
	if d == "" {
		return "/join?c=" + plain
	}
	if !strings.Contains(d, "://") {
		d = "https://" + d
	}
	return strings.TrimRight(d, "/") + "/join?c=" + plain
}

// resolveUserRef 按 `--id <id>` 或位置参数 `<username>` 定位账号（二者必居其一）。
func resolveUserRef(ctx context.Context, st *store.Store, cmd, idFlag string, positional []string) (*store.User, error) {
	if idFlag != "" && len(positional) > 0 {
		return nil, fmt.Errorf("%s: --id 与 <username> 只能二选一", cmd)
	}
	if idFlag != "" {
		u, err := st.UserByID(ctx, idFlag)
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%s: 账号不存在（id=%s）", cmd, idFlag)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", cmd, err)
		}
		return u, nil
	}
	if len(positional) != 1 {
		return nil, fmt.Errorf("%s: 缺少 <username> 或 --id", cmd)
	}
	u, err := st.UserByUsername(ctx, positional[0])
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%s: 账号不存在（username=%s）", cmd, positional[0])
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cmd, err)
	}
	return u, nil
}
