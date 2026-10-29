// Command vkeyd 是 vkey 的零知识同步服务端。
//
// 子命令：
//
//	vkeyd init   --db <path> [--username default] [--master-key <base32>]
//	vkeyd serve  --db <path> --listen :8080 [--domain <域名>] [--artifacts-dir <dir>] [--set-require-master-pw=true|false]
//	vkeyd policy set --db <path> [--require-master-pw=<bool>] [--user-mode=single|admin]
//	                           [--max-items-per-user=<n>] [--max-bytes-per-user=<n|20MiB>] [--max-devices-per-user=<n>]
//	                           [--update-source=github|local] [--update-repo=<owner/repo>] [--update-asset=<file>]
//	                           [--update-version-code=<n>] [--update-version-name=<x.y.z>]
//	                           [--update-sha256=<hex>] [--update-size=<n>] [--update-notes=<text>]
//	                           [--update-auto-check=<bool>] [--update-check-interval=<seconds>]
//	vkeyd update show --db <path>
//	vkeyd user add <username> --db <path> [--ttl 30m] [--domain <域名>]
//	vkeyd user list --db <path>
//	vkeyd user disable|enable <username>|--id <id> --db <path>
//	vkeyd user delete <username>|--id <id> --db <path> [--yes]
//	vkeyd user revoke <code_id> --db <path>
//	vkeyd purge  --db <path> [--dry-run | --yes]
//
// purge 无开关且在终端里执行时进入交互式勾选，选择要物理删除的墓碑。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/api"
	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
	"xiaoqiong0v0.cn/vkey/server/internal/version"
)

// msgNoTombstone 是无待删条目时的统一提示。
const msgNoTombstone = "没有已逻辑删除的条目"

// main 是进程入口；失败时打印到 stderr 并以非 0 退出。
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "vkeyd: %v\n", err)
		os.Exit(1)
	}
}

// run 解析子命令并执行。
func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stderr)
		return errors.New("缺少子命令")
	}
	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "serve":
		return runServe(args[1:])
	case "policy":
		return runPolicy(args[1:])
	case "update":
		return runUpdate(args[1:])
	case "user":
		return runUser(args[1:])
	case "purge":
		return runPurge(args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("未知子命令 %q", args[0])
	}
}

// runInit 建库并创建账号。
//
// stdout 只输出一次 `master_key: <base32>`；其余信息一律走 stderr。
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	username := fs.String("username", "default", "账号名")
	masterKeyInput := fs.String("master-key", "", "base32 形式的 master_key（缺省随机生成）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" {
		return errors.New("init: 缺少 --db")
	}
	if *username == "" {
		return errors.New("init: --username 不能为空")
	}

	masterKey, err := resolveMasterKey(*masterKeyInput)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	verifier, err := crypto.Verifier(masterKey, *username)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	err = st.CreateUser(context.Background(), store.User{
		Username:        *username,
		Verifier:        verifier,
		RequireMasterPW: false,
		CreatedAt:       time.Now().Unix(),
	})
	if errors.Is(err, store.ErrExists) {
		return fmt.Errorf("init: 数据库已初始化（用户名 %q 已存在）", *username)
	}
	if err != nil {
		return err
	}

	// 唯一写入 stdout 的内容。
	fmt.Printf("master_key: %s\n", crypto.Base32Upper(masterKey))
	fmt.Fprintf(os.Stderr, "vkeyd: 已初始化 %s（用户 %s，策略 require_master_pw=false）\n", *dbPath, *username)
	fmt.Fprintf(os.Stderr, "vkeyd: master_key 只显示这一次，请立即离线保存；丢失将无法解密任何条目\n")
	return nil
}

// resolveMasterKey 解析或生成 master_key。
func resolveMasterKey(in string) ([]byte, error) {
	if in != "" {
		k, err := crypto.ParseMasterKey(in)
		if err != nil {
			return nil, fmt.Errorf("--master-key 非法: %w", err)
		}
		return k, nil
	}
	k, err := crypto.Random(crypto.KeyLen)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// runServe 启动 HTTP 服务（TLS 由外层 nginx 终止）。
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	listen := fs.String("listen", ":8080", "监听地址")
	domain := fs.String("domain", "", "对外域名（用于生成引导脚本；缺省按请求 Host 推导）")
	artifactsDir := fs.String("artifacts-dir", "./artifacts", "产物目录（只读；/dl/* 白名单来自其中的 SHA256SUMS）")
	setRequire := fs.String("set-require-master-pw", "", "启动时设置策略：true|false（缺省不修改）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" {
		return errors.New("serve: 缺少 --db")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	if *setRequire != "" {
		require, err := strconv.ParseBool(*setRequire)
		if err != nil {
			return fmt.Errorf("serve: --set-require-master-pw 必须是 true 或 false")
		}
		if err := setPolicy(context.Background(), st, require); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "vkeyd: 已设置 require_master_pw=%v\n", require)
	} else if _, err := st.FirstUser(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "vkeyd: 警告：数据库中尚无账号，请先执行 `vkeyd init --db %s`\n", *dbPath)
	}

	logger := log.New(os.Stderr, "vkeyd ", log.LstdFlags|log.LUTC)
	handler := api.New(st, api.Options{
		Domain:       *domain,
		Version:      version.Version,
		ArtifactsDir: *artifactsDir,
		Logger:       logger,
	}).Handler()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	fmt.Fprintf(os.Stderr, "vkeyd: 开始监听 %s（version=%s, domain=%q）\n", *listen, version.Version, *domain)

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: 监听失败: %w", err)
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "vkeyd: 收到退出信号，正在关闭")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// runPolicy 处理 `policy set` 子命令：可修改主密码策略、用户模式、每用户配额与 Android 更新信息。
//
// 至少给出一个策略开关；各项相互独立，未给出的保持不变。
func runPolicy(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("policy: 用法 `vkeyd policy set --db <path> [--require-master-pw=<bool>] [--user-mode=single|admin] [--max-items-per-user=<n>] [--max-bytes-per-user=<n>] [--max-devices-per-user=<n>] [--update-source=github|local] [--update-repo=<owner/repo>] [--update-asset=<file>] [--update-version-code=<n>] [--update-version-name=<x.y.z>]         [--update-sha256=<hex>] [--update-size=<n>] [--update-notes=<text>] [--update-auto-check=<bool>] [--update-check-interval=<seconds>]`")
	}
	fs := flag.NewFlagSet("policy set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	require := fs.String("require-master-pw", "", "是否强制主密码：true|false（可选）")
	userMode := fs.String("user-mode", "", "用户模式：single|admin（可选）")
	maxItems := fs.String("max-items-per-user", "", "每用户条目数配额；-1 表示不限制（可选）")
	maxBytes := fs.String("max-bytes-per-user", "", "每用户密文字节配额；支持 20MiB/K/M/G 后缀，-1 不限制（可选）")
	maxDevices := fs.String("max-devices-per-user", "", "每用户设备数配额；-1 表示不限制（可选）")
	var upd updateFlagValues
	fs.StringVar(&upd.Source, "update-source", "", "Android 更新来源：github|local（可选）")
	fs.StringVar(&upd.Repo, "update-repo", "", "GitHub 仓库 owner/repo（可选）")
	fs.StringVar(&upd.Asset, "update-asset", "", "APK 产物文件名（可选，缺省 vkey-android.apk）")
	fs.StringVar(&upd.VersionCode, "update-version-code", "", "Android versionCode（可选）")
	fs.StringVar(&upd.VersionName, "update-version-name", "", "Android versionName（可选）")
	fs.StringVar(&upd.SHA256, "update-sha256", "", "APK 的 sha256（64 位 hex，可选）")
	fs.StringVar(&upd.Size, "update-size", "", "APK 字节数（可选）")
	fs.StringVar(&upd.Notes, "update-notes", "", "发布说明（可选）")
	fs.StringVar(&upd.AutoCheck, "update-auto-check", "", "请求时惰性检查更新：true|false（可选）")
	fs.StringVar(&upd.CheckInterval, "update-check-interval", "", "惰性检查间隔（秒，0 表示每次请求都检查，可选）")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dbPath == "" {
		return errors.New("policy set: 缺少 --db")
	}
	if *require == "" && *userMode == "" && *maxItems == "" && *maxBytes == "" && *maxDevices == "" && upd.empty() {
		return errors.New("policy set: 至少给出一个策略开关")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	if *require != "" {
		v, err := strconv.ParseBool(*require)
		if err != nil {
			return errors.New("policy set: --require-master-pw 必须是 true 或 false")
		}
		if err := setPolicy(ctx, st, v); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "vkeyd: require_master_pw 已设置为 %v\n", v)
	}
	if *userMode != "" {
		if *userMode != policy.UserModeSingle && *userMode != policy.UserModeAdmin {
			return fmt.Errorf("policy set: --user-mode 必须是 %s 或 %s", policy.UserModeSingle, policy.UserModeAdmin)
		}
		if err := st.SetUserMode(ctx, *userMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "vkeyd: user_mode 已设置为 %s\n", *userMode)
	}
	quotas := []struct {
		name, value string
		key         string
	}{
		{"--max-items-per-user", *maxItems, store.MetaKeyMaxItemsPerUser},
		{"--max-bytes-per-user", *maxBytes, store.MetaKeyMaxBytesPerUser},
		{"--max-devices-per-user", *maxDevices, store.MetaKeyMaxDevicesPerUser},
	}
	for _, q := range quotas {
		if q.value == "" {
			continue
		}
		v, err := parseQuotaValue(q.value)
		if err != nil {
			return fmt.Errorf("policy set: %s %w", q.name, err)
		}
		if err := st.SetQuota(ctx, q.key, v); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "vkeyd: %s 已设置为 %d\n", q.name, v)
	}
	return applyUpdateFlags(ctx, st, upd)
}

// updateFlagValues 收集 `policy set` 的更新信息开关（空串表示未给出）。
type updateFlagValues struct {
	Source        string
	Repo          string
	Asset         string
	VersionCode   string
	VersionName   string
	SHA256        string
	Size          string
	Notes         string
	AutoCheck     string
	CheckInterval string
}

// empty 判断所有更新信息开关都未给出。
func (v updateFlagValues) empty() bool {
	return v.Source == "" && v.Repo == "" && v.Asset == "" && v.VersionCode == "" &&
		v.VersionName == "" && v.SHA256 == "" && v.Size == "" && v.Notes == "" &&
		v.AutoCheck == "" && v.CheckInterval == ""
}

// applyUpdateFlags 校验并写入更新信息；写入 version_code 或 sha256 时刷新发布时间。
//
// 返回：任一项校验失败时返回错误（此时之前已写入的项保留）。
func applyUpdateFlags(ctx context.Context, st *store.Store, v updateFlagValues) error {
	items := []struct {
		name  string
		key   string
		value string
	}{
		{"--update-source", store.MetaKeyUpdateSource, v.Source},
		{"--update-repo", store.MetaKeyUpdateRepo, v.Repo},
		{"--update-asset", store.MetaKeyUpdateAsset, v.Asset},
		{"--update-version-code", store.MetaKeyUpdateVersionCode, v.VersionCode},
		{"--update-version-name", store.MetaKeyUpdateVersionName, v.VersionName},
		{"--update-sha256", store.MetaKeyUpdateSHA256, v.SHA256},
		{"--update-size", store.MetaKeyUpdateSize, v.Size},
		{"--update-notes", store.MetaKeyUpdateNotes, v.Notes},
		{"--update-auto-check", store.MetaKeyUpdateAutoCheck, v.AutoCheck},
		{"--update-check-interval", store.MetaKeyUpdateCheckInterval, v.CheckInterval},
	}
	release := false
	for _, it := range items {
		if it.value == "" {
			continue
		}
		norm, err := normalizeUpdateValue(it.key, it.value)
		if err != nil {
			return fmt.Errorf("policy set: %s %w", it.name, err)
		}
		if err := st.SetMeta(ctx, it.key, norm); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "vkeyd: %s 已设置为 %s\n", strings.TrimPrefix(it.name, "--"), norm)
		if it.key == store.MetaKeyUpdateVersionCode || it.key == store.MetaKeyUpdateSHA256 {
			release = true
		}
	}
	if release {
		ts := time.Now().Unix()
		if err := st.SetUpdatePublishedAt(ctx, ts); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "vkeyd: update_published_at 已设置为 %d\n", ts)
	}
	return nil
}

// normalizeUpdateValue 按 meta 键校验并规范化单个更新信息取值。
func normalizeUpdateValue(key, value string) (string, error) {
	switch key {
	case store.MetaKeyUpdateSource:
		if value != store.UpdateSourceGitHub && value != store.UpdateSourceLocal {
			return "", fmt.Errorf("必须是 %s 或 %s", store.UpdateSourceGitHub, store.UpdateSourceLocal)
		}
		return value, nil
	case store.MetaKeyUpdateRepo:
		if !store.ValidUpdateRepo(value) {
			return "", fmt.Errorf("必须是 owner/repo 形式（字母数字与 . _ -），实际 %q", value)
		}
		return value, nil
	case store.MetaKeyUpdateAsset:
		if !validArtifactFileName(value) {
			return "", fmt.Errorf("必须是单段文件名（字母数字与 . _ -），实际 %q", value)
		}
		return value, nil
	case store.MetaKeyUpdateVersionCode, store.MetaKeyUpdateSize:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return "", fmt.Errorf("必须是不小于 0 的整数，实际 %q", value)
		}
		return strconv.FormatInt(n, 10), nil
	case store.MetaKeyUpdateSHA256:
		if !store.IsSHA256Hex(value) {
			return "", fmt.Errorf("必须是 64 位十六进制，实际 %q", value)
		}
		return strings.ToLower(value), nil
	case store.MetaKeyUpdateAutoCheck:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return "", fmt.Errorf("必须是 true 或 false，实际 %q", value)
		}
		return strconv.FormatBool(b), nil
	case store.MetaKeyUpdateCheckInterval:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return "", fmt.Errorf("必须是不小于 0 的整数（秒），实际 %q", value)
		}
		return strconv.FormatInt(n, 10), nil
	default:
		return value, nil
	}
}

// validArtifactFileName 判断产物文件名能否安全拼进 /dl/ 与 GitHub 下载地址。
func validArtifactFileName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "..") {
		return false
	}
	if strings.ContainsAny(name, "/\\ \t\r\n") {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// runUpdate 处理 `update show` 子命令：打印当前 Android 更新信息配置。
//
// stdout 为固定的 key=value 行（便于脚本解析），提示信息走 stderr。
func runUpdate(args []string) error {
	if len(args) == 0 || args[0] != "show" {
		return errors.New("update: 用法 `vkeyd update show --db <path>`")
	}
	fs := flag.NewFlagSet("update show", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dbPath == "" {
		return errors.New("update show: 缺少 --db")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	info, err := st.UpdateInfo(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("source=%s\nrepo=%s\nasset=%s\nversion_code=%d\nversion_name=%s\nsha256=%s\nsize=%d\nnotes=%s\npublished_at=%d\nconfigured=%t\nauto_check=%t\ncheck_interval=%d\nlast_checked_at=%d\nlast_check_error=%s\n",
		info.Source, info.Repo, info.Asset, info.VersionCode, info.VersionName,
		info.SHA256, info.Size, info.Notes, info.PublishedAt, info.Configured,
		info.AutoCheck, info.CheckInterval, info.LastCheckedAt, info.LastCheckError)
	if !info.Configured {
		fmt.Fprintln(os.Stderr, "vkeyd: 更新信息尚未配置完整（需要 version_code 与 sha256），GET /api/v1/update/android 返回 204")
	}
	return nil
}

// parseQuotaValue 解析配额取值：整数（含 -1=不限制），
// 或带 K/M/G/KiB/MiB/GiB/B 后缀的字节数（后缀按 1024 进制，20MiB 与 20M 等价）。
func parseQuotaValue(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("不能为空")
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	upper := strings.ToUpper(s)
	mult := int64(1)
	switch {
	case strings.HasSuffix(upper, "KIB"):
		mult, upper = 1<<10, strings.TrimSuffix(upper, "KIB")
	case strings.HasSuffix(upper, "MIB"):
		mult, upper = 1<<20, strings.TrimSuffix(upper, "MIB")
	case strings.HasSuffix(upper, "GIB"):
		mult, upper = 1<<30, strings.TrimSuffix(upper, "GIB")
	case strings.HasSuffix(upper, "K"):
		mult, upper = 1<<10, strings.TrimSuffix(upper, "K")
	case strings.HasSuffix(upper, "M"):
		mult, upper = 1<<20, strings.TrimSuffix(upper, "M")
	case strings.HasSuffix(upper, "G"):
		mult, upper = 1<<30, strings.TrimSuffix(upper, "G")
	case strings.HasSuffix(upper, "B"):
		upper = strings.TrimSuffix(upper, "B")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(upper), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("非法取值 %q（需为整数或如 20MiB 的字节数）", s)
	}
	return n * mult, nil
}

// setPolicy 把策略写入唯一账号。
func setPolicy(ctx context.Context, st *store.Store, require bool) error {
	u, err := st.FirstUser(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("数据库中尚无账号，请先执行 init")
	}
	if err != nil {
		return err
	}
	if err := st.SetRequireMasterPW(ctx, u.ID, require); err != nil {
		return err
	}
	return nil
}

// purgeMode 是 purge 子命令的执行模式。
type purgeMode int

const (
	// purgeModeList 只列清单（无终端且未给 --yes，无法交互）。
	purgeModeList purgeMode = iota
	// purgeModeDryRun 显式 --dry-run：只列清单。
	purgeModeDryRun
	// purgeModeInteractive 无开关且 stdin 是终端：交互式勾选后删除。
	purgeModeInteractive
	// purgeModeDelete --yes：直接删全部墓碑。
	purgeModeDelete
)

// runPurge 处理 `purge` 子命令：物理删除已逻辑删除的墓碑条目。
//
// 只允许在控制台/运维手动执行，不提供任何 HTTP 接口。
// 模式选择见 resolvePurgeMode：终端里无开关时为交互式勾选，
// 非终端无 --yes 时只列清单并提示加 --yes。
func runPurge(args []string) error {
	fs := flag.NewFlagSet("purge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	dryRun := fs.Bool("dry-run", false, "只列出待物理删除的墓碑，不写库")
	yes := fs.Bool("yes", false, "不交互，直接删除全部墓碑")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" {
		return errors.New("purge: 缺少 --db")
	}
	mode, note := resolvePurgeMode(*dryRun, *yes, isTerminal(os.Stdin))
	if note != "" {
		fmt.Fprintf(os.Stderr, "vkeyd: %s\n", note)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	switch mode {
	case purgeModeInteractive:
		return purgeInteractive(ctx, st, os.Stdin, os.Stdout)
	case purgeModeDelete:
		return purgeDeleteAll(ctx, st)
	case purgeModeList:
		return purgeDryRun(ctx, st, os.Stdout, true)
	default:
		return purgeDryRun(ctx, st, os.Stdout, false)
	}
}

// purgeDeleteAll 直接物理删除全部墓碑（--yes）。
func purgeDeleteAll(ctx context.Context, st *store.Store) error {
	n, err := st.Purge(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Printf("%s\n", msgNoTombstone)
		return nil
	}
	fmt.Printf("已物理删除 %d 条墓碑\n", n)
	return nil
}

// purgeDryRun 打印将被物理删除的墓碑清单，不写库。
//
// 参数：hintNoTTY 为 true 时追加「没有终端、请用 --yes」的提示。
func purgeDryRun(ctx context.Context, st *store.Store, w io.Writer, hintNoTTY bool) error {
	targets, err := st.PurgePending(ctx)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Fprintf(w, "%s\n", msgNoTombstone)
		return nil
	}
	fmt.Fprintf(w, "以下 %d 条墓碑将被物理删除（未写库）\n", len(targets))
	for _, t := range targets {
		fmt.Fprintf(w, "  user=%s id=%s kind=%s rp_id=%s deleted_at=%d version=%d\n",
			shortID(t.UserID), shortID(t.ID), t.Kind, t.RPID, t.DeletedAt, t.Version)
	}
	if hintNoTTY {
		fmt.Fprintf(w, "合计：%d 条\n", len(targets))
		fmt.Fprintf(w, "%s\n", msgPurgeNoTTY)
		return nil
	}
	fmt.Fprintf(w, "合计：%d 条（加 --yes 执行删除）\n", len(targets))
	return nil
}

// resolvePurgeMode 决定 purge 的执行模式。
//
// 参数：dryRun / yes 为命令行开关；isTTY 表示 stdin 是否连接终端。
// 返回：mode 为执行模式；note 为需要提示给用户的说明（无提示时为空）。
// 两个开关同时给出时以 --dry-run 为准（更安全）。
func resolvePurgeMode(dryRun, yes, isTTY bool) (mode purgeMode, note string) {
	if dryRun && yes {
		return purgeModeDryRun, "--dry-run 与 --yes 同时给出，以 --dry-run 为准（未写库）"
	}
	if dryRun {
		return purgeModeDryRun, ""
	}
	if yes {
		return purgeModeDelete, ""
	}
	if isTTY {
		return purgeModeInteractive, ""
	}
	return purgeModeList, ""
}

// shortID 返回用于展示的 id 前缀。
func shortID(id string) string {
	const n = 8
	if len(id) <= n {
		return id
	}
	return id[:n] + "…"
}

// usage 打印命令帮助。
func usage(w *os.File) {
	fmt.Fprint(w, `vkeyd — vkey 零知识同步服务端

用法：
  vkeyd init   --db <path> [--username default] [--master-key <base32>]
  vkeyd serve  --db <path> --listen :8080 [--domain <域名>] [--artifacts-dir <dir>] [--set-require-master-pw=true|false]
  vkeyd policy set --db <path> [--require-master-pw=<bool>] [--user-mode=single|admin]
                             [--max-items-per-user=<n>] [--max-bytes-per-user=<n|20MiB>] [--max-devices-per-user=<n>]
                             [--update-source=github|local] [--update-repo=<owner/repo>] [--update-asset=<file>]
                             [--update-version-code=<n>] [--update-version-name=<x.y.z>]
                             [--update-sha256=<hex>] [--update-size=<n>] [--update-notes=<text>]
                             [--update-auto-check=<bool>] [--update-check-interval=<seconds>]
  vkeyd update show --db <path>
   vkeyd user add <username> --db <path> [--ttl 30m] [--domain <域名>]
  vkeyd user list --db <path>
  vkeyd user disable|enable <username>|--id <id> --db <path>
  vkeyd user delete <username>|--id <id> --db <path> [--yes]
  vkeyd user revoke <code_id> --db <path>
  vkeyd purge  --db <path> [--dry-run | --yes]

说明：
  init   建库并创建账号，stdout 只打印一次 master_key（base32 无填充）
  serve  启动 HTTP 服务；TLS 由 nginx 终止
  policy 修改服务端策略（主密码、用户模式、每用户配额；-1 表示不限制）
         亦用于配置 Android 更新信息（--update-*，只写库、不访问网络）；
         写入 --update-version-code 或 --update-sha256 时同时刷新发布时间；
         --update-auto-check / --update-check-interval 控制服务端在请求到达时
         按 TTL 拉取 Release 资产 android.json（缺省 true / 86400 秒）
  update 查看 Android 更新信息配置（show）：stdout 为 key=value 行，
         configured=false 时 GET /api/v1/update/android 返回 204
  user   多用户运维（仅 user_mode=admin 生效）：
         add     签发一次性开户码（默认 30 分钟、单次使用），stdout 为
                  username=/code=/code_id=/expires_at=/join_url= 五行，便于脚本解析；
                  --domain 指定对外域名时 join_url 为完整链接（可直接发给对方），
                  否则为相对路径并提示补全；single 模式下直接拒绝
         list    列出账号（含设备/条目计数）与待用开户码
         disable 停用账号：其全部设备立即 401，数据保留；enable 恢复
         delete  级联删除 items/devices/pairs 等；不带 --yes 只打印将删除的行数
         revoke  撤销一条未使用的开户码
  purge  物理删除已逻辑删除的条目（墓碑）；仅控制台执行，无 HTTP 接口
         无开关且在终端里 → 交互勾选（空格选择、回车确认、y 删除）
         无开关且没有终端 → 只列清单，提示加 --yes
         加 --dry-run 只列清单；加 --yes 直接删除全部墓碑
         远端服务器需 ssh -t 才有终端，否则会退化为只列清单

退出码：0 成功；非 0 失败（错误信息输出到 stderr）。
`)
}
