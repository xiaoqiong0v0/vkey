// Command vkeyd 是 vkey 的零知识同步服务端。
//
// 子命令：
//
//	vkeyd init   --db <path> [--username default] [--master-key <base32>]
//	vkeyd serve  --db <path> --listen :8080 [--domain <域名>] [--artifacts-dir <dir>] [--set-require-master-pw=true|false]
//	vkeyd policy set --db <path> --require-master-pw=<bool>
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/api"
	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
	"xiaoqiong0v0.cn/vkey/server/internal/version"
)

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

// runPolicy 处理 `policy set` 子命令。
func runPolicy(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("policy: 用法 `vkeyd policy set --db <path> --require-master-pw=<bool>`")
	}
	fs := flag.NewFlagSet("policy set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dbPath := fs.String("db", "", "sqlite 数据库路径（必填）")
	require := fs.String("require-master-pw", "", "是否强制主密码：true|false（必填）")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dbPath == "" {
		return errors.New("policy set: 缺少 --db")
	}
	if *require == "" {
		return errors.New("policy set: 缺少 --require-master-pw")
	}
	v, err := strconv.ParseBool(*require)
	if err != nil {
		return errors.New("policy set: --require-master-pw 必须是 true 或 false")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := setPolicy(context.Background(), st, v); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "vkeyd: require_master_pw 已设置为 %v\n", v)
	return nil
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

// usage 打印命令帮助。
func usage(w *os.File) {
	fmt.Fprint(w, `vkeyd — vkey 零知识同步服务端

用法：
  vkeyd init   --db <path> [--username default] [--master-key <base32>]
  vkeyd serve  --db <path> --listen :8080 [--domain <域名>] [--artifacts-dir <dir>] [--set-require-master-pw=true|false]
  vkeyd policy set --db <path> --require-master-pw=<bool>

说明：
  init   建库并创建账号，stdout 只打印一次 master_key（base32 无填充）
  serve  启动 HTTP 服务；TLS 由 nginx 终止
  policy 修改服务端策略（是否强制主密码）

退出码：0 成功；非 0 失败（错误信息输出到 stderr）。
`)
}
