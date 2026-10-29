package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// testUpdateSHA256 是测试用 APK 摘要（64 位小写 hex）。
const testUpdateSHA256 = "3f786850e387550fdab836ed7e6dc881de23001b2b0f4d1ad1e0c1e7b6d4b3f0"

// openUpdateCLIStore 打开（必要时新建）临时库并注册清理。
func openUpdateCLIStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// runCapture 运行 CLI 函数并捕获其 stdout/stderr。
func runCapture(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建管道失败: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建管道失败: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	runErr := fn()
	_ = outW.Close()
	_ = errW.Close()
	out, _ := io.ReadAll(outR)
	errOut, _ := io.ReadAll(errR)
	_ = outR.Close()
	_ = errR.Close()
	return string(out), string(errOut), runErr
}

// TestPolicySetUpdateFlags 验证 `policy set --update-*` 写库后能被 Store.UpdateInfo 读到。
func TestPolicySetUpdateFlags(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "update-cli.db")

	_, _, err := runCapture(t, func() error {
		return runPolicy([]string{"set", "--db", dbPath,
			"--update-source=local",
			"--update-repo=owner/repo",
			"--update-asset=vkey-android.apk",
			"--update-version-code=30101",
			"--update-version-name=0.3.2",
			"--update-sha256=" + strings.ToUpper(testUpdateSHA256),
			"--update-size=8388608",
			"--update-notes=首个公开版本",
		})
	})
	if err != nil {
		t.Fatalf("policy set --update-* 失败: %v", err)
	}

	info, err := openUpdateCLIStore(t, dbPath).UpdateInfo(context.Background())
	if err != nil {
		t.Fatalf("UpdateInfo: %v", err)
	}
	if info.Source != store.UpdateSourceLocal || info.Repo != "owner/repo" || info.Asset != "vkey-android.apk" {
		t.Fatalf("来源/仓库/产物不匹配: %+v", info)
	}
	if info.VersionCode != 30101 || info.VersionName != "0.3.2" {
		t.Fatalf("版本字段不匹配: %+v", info)
	}
	// sha256 由 CLI 规范化为小写。
	if info.SHA256 != testUpdateSHA256 {
		t.Fatalf("sha256 = %q，期望小写规范化后的 %q", info.SHA256, testUpdateSHA256)
	}
	if info.Size != 8388608 || info.Notes != "首个公开版本" {
		t.Fatalf("产物字段不匹配: %+v", info)
	}
	if !info.Configured {
		t.Fatal("version_code 与 sha256 都已写入，Configured 应为 true")
	}
	if info.PublishedAt <= 0 {
		t.Fatalf("写入 version_code/sha256 时应刷新发布时间，实际 %d", info.PublishedAt)
	}
}

// TestUpdateShowOutput 验证 `update show` 输出为 key=value 且含 configured=。
func TestUpdateShowOutput(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "update-show.db")
	openUpdateCLIStore(t, dbPath) // 建空库

	out, _, err := runCapture(t, func() error {
		return runUpdate([]string{"show", "--db", dbPath})
	})
	if err != nil {
		t.Fatalf("update show 失败: %v", err)
	}
	if !strings.Contains(out, "configured=false") {
		t.Fatalf("未配置时输出应含 configured=false：\n%s", out)
	}

	_, _, err = runCapture(t, func() error {
		return runPolicy([]string{"set", "--db", dbPath,
			"--update-version-code=30101",
			"--update-sha256=" + testUpdateSHA256,
		})
	})
	if err != nil {
		t.Fatalf("policy set --update-* 失败: %v", err)
	}

	out, _, err = runCapture(t, func() error {
		return runUpdate([]string{"show", "--db", dbPath})
	})
	if err != nil {
		t.Fatalf("update show 失败: %v", err)
	}
	for _, want := range []string{"configured=true", "version_code=30101", "sha256=" + testUpdateSHA256} {
		if !strings.Contains(out, want) {
			t.Fatalf("输出缺少 %q：\n%s", want, out)
		}
	}
}
