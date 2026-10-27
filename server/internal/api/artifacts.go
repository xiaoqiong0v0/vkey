package api

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// defaultArtifactsDir 是 --artifacts-dir 缺省时的产物目录。
const defaultArtifactsDir = "./artifacts"

// manifestName 是产物清单文件名（固定，不允许被白名单之外的内容覆盖）。
const manifestName = "SHA256SUMS"

// artifactNamePattern 限制产物文件名：单段、仅字母数字与 . _ -。
//
// 该正则天然排除 "/"、"\" 与空白，从而阻断路径穿越；调用方仍会额外
// 拒绝 "."、".." 与包含 ".." 的名字。
var artifactNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// validArtifactName 判断文件名是否可安全拼接进产物目录。
func validArtifactName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	return artifactNamePattern.MatchString(name)
}

// parseSHA256SUMS 解析 `sha256sum` 格式清单，返回「文件名 → 小写 hash」。
//
// 无法解析或文件名非法的行会被忽略；白名单只来自这个清单。
func parseSHA256SUMS(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[1], "*")
		if !validArtifactName(name) {
			continue
		}
		out[name] = hash
	}
	return out
}

// readArtifactWhitelist 读取 <dir>/SHA256SUMS 并返回白名单。
func (s *Server) readArtifactWhitelist() (map[string]string, error) {
	dir := s.opts.ArtifactsDir
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return nil, err
	}
	return parseSHA256SUMS(data), nil
}

// handleArtifactNotFound 处理 /dl/ 下的空名与多段路径（统一 404）。
func (s *Server) handleArtifactNotFound(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
}

// hasDotSegmentOrBackslash 判断路径是否含 "." / ".." 段或反斜杠。
//
// 用于在 ServeMux 之前拦下 /dl/* 的路径穿越形态（ServeMux 会把
// /dl/../x 规范化成 301 重定向，而不是 404）。
func hasDotSegmentOrBackslash(p string) bool {
	if strings.Contains(p, `\`) {
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// handleArtifact 处理 GET /dl/{name}。
//
// 只有出现在 <dir>/SHA256SUMS 中的文件才可下载；清单本身固定可下载。
func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == manifestName {
		s.serveManifest(w)
		return
	}
	if !validArtifactName(name) {
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}

	whitelist, err := s.readArtifactWhitelist()
	if err != nil {
		// 目录或清单缺失：仅 /dl/* 受影响，其它接口照常工作。
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}
	if _, ok := whitelist[name]; !ok {
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}

	dir := filepath.Clean(s.opts.ArtifactsDir)
	path := filepath.Join(dir, name)
	if filepath.Dir(path) != dir {
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}

	// Lstat 拒绝符号链接，避免借白名单名字读到目录外文件。
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// serveManifest 返回 SHA256SUMS 原文。
func (s *Server) serveManifest(w http.ResponseWriter) {
	dir := s.opts.ArtifactsDir
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
