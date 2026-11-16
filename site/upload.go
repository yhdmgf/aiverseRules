package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxUploadSize   = 10 << 20 // 整包上限 10MB
	maxFileInZip    = 2 << 20  // 包内单文件上限 2MB
	uploadFormField = "file"
)

// handleUpload 接收插件 zip 包，校验后存入暂存目录并写入待审核元数据。
func (s *Store) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	ip := clientIP(r)
	if s.uploadRL.Blocked(ip) {
		writeErr(w, http.StatusTooManyRequests, "上传过于频繁，请稍后再试")
		return
	}

	// 用 http.MaxBytesReader 硬限制请求体大小（略高于整包上限，留出 multipart 开销）
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize+1<<20)
	if err := r.ParseMultipartForm(maxUploadSize + 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体过大或格式错误（整包上限 10MB）")
		return
	}

	// 可选的上传者标识（表单字段 uploader），未提供则记为 anonymous
	uploader := strings.TrimSpace(r.FormValue("uploader"))
	if uploader == "" {
		uploader = "anonymous"
	}

	file, header, err := r.FormFile(uploadFormField)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "缺少上传文件字段 file")
		return
	}
	defer file.Close()

	// 1) 上传文件扩展名必须是 .zip
	if !strings.EqualFold(filepath.Ext(header.Filename), ".zip") {
		s.uploadRL.Fail(ip)
		writeErr(w, http.StatusBadRequest, "只接受 .zip 插件包")
		return
	}
	if header.Size > maxUploadSize {
		s.uploadRL.Fail(ip)
		writeErr(w, http.StatusRequestEntityTooLarge, "整包超过 10MB 上限")
		return
	}

	// 2) 读入内存（上限内），既用于 zip 解析也用于计算哈希
	data, err := io.ReadAll(io.LimitReader(file, maxUploadSize+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取上传内容失败")
		return
	}
	if int64(len(data)) > maxUploadSize {
		s.uploadRL.Fail(ip)
		writeErr(w, http.StatusRequestEntityTooLarge, "整包超过 10MB 上限")
		return
	}

	// 3) 解析 zip 并做安全校验（Zip Slip / 黑名单扩展 / 单文件大小）
	manifest, err := validateZip(data)
	if err != nil {
		s.uploadRL.Fail(ip)
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("校验失败: %v", err))
		return
	}

	// 4) 计算包哈希并落地到暂存目录（文件名由 id+version 决定，防穿越）
	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])
	zipName := fmt.Sprintf("%s_%s.zip", manifest.ID, manifest.Version)
	destPath, ok := safeJoin(s.inbox, zipName)
	if !ok {
		writeErr(w, http.StatusBadRequest, "插件 id/version 生成的不安全路径")
		return
	}
	if err := atomicWrite(destPath, data, 0o644); err != nil {
		log.Printf("[错误] 保存上传包失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "保存文件失败")
		return
	}

	// 5) 写待审核元数据
	relPath, _ := filepath.Rel(s.cfg.DataDir, destPath)
	entry := &QueueEntry{
		ID:           manifest.ID,
		Name:         manifest.Name.Default,
		Version:      manifest.Version,
		Uploader:     uploader,
		UploadedAt:   time.Now(),
		PackagePath:  filepath.ToSlash(relPath),
		OrigFilename: header.Filename,
		SHA256:       shaHex,
		Status:       StatusPending,
		Size:         int64(len(data)),
	}
	if err := s.saveEntry(entry); err != nil {
		log.Printf("[错误] 写审核元数据失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "写入队列失败")
		return
	}

	s.uploadRL.Success(ip)
	log.Printf("[信息] 收到插件包 %s v%s（来自 %s，%d 字节）", manifest.ID, manifest.Version, ip, len(data))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"id":      manifest.ID,
		"version": manifest.Version,
		"message": "上传成功，已进入待审核队列",
	})
}

// validateZip 校验 zip 包内容安全，并从根 plugin.json 解析出 Manifest。
// 任一条目违反规则即返回错误（不落地文件）。
func validateZip(data []byte) (*Manifest, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("不是合法的 zip 包: %w", err)
	}
	if len(zr.File) == 0 {
		return nil, fmt.Errorf("zip 包为空")
	}

	var manifestData []byte
	var totalUncompressed int64

	for _, f := range zr.File {
		name := f.Name

		// —— Zip Slip 防护：拒绝绝对路径、..、盘符、反斜杠 ——
		if err := checkZipEntryName(name); err != nil {
			return nil, err
		}

		// —— 危险扩展名黑名单 ——
		if extBlocked(name) {
			return nil, fmt.Errorf("包内包含禁止的可执行/脚本文件: %s", name)
		}

		// —— 目录条目跳过大小统计 ——
		if f.FileInfo().IsDir() {
			continue
		}

		// —— 单文件与整包解压后大小限制 ——
		if f.UncompressedSize64 > maxFileInZip {
			return nil, fmt.Errorf("包内单文件超过 2MB 上限: %s", name)
		}
		totalUncompressed += int64(f.UncompressedSize64)
		if totalUncompressed > maxUploadSize {
			return nil, fmt.Errorf("包解压后总大小超过 10MB 上限")
		}

		// —— 根目录 plugin.json ——
		if isRootPluginJSON(name) {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("读取 plugin.json 失败: %w", err)
			}
			content, err := io.ReadAll(io.LimitReader(rc, maxFileInZip+1))
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("读取 plugin.json 失败: %w", err)
			}
			if int64(len(content)) > maxFileInZip {
				return nil, fmt.Errorf("plugin.json 超过 2MB 上限")
			}
			manifestData = content
		}
	}

	if manifestData == nil {
		return nil, fmt.Errorf("缺少包根 plugin.json")
	}

	var m Manifest
	// 不使用 DisallowUnknownFields：真实 plugin.json 可能含有商店不关心的额外字段，
	// 过于严格会误拒合法插件；只校验关心的关键。
	dec := json.NewDecoder(bytes.NewReader(manifestData))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("plugin.json 解析失败: %w", err)
	}
	if err := validateManifest(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// checkZipEntryName 校验单个 zip 条目名，防 Zip Slip 路径穿越。
func checkZipEntryName(name string) error {
	if name == "" {
		return fmt.Errorf("存在空路径条目")
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("拒绝绝对路径条目: %s", name)
	}
	if strings.Contains(name, "\\") {
		return fmt.Errorf("拒绝包含反斜杠的路径条目: %s", name)
	}
	// 拒绝 Windows 盘符（如 C:\ 或 C:/）
	if len(name) >= 2 && name[1] == ':' {
		return fmt.Errorf("拒绝盘符路径条目: %s", name)
	}
	// 按段检查：任何一段为 .. 即视为穿越攻击
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return fmt.Errorf("拒绝包含 .. 的路径条目: %s", name)
		}
	}
	// 用 path.Clean 兜底：清理后若变成以 ../ 开头说明原路径试图逃逸
	if cleaned := path.Clean(name); cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("拒绝路径穿越条目: %s", name)
	}
	// 拒绝 Windows 保留设备名
	base := strings.ToUpper(path.Base(name))
	for _, dev := range []string{"CON", "PRN", "AUX", "NUL"} {
		if base == dev || strings.HasPrefix(base, dev+".") {
			return fmt.Errorf("拒绝保留设备名条目: %s", name)
		}
	}
	return nil
}

// isRootPluginJSON 判断条目是否为包根的 plugin.json（不含目录前缀）。
func isRootPluginJSON(name string) bool {
	return name == "plugin.json" || name == "./plugin.json"
}
