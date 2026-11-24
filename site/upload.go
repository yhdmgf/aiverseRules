package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxUploadSize   = 10 << 20 // 整包上限 10MB
	maxFileInZip    = 2 << 20  // 包内单文件上限 2MB
	uploadFormField = "file"

	// anonymousUploader 是 uploader 缺失时的兜底署名（隐秘英文默认名），
	// 与审核后台前端未填署名时显示的 anonymous 保持一致。
	anonymousUploader = "anonymous"
)

// handleUpload 接收插件 zip 包，校验后存入暂存目录并写入待审核元数据。
//
// 命名策略（自动整理）：上传文件名不再要求特定格式，后台一律以包内 plugin.json 为唯一权威
// 取 id / version / author，落地时自动按 {id}_{version}.zip 重新命名归档。
// 这样任何文件名（如 dafeiyu-pet_2.5.2.zip）都不会再触发“文件名格式不合法 / 与 plugin.json 不一致”等报错。
func (s *Store) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	// 访问控制：已登录管理员（后台 /admin 上传）直接放行；否则要求开发者上传令牌。
	// 这样后台原有的管理员上传不受影响（跟登录同一套密钥），令牌仅作为未登录开发者的可选通道。
	isAdmin := false
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if _, ok := s.sessions.Get(c.Value); ok {
			isAdmin = true
		}
	}
	if !isAdmin {
		// 带正确上传令牌的可信开发者：视为可信（跳过保留字等校验，只大小/格式限制）。
		// 无令牌或令牌错误：不拒绝，作为普通用户上传，走完整 API 校验（保留字、zip、内容安全）。
		// 令牌仅用于区分信任级别，不是上传的硬门槛。
		tok := r.Header.Get("X-Upload-Token")
		if s.cfg.UploadToken != "" && safeEqual(tok, s.cfg.UploadToken) {
			isAdmin = true
		}
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

	// 上传者标识（表单字段 uploader）：可选。缺失时按“表单 → plugin.json 的 author → anonymous”兜底。
	formUploader := strings.TrimSpace(r.FormValue("uploader"))

	file, header, err := r.FormFile(uploadFormField)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "缺少上传文件字段 file")
		return
	}
	defer file.Close()

	// 1) 上传文件扩展名必须是 .zip（仅此一项文件名硬要求，其余命名后台自动整理）
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

	// 3) 解析 zip 并做安全校验（Zip Slip / 黑名单扩展 / 单文件大小），同时取出 plugin.json
	manifest, err := validateZip(data, isAdmin)
	if err != nil {
		s.uploadRL.Fail(ip)
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("校验失败: %v", err))
		return
	}

	// 3.1) 后台自动整理：以 plugin.json 为权威决定归档 id / version / author，
	// 不再校验上传文件名，任何文件名都能上传。
	pluginID := manifest.ID
	pluginVersion := manifest.Version

	// 3.2) 上传者署名：显式（表单）优先；否则兜底 plugin.json 的 author，再兜底 anonymous。
	// 仅当用户显式署名时才做所有者/作者一致性校验，未署名不拦截，保证“没填也能上传”。
	explicitUploader := formUploader
	uploader := explicitUploader
	if uploader == "" {
		if a := strings.TrimSpace(manifest.Author); a != "" {
			uploader = a
		}
	}
	if uploader == "" {
		uploader = anonymousUploader
	}

	// 3.55) 所有者校验：仅当用户显式署名时才校验，避免匿名兜底误伤正常上传。
	// 插件已登记所有者时，非管理员的署名必须匹配。
	if !isAdmin && explicitUploader != "" {
		if err := s.checkPluginOwner(pluginID, explicitUploader); err != nil {
			s.uploadRL.Fail(ip)
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
	}

	// 3.56) 作者名一致性校验：plugin.json 里的 author 必须和显式上传者署名一致。
	// 仅在用户显式署名时校验；未署名（兜底）时跳过，保证“没填也能上传”。
	// 管理员豁免此校验（可以上传任何插件）。
	if !isAdmin && explicitUploader != "" {
		manifestAuthor := strings.TrimSpace(manifest.Author)
		if manifestAuthor == "" {
			s.uploadRL.Fail(ip)
			writeErr(w, http.StatusBadRequest, "plugin.json 缺少 author 字段，请填写作者名")
			return
		}
		if manifestAuthor != explicitUploader {
			s.uploadRL.Fail(ip)
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("plugin.json 里的 author（%s）与上传时填写的作者名（%s）不一致，请输入正确的作者", manifestAuthor, explicitUploader))
			return
		}
	}

	// 3.6) 同 id + 同版本是否“已发布”以远程 index.json 为准，而非本地队列状态。
	// 下架（unpublish）只删远程 index 条目 + packages 包，不回退本地队列的 approved 标记，
	// 若据此判定会误拦“下架后重新上传同版本”。故此处直接查远程；远程不可用（未配置 GitHub /
	// 网络/限流失败）时才回退到本地队列状态，保证无 GitHub 环境仍可用。
	publishedRemotely, remoteErr := s.versionPublishedRemotely(r.Context(), pluginID, pluginVersion)
	if remoteErr == nil {
		// 远程权威：同 id + 同版本仍在远程 index 里才算重复。
		if publishedRemotely {
			s.uploadRL.Fail(ip)
			writeErr(w, http.StatusConflict, fmt.Sprintf("插件 %s v%s 已发布，请更新版本号后再上传", pluginID, pluginVersion))
			return
		}
	} else {
		// 远程不可用，回退本地队列（仅作降级，不作为权威）。
		if prev, _ := s.getEntry(pluginID); prev != nil && prev.Status == StatusApproved && prev.Version == pluginVersion {
			s.uploadRL.Fail(ip)
			writeErr(w, http.StatusConflict, fmt.Sprintf("插件 %s v%s 已发布，请更新版本号后再上传", pluginID, pluginVersion))
			return
		}
	}

	// 是否为“更新”（同 id 不同版本），仅用于下游区分新增/更新，不再作为重复依据
	isUpdate := false
	if prev, _ := s.getEntry(pluginID); prev != nil {
		isUpdate = prev.Version != pluginVersion
	}
	_ = isUpdate

	// dry-run 预检模式：只做上述全部校验，不落盘、不写元数据，供上传端预先检查
	if r.URL.Query().Get("dryrun") == "1" {
		s.uploadRL.Success(ip)
		s.writeAudit(auditEvent{Event: auditEventUploadDryRun, User: uploader, IP: ip, Target: pluginID, Result: "ok", Detail: "version=" + pluginVersion})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"dryrun":    true,
			"id":        pluginID,
			"version":   pluginVersion,
			"is_update": isUpdate,
			"message":   "预检通过，包结构合法" + updateSuffix(isUpdate),
		})
		return
	}

	// 4) 计算包哈希并落地到暂存目录（文件名由 plugin.json 的 id+version 决定，防穿越 + 自动整理）
	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])
	zipName := fmt.Sprintf("%s_%s.zip", pluginID, pluginVersion)
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
		ID:           pluginID,
		Name:         manifest.Name.Default,
		Version:      pluginVersion,
		Uploader:     uploader,
		UploadedAt:   time.Now(),
		PackagePath:  filepath.ToSlash(relPath),
		OrigFilename: header.Filename, // 保留用户原始文件名仅供审核参考，归档名已自动整理
		SHA256:       shaHex,
		Status:       StatusPending,
		Size:         int64(len(data)),
		IsUpdate:     isUpdate,
	}
	if err := s.saveEntry(entry); err != nil {
		log.Printf("[错误] 写审核元数据失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "写入队列失败")
		return
	}

	s.uploadRL.Success(ip)
	log.Printf("[信息] 收到插件包 %s v%s（来自 %s，上传者 %s，原文件名 %s，%d 字节）", pluginID, pluginVersion, ip, uploader, header.Filename, len(data))
	s.writeAudit(auditEvent{Event: auditEventUpload, User: uploader, IP: ip, Target: pluginID, Result: "ok", Detail: "version=" + pluginVersion})
	// 上传成功进入待审核队列后，异步推送 Telegram 群提醒（失败不影响上传结果）。
	notifyUploadAsync(pluginID, pluginVersion, uploader, ip, int64(len(data)), isUpdate)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"id":        pluginID,
		"version":   pluginVersion,
		"is_update": isUpdate,
		"message":   "上传成功，已进入待审核队列" + updateSuffix(isUpdate),
	})
}

// checkPluginOwner 校验插件所有者：若该插件已登记上传者（待审核队列）且与本次 uploader 不一致，
// 则拒绝上传（防冒名更新他人插件）。管理员调用已在调用方拦截，这里只做匹配比较。
// 注意：错误信息不回显具体作者名（隐私保护）。anonymous 兜底署名不参与所有者判定。
func (s *Store) checkPluginOwner(pluginID, uploader string) error {
	prev, err := s.getEntry(pluginID)
	if err != nil || prev == nil {
		return nil // 队列无记录（含未登记上传者）则放行
	}
	if prev.Uploader != "" && prev.Uploader != uploader && prev.Uploader != anonymousUploader {
		return fmt.Errorf("该插件属于其他作者，你不能更新（当前所有者已登记）")
	}
	return nil
}

// updateSuffix 返回“更新”提示后缀，用于上传响应 message。
func updateSuffix(isUpdate bool) string {
	if isUpdate {
		return "（检测为已有插件的新版本更新）"
	}
	return ""
}

// validateZip 校验 zip 包内容安全，并从根 plugin.json 解析出 Manifest。
// 任一条目违反规则即返回错误（不落地文件）。
func validateZip(data []byte, isAdmin bool) (*Manifest, error) {
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
	if err := validateManifest(&m, isAdmin); err != nil {
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

// ---------- 包内文件预览 / 编辑辅助（审核后台用） ----------

// maxPreviewSize 预览/编辑单个包内文件的字节上限。
const maxPreviewSize = 1 << 20 // 1MB

// normalizeZipPath 校验并规范化包内相对路径，防路径穿越（zip slip）。
// 返回与 zip 条目名可直接比较的清理后路径；包含 .. / 绝对路径 / 反斜杠时返回 false。
func normalizeZipPath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", false
	}
	if strings.Contains(p, "\\") || strings.HasPrefix(p, "/") {
		return "", false
	}
	cleaned := filepath.Clean("/" + p) // 以 / 为根拼后 Clean，消化 .. 等相对段
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "", false
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

// isTextContent 判断一段字节是否可作为文本预览：
// 前 512 字节内含 NUL（0x00）或整体非合法 UTF-8 则视为二进制。
func isTextContent(b []byte) bool {
	head := b
	if len(head) > 512 {
		head = head[:512]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	return utf8.Valid(b)
}

// readZipFile 从 zip 中按路径读取单个文件内容。
// 目录条目或路径不存在返回 os.ErrNotExist；调用方需自行限制大小。
func readZipFile(zr *zip.Reader, filePath string) ([]byte, error) {
	cleaned, ok := normalizeZipPath(filePath)
	if !ok {
		return nil, os.ErrInvalid
	}
	for _, f := range zr.File {
		name := strings.TrimSuffix(f.Name, "/")
		if f.FileInfo().IsDir() || name != cleaned {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		return content, nil
	}
	return nil, os.ErrNotExist
}

// replaceZipFile 返回把 zipData 内指定 path 的文件内容替换为 newContent 后的新 zip 字节。
// 其余条目原样复制；指定的 path 必须已存在，否则报错（不新增文件）。
func replaceZipFile(zipData []byte, filePath string, newContent []byte) ([]byte, error) {
	cleaned, ok := normalizeZipPath(filePath)
	if !ok {
		return nil, fmt.Errorf("包内路径非法")
	}
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("不是合法的 zip 包: %w", err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	replaced := false
	for _, f := range zr.File {
		if err := checkZipEntryName(f.Name); err != nil {
			return nil, err
		}
		if !f.FileInfo().IsDir() && strings.TrimSuffix(f.Name, "/") == cleaned {
			w, err := zw.Create(f.Name)
			if err != nil {
				return nil, err
			}
			if _, err := w.Write(newContent); err != nil {
				return nil, err
			}
			replaced = true
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		// 克隆原始 FileHeader，保留目录标志位/时间/权限等元数据，避免重组后丢目录条目
		fh := cloneZipFileHeader(f.FileHeader)
		w, err := zw.CreateHeader(&fh)
		if err != nil {
			rc.Close()
			return nil, err
		}
		if !f.FileInfo().IsDir() {
			if _, err := io.Copy(w, rc); err != nil {
				rc.Close()
				return nil, err
			}
		}
		rc.Close()
	}
	if !replaced {
		zw.Close()
		return nil, os.ErrNotExist
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// cloneZipFileHeader 复制一个 zip.FileHeader（值拷贝，含切片字段独立），供重组 zip 时保留原条目元数据。
func cloneZipFileHeader(h zip.FileHeader) zip.FileHeader {
	out := h
	out.Extra = append([]byte(nil), h.Extra...)
	out.Comment = h.Comment
	out.NonUTF8 = h.NonUTF8
	return out
}

// versionPublishedRemotely 查询远程 index.json，判断插件 id 的指定 version 是否仍在已发布列表中。
// 这是“是否已发布/是否重复”的权威依据。返回 (是否已发布, 错误)；GitHub 未配置或查询失败时返回错误，
// 由调用方决定是否降级到本地队列。
func (s *Store) versionPublishedRemotely(ctx context.Context, id, version string) (bool, error) {
	if s.publisher == nil || !s.ghEnabled {
		return false, fmt.Errorf("GitHub 未配置")
	}
	idx, err := s.publisher.fetchIndex(ctx, s.cfg.GHBranch)
	if err != nil {
		return false, err
	}
	for _, e := range idx.Plugins {
		if e.ID == id && (version == "" || e.Version == version) {
			return true, nil
		}
	}
	return false, nil
}
