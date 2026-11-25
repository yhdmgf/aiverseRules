package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// publishMu 串行化 GitHub 发布/下架对 index.json 的写操作，避免并发写丢失更新。
var publishMu sync.Mutex

// acquirePublishLock 获取全局发布锁，返回释放函数。approve（发布）与 unpublish（下架）都经此串行。
func acquirePublishLock() func() {
	publishMu.Lock()
	return publishMu.Unlock
}

// publisher 通过 GitHub Contents API 把插件包发布到商店仓库。
// token 只从 Config（环境变量）读取，绝不写日志或返回前端。
type publisher struct {
	cfg    Config
	client *http.Client
}

func newPublisher(cfg Config) *publisher {
	return &publisher{
		cfg: cfg,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// indexFile 是商店仓库 index.json 的完整结构，与现有格式严格一致。
type indexFile struct {
	SchemaVersion int          `json:"schema_version"`
	Plugins       []indexEntry `json:"plugins"`
}

// indexEntry 是 index.json 中单个插件条目。
type indexEntry struct {
	ID            string        `json:"id"`
	Name          LocalizedText `json:"name"`
	Description   LocalizedText `json:"description"`
	Author        string        `json:"author"`
	Repository    string        `json:"repository"`
	Version       string        `json:"version"`
	License       string        `json:"license"`
	Tags          []string      `json:"tags"`
	LastUpdate    int64         `json:"lastUpdate"`
	Logo          string        `json:"logo,omitempty"`
	Icon          string        `json:"icon,omitempty"`
	Homepage      string        `json:"homepage,omitempty"`
	PackageURL    string        `json:"package_url,omitempty"`
	MinAppVersion string        `json:"min_app_version,omitempty"`
}

// ghAPI 返回 Contents API 的文件 URL。
func (p *publisher) ghAPI(path string) string {
	return fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s",
		p.cfg.GHOwner, p.cfg.GHRepo, path)
}

// publishToStore 把插件包与 index.json 条目发布到商店仓库（幂等）。
func (s *Store) publishToStore(r *http.Request, entry *QueueEntry) error {
	p := s.publisher
	ctx := r.Context()

	// 读取暂存 zip 内容（已在白名单内，路径由 id+version 构成，安全）
	pkgPath, ok := safeJoin(s.cfg.DataDir, entry.PackagePath)
	if !ok {
		return fmt.Errorf("插件包路径非法")
	}
	zipBytes, err := readFileLimited(pkgPath, maxUploadSize+1)
	if err != nil {
		return fmt.Errorf("读取暂存包失败: %w", err)
	}

	// 重新解析 plugin.json（保证 name/description/tags 与原始包一致）。
	// 上传时已校验通过，此处若失败说明暂存包被篡改/损坏，直接报错不发布。
	// 发布流程仅管理员可触发（requireSession 保护），故按管理员跳过防冒充校验。
	manifest, err := validateZip(zipBytes, true)
	if err != nil {
		return fmt.Errorf("暂存包 plugin.json 校验失败: %w", err)
	}

	// 1) 上传 zip 到 packages/<id>_<version>.zip
	// 关键：APP 端会用 index 的 repository 与包内 plugin.json 的 repository 做精确字符串比对，
	// 不一致会报"源码仓库与商店登记不一致"并取消安装。因此这里在上传前把包内 plugin.json 的
	// repository 统一改写为商店仓库，保证与 updateIndex 写入 index 的值完全一致，
	// 用户无需关心 plugin.json 里填什么仓库，发布后自动对齐。
	rewritten, err := rewriteZipManifestRepository(zipBytes, p.storeRepositoryURL())
	if err != nil {
		return fmt.Errorf("改写包内 repository 失败: %w", err)
	}
	zipBytes = rewritten

	pkgRemote := fmt.Sprintf("packages/%s_%s.zip", entry.ID, entry.Version)
	commitMsg := fmt.Sprintf("发布插件 %s v%s", entry.ID, entry.Version)
	if err := p.putFile(ctx, pkgRemote, zipBytes, commitMsg); err != nil {
		return fmt.Errorf("上传插件包失败: %w", err)
	}

	// 1.5) 上传图标：清单 icon 为包内图片路径（如 assets/icon.png）时，从包内提取
	// 图片上传到 icons/<id>.png，供 index 的 logo 直链使用；内置图标名（zap/layers 等）
	// 无需上传，APP 直接用内置图标。
	if manifest.Icon != "" && !isBuiltinIcon(manifest.Icon) {
		if iconBytes, err := readZipEntry(zipBytes, manifest.Icon); err == nil && len(iconBytes) > 0 {
			iconRemote := fmt.Sprintf("icons/%s.png", entry.ID)
			if err := p.putFile(ctx, iconRemote, iconBytes, "上传插件图标 "+entry.ID); err != nil {
				return fmt.Errorf("上传插件图标失败: %w", err)
			}
		}
	}

	// 2) 读取并更新 index.json
	if err := p.updateIndex(ctx, s.cfg.GHBranch, entry, *manifest); err != nil {
		return fmt.Errorf("更新 index.json 失败: %w", err)
	}
	return nil
}

// updateIndex 读取仓库 index.json，追加/更新该插件条目后写回（幂等）。
func (p *publisher) updateIndex(ctx context.Context, branch string, entry *QueueEntry, m Manifest) error {
	// 读取现有 index.json
	existing, existingSHA, err := p.getFile(ctx, "index.json", branch)
	if err != nil {
		return err
	}

	var idx indexFile
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &idx); err != nil {
			return fmt.Errorf("仓库 index.json 解析失败: %w", err)
		}
	}
	if idx.SchemaVersion == 0 {
		idx.SchemaVersion = 1
	}

	// 中文名称优先：default 为英文且包内已有中文时，用中文替换 default，
	// 这样 APP 端即使只读 default 也能显示中文（中文本来就在 plugin.json 里）。
	m.Name.applyChineseDefault()
	m.Description.applyChineseDefault()

	// repository 必须写商店仓库：APP 端既用它解析包下载地址（packages/），又用它和包内
	// plugin.json 的 repository 做精确比对。统一取 storeRepositoryURL()，与发布时改写进
	// 包内的值保持完全一致，避免"源码仓库不一致"或"找不到可安装版本"。
	repository := p.storeRepositoryURL()

	// 构造新条目
	newEntry := indexEntry{
		ID:          m.ID,
		Name:        m.Name,
		Description: m.Description,
		Author:      authorOf(m),
		Repository:  repository,
		Version:     m.Version,
		License:     m.License,
		Tags:        m.inferTags(),
		LastUpdate:  time.Now().UnixMilli(),
	}
	if newEntry.ID == "" {
		newEntry.ID = entry.ID
	}
	if newEntry.Version == "" {
		newEntry.Version = entry.Version
	}

	// 自动生成直链下载地址（package_url）：APP 有值时直接下载，不再查询作者仓库 Release。
	newEntry.PackageURL = p.packageURL(newEntry.ID, newEntry.Version)
	// 图标：清单 icon 为内置图标名（如 zap/layers）时写入 icon；为包内图片路径时
	// 由发布流程上传到 icons/<id>.png，这里用其直链作为 logo。
	if m.Icon != "" {
		if isBuiltinIcon(m.Icon) {
			newEntry.Icon = m.Icon
		} else {
			newEntry.Logo = p.iconURL(newEntry.ID)
		}
	}
	if m.Homepage != "" {
		newEntry.Homepage = m.Homepage
	}

	// 幂等：同 id 同版本则更新，否则追加
	replaced := false
	for i := range idx.Plugins {
		if idx.Plugins[i].ID == newEntry.ID && idx.Plugins[i].Version == newEntry.Version {
			idx.Plugins[i] = newEntry
			replaced = true
			break
		}
	}
	if !replaced {
		idx.Plugins = append(idx.Plugins, newEntry)
	}

	out, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("更新 index.json：插件 %s v%s", newEntry.ID, newEntry.Version)
	if err := p.putFileWithSHA(ctx, "index.json", out, msg, existingSHA, branch); err != nil {
		return err
	}
	return nil
}

// fetchIndex 拉取仓库 index.json 并解析为 indexFile。
// 文件不存在或解析失败均返回错误，由调用方决定降级策略。
func (p *publisher) fetchIndex(ctx context.Context, branch string) (*indexFile, error) {
	data, _, err := p.getFile(ctx, "index.json", branch)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("仓库 index.json 不存在")
	}
	var idx indexFile
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("仓库 index.json 解析失败: %w", err)
	}
	return &idx, nil
}

// authorOf 返回插件作者：优先 plugin.json 的 author，否则取 id 的发布者段。
func authorOf(m Manifest) string {
	// TrimSpace 兜底：即使校验被绕过（如历史数据），生成 index 条目时也绝不写入
	// 带首尾空白的 author，避免 APP 端 AUTHOR 正则匹配失败、拒绝加载整个商店索引。
	if a := strings.TrimSpace(m.Author); a != "" {
		return a
	}
	if i := strings.Index(m.ID, "."); i > 0 {
		return m.ID[:i]
	}
	return "unknown"
}

// putFile 创建或更新仓库中的文件（无 SHA，用于新文件）。
func (p *publisher) putFile(ctx context.Context, remotePath string, content []byte, msg string) error {
	// 先尝试取现有 SHA（文件已存在时必须带 SHA 才能更新）
	_, sha, _ := p.getFile(ctx, remotePath, p.cfg.GHBranch)
	return p.putFileWithSHA(ctx, remotePath, content, msg, sha, p.cfg.GHBranch)
}

// putFileWithSHA 用 Contents API PUT 创建/更新文件。
func (p *publisher) putFileWithSHA(ctx context.Context, remotePath string, content []byte, msg, sha, branch string) error {
	payload := map[string]any{
		"message": msg,
		"content": base64.StdEncoding.EncodeToString(content),
		"branch":  branch,
	}
	if sha != "" {
		payload["sha"] = sha
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.ghAPI(remotePath), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.GHToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GitHub PUT %s 返回 %d: %s", remotePath, resp.StatusCode, string(b))
	}
	return nil
}

// getFile 读取仓库文件内容与其 SHA（用于更新）。
// 文件不存在时返回 (nil, "", nil)。
func (p *publisher) getFile(ctx context.Context, remotePath, branch string) ([]byte, string, error) {
	url := p.ghAPI(remotePath) + "?ref=" + branch
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.GHToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", nil
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", fmt.Errorf("GitHub GET %s 返回 %d: %s", remotePath, resp.StatusCode, string(b))
	}

	var payload struct {
		Content  string `json:"content"`
		SHA      string `json:"sha"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&payload); err != nil {
		return nil, "", err
	}
	var content []byte
	if payload.Encoding == "base64" {
		content, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(payload.Content, "\n", ""))
		if err != nil {
			return nil, "", err
		}
	}
	return content, payload.SHA, nil
}

// readFileLimited 读取本地文件，限制最大字节数。
func readFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// unpublishFromStore 把插件从商店下架：先从 index.json 移除条目（用户可见列表立即消失），
// 再删除 packages/<id>_<version>.zip。任一步失败返回明确错误。
// 顺序说明：先改 index 再删包——即使删包失败，列表已不展示，不会出现“列表还在但包 404”的反向问题。
func (s *Store) unpublishFromStore(ctx context.Context, id, version string) error {
	p := s.publisher

	// 1) 从 index.json 移除该 id（可选限定 version）的条目
	removed, err := p.removeFromIndex(ctx, id, version)
	if err != nil {
		return fmt.Errorf("从 index.json 移除失败: %w", err)
	}
	_ = removed

	// 2) 删除 packages/<id>_<version>.zip（仅当指定了 version）
	if version != "" {
		pkgRemote := fmt.Sprintf("packages/%s_%s.zip", id, version)
		if err := p.deleteFile(ctx, pkgRemote); err != nil {
			return fmt.Errorf("删除插件包失败: %w", err)
		}
	}
	return nil
}

// removeFromIndex 读取仓库 index.json，删除指定 id（可选限定 version）的条目后写回。
// 返回是否确实删除了条目；未找到时返回错误。
func (p *publisher) removeFromIndex(ctx context.Context, id, version string) (bool, error) {
	existing, existingSHA, err := p.getFile(ctx, "index.json", p.cfg.GHBranch)
	if err != nil {
		return false, err
	}
	if len(existing) == 0 {
		return false, fmt.Errorf("仓库 index.json 不存在")
	}
	var idx indexFile
	if err := json.Unmarshal(existing, &idx); err != nil {
		return false, fmt.Errorf("仓库 index.json 解析失败: %w", err)
	}

	kept := idx.Plugins[:0]
	removedAny := false
	for _, e := range idx.Plugins {
		match := e.ID == id && (version == "" || e.Version == version)
		if match {
			removedAny = true
			continue
		}
		kept = append(kept, e)
	}
	if !removedAny {
		return false, fmt.Errorf("index.json 中未找到 %s%s", id, versionLabel(version))
	}
	idx.Plugins = kept

	out, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return false, err
	}
	msg := fmt.Sprintf("下架插件 %s%s", id, versionLabel(version))
	if err := p.putFileWithSHA(ctx, "index.json", out, msg, existingSHA, p.cfg.GHBranch); err != nil {
		return false, err
	}
	return true, nil
}

// versionLabel 返回用于提交信息/错误提示的版本后缀（如 " v1.0.0"，空版本返回空串）。
func versionLabel(v string) string {
	if v == "" {
		return ""
	}
	return " v" + v
}

// deleteFile 删除仓库中的文件（Contents API DELETE，需先取 SHA）。
// 文件不存在时视为成功（幂等）。
func (p *publisher) deleteFile(ctx context.Context, remotePath string) error {
	_, sha, err := p.getFile(ctx, remotePath, p.cfg.GHBranch)
	if err != nil {
		return err
	}
	if sha == "" {
		return nil // 文件不存在，视为已删除
	}
	payload := map[string]any{
		"message": "删除 " + remotePath,
		"sha":     sha,
		"branch":  p.cfg.GHBranch,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.ghAPI(remotePath), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.GHToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 404 视为已删除（幂等）；其余 >=300 视为失败
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GitHub DELETE %s 返回 %d: %s", remotePath, resp.StatusCode, string(b))
	}
	return nil
}

// storeRepositoryURL 返回本商店仓库的规范 URL（用于写入 index 的 repository 字段，
// 以及发布时改写进插件包内的 plugin.json repository，保证两处值与大小写完全一致）。
func (p *publisher) storeRepositoryURL() string {
	return fmt.Sprintf("https://github.com/%s/%s", p.cfg.GHOwner, p.cfg.GHRepo)
}

// rawURL 返回商店仓库内某文件的 raw 直链（raw.githubusercontent.com）。
func (p *publisher) rawURL(path string) string {
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
		p.cfg.GHOwner, p.cfg.GHRepo, p.cfg.GHBranch, path)
}

// packageURL 返回插件包直链下载地址（index 的 package_url 字段）。
func (p *publisher) packageURL(id, version string) string {
	return p.rawURL(fmt.Sprintf("packages/%s_%s.zip", id, version))
}

// iconURL 返回插件图标直链地址（index 的 logo 字段）。
func (p *publisher) iconURL(id string) string {
	return p.rawURL(fmt.Sprintf("icons/%s.png", id))
}

// isBuiltinIcon 判断清单 icon 是否为内置图标名（zap/layers/shield 等）。
// 与 APP 端 PluginManifestParser.isIconFilePath 约定一致：以 .png/.webp 结尾视为包内图片路径，
// 其余视为内置图标名。
func isBuiltinIcon(value string) bool {
	lower := strings.ToLower(value)
	return !strings.HasSuffix(lower, ".png") && !strings.HasSuffix(lower, ".webp")
}

// readZipEntry 从插件包 zip 中按文件名（不区分大小写）读取一个条目。
func readZipEntry(zipBytes []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("读取插件包失败: %w", err)
	}
	for _, f := range zr.File {
		if strings.EqualFold(f.Name, name) || strings.EqualFold(f.Name, "/"+name) {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("读取包内文件 %s 失败: %w", f.Name, err)
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxUploadSize))
		}
	}
	return nil, fmt.Errorf("包内未找到图标 %s", name)
}

// appManifestTopLevelAllowed 判断 plugin.json 顶层字段是否被 APP 严格解析器允许。
// APP 端 PluginManifestParser 用固定白名单校验顶层字段，白名单外的键（典型如 author，
// APP 只认 publisher）会触发 UNSUPPORTED_FIELD 直接拒绝整个包，导致该插件在商店里
// 无法加载/安装。发布时据此剔除多余顶层字段；作者信息由 index.json 承载，包内无需保留。
func appManifestTopLevelAllowed(key string) bool {
	switch key {
	case "$schema", "manifestVersion", "id", "name", "version", "publisher",
		"repository", "description", "license", "engines", "runtime",
		"contributes", "configPage", "icon":
		return true
	}
	return false
}

// rewriteZipManifestRepository 把插件包 zip 内 plugin.json 的 repository 字段改写为 storeRepoURL，
// 其余文件字节原样保留。返回新的 zip 字节。用于发布时统一对齐商店仓库，避免 APP 端
// "源码仓库与商店登记不一致"校验失败。
func rewriteZipManifestRepository(zipBytes []byte, storeRepoURL string) ([]byte, error) {
	src, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("读取插件包失败: %w", err)
	}

	var buf bytes.Buffer
	dst := zip.NewWriter(&buf)

	for _, f := range src.File {
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("读取包内文件 %s 失败: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("读取包内文件 %s 失败: %w", f.Name, err)
		}

		// 改写 plugin.json（根目录）：repository 统一为商店仓库，并清洗掉 APP
		// 严格解析器不认的顶层字段（如 author，APP 只认 publisher）。APP 的
		// PluginManifestParser 用白名单校验顶层字段，包内一旦出现白名单外的键，会以
		// UNSUPPORTED_FIELD 拒绝整个包，导致商店里该插件无法加载/安装。发布时在此
		// 自动剔除；作者信息已由 index.json 承载，包内无需保留。
		if f.Name == "plugin.json" || f.Name == "/plugin.json" {
			var m map[string]interface{}
			if err := json.Unmarshal(data, &m); err != nil {
				return nil, fmt.Errorf("解析包内 plugin.json 失败: %w", err)
			}
			m["repository"] = storeRepoURL
			for k := range m {
				if !appManifestTopLevelAllowed(k) {
					delete(m, k)
				}
			}
			data, err = json.MarshalIndent(m, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("序列化 plugin.json 失败: %w", err)
			}
		}

		w, err := dst.Create(f.Name)
		if err != nil {
			return nil, fmt.Errorf("写入新包 %s 失败: %w", f.Name, err)
		}
		if _, err := w.Write(data); err != nil {
			return nil, fmt.Errorf("写入新包 %s 失败: %w", f.Name, err)
		}
	}

	if err := dst.Close(); err != nil {
		return nil, fmt.Errorf("关闭新包失败: %w", err)
	}
	return buf.Bytes(), nil
}
