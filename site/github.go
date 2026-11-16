package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

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
	ID          string        `json:"id"`
	Name        LocalizedText `json:"name"`
	Description LocalizedText `json:"description"`
	Author      string        `json:"author"`
	Repository  string        `json:"repository"`
	Version     string        `json:"version"`
	License     string        `json:"license"`
	Tags        []string      `json:"tags"`
	LastUpdate  int64         `json:"lastUpdate"`
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
	manifest, err := validateZip(zipBytes)
	if err != nil {
		return fmt.Errorf("暂存包 plugin.json 校验失败: %w", err)
	}

	// 1) 上传 zip 到 packages/<id>_<version>.zip
	pkgRemote := fmt.Sprintf("packages/%s_%s.zip", entry.ID, entry.Version)
	commitMsg := fmt.Sprintf("发布插件 %s v%s", entry.ID, entry.Version)
	if err := p.putFile(ctx, pkgRemote, zipBytes, commitMsg); err != nil {
		return fmt.Errorf("上传插件包失败: %w", err)
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

	// 构造新条目
	newEntry := indexEntry{
		ID:     m.ID,
		Name:   m.Name,
		Description: m.Description,
		Author: authorOf(m),
		Repository: fmt.Sprintf("https://github.com/%s/%s", p.cfg.GHOwner, p.cfg.GHRepo),
		Version:    m.Version,
		License:    m.License,
		Tags:       m.inferTags(),
		LastUpdate: time.Now().UnixMilli(),
	}
	if newEntry.ID == "" {
		newEntry.ID = entry.ID
	}
	if newEntry.Version == "" {
		newEntry.Version = entry.Version
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

// authorOf 返回插件作者：优先 plugin.json 的 author，否则取 id 的发布者段。
func authorOf(m Manifest) string {
	if strings.TrimSpace(m.Author) != "" {
		return m.Author
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
