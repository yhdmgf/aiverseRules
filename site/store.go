package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// PluginStatus 插件包在审核流程中的状态。
type PluginStatus string

const (
	StatusPending  PluginStatus = "pending"  // 待审核
	StatusApproved PluginStatus = "approved" // 已通过并发布
	StatusRejected PluginStatus = "rejected" // 已拒绝
)

// QueueEntry 是 data/queue/<id>.json 的元数据，记录一个待处理/已处理的插件包。
type QueueEntry struct {
	ID             string       `json:"id"`   // 插件 id，形如 demo.chat-bridge
	Name           string       `json:"name"` // 展示名（取 plugin.json 的 name.default）
	Version        string       `json:"version"`
	Uploader       string       `json:"uploader"`
	UploadedAt     time.Time    `json:"uploaded_at"`
	PackagePath    string       `json:"package_path"` // 暂存 zip 相对 data/ 的路径
	OrigFilename   string       `json:"orig_filename"`
	SHA256         string       `json:"sha256"`
	Status         PluginStatus `json:"status"`
	Size           int64        `json:"size"`
	ReviewedBy     string       `json:"reviewed_by,omitempty"`
	ReviewedAt     *time.Time   `json:"reviewed_at,omitempty"`
	RejectReason   string       `json:"reject_reason,omitempty"`
}

// Store 封装数据目录与各子组件（session、限流、发布）。
type Store struct {
	cfg    Config
	inbox  string // data/incoming  暂存 zip
	queue  string // data/queue     审核元数据
	rejDir string // data/rejected  拒绝原因
	sessDir string // data/sessions  会话
	pkgDir string // data/packages  发布缓存

	sessions   *sessionStore
	loginRL    *rateLimiter // IP 维度登录限流（data/ipban.json）
	accountRL  *rateLimiter // 账号维度登录限流（data/accountban.json）
	uploadRL   *rateLimiter
	captcha    *captchaStore // 算术验证挑战与一次性 token（内存）
	publisher  *publisher
	ghEnabled  bool
	noTOTP     bool // 未配置 STORE_ADMIN_TOTP_SECRET 时为 true，登录跳过 TOTP 校验
}

// NewStore 初始化目录结构与各组件。
func NewStore(cfg Config) (*Store, error) {
	s := &Store{
		cfg:    cfg,
		inbox:  filepath.Join(cfg.DataDir, "incoming"),
		queue:  filepath.Join(cfg.DataDir, "queue"),
		rejDir: filepath.Join(cfg.DataDir, "rejected"),
		sessDir: filepath.Join(cfg.DataDir, "sessions"),
		pkgDir: filepath.Join(cfg.DataDir, "packages"),
	}
	for _, d := range []string{s.inbox, s.queue, s.rejDir, s.sessDir, s.pkgDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("创建目录 %s 失败: %w", d, err)
		}
	}
	s.sessions = newSessionStore(s.sessDir, cfg.SessionTTL)
	// 登录限流（IP 维度）：1 分钟内同 IP 连续失败 3 次锁 30 分钟
	s.loginRL = newWindowedRateLimiter(filepath.Join(cfg.DataDir, "ipban.json"), 3, time.Minute, 30*time.Minute)
	s.loginRL.cleanupExpired()
	// 登录限流（账号维度）：1 分钟内同账号失败 3 次锁 30 分钟
	s.accountRL = newAccountRateLimiter(cfg.DataDir)
	s.accountRL.cleanupExpired()
	// 算术验证（登录前人机校验）
	s.captcha = newCaptchaStore()
	// 上传限流：同 IP 5 分钟内最多 10 次
	s.uploadRL = newRateLimiter(filepath.Join(cfg.DataDir, "upload_ratelimit.json"), 10, 5*time.Minute)
	s.publisher = newPublisher(cfg)
	s.ghEnabled = cfg.GHToken != ""
	// 未配置 TOTP 密钥时降级：跳过 TOTP 校验（保证向后兼容），启动日志已告警
	s.noTOTP = cfg.AdminTOTPSecret == ""
	return s, nil
}

// queuePath 返回某插件 id 的元数据文件路径。
func (s *Store) queuePath(id string) (string, bool) {
	if !safeFilename(id) {
		return "", false
	}
	return filepath.Join(s.queue, id+".json"), true
}

// saveEntry 持久化审核元数据。
func (s *Store) saveEntry(e *QueueEntry) error {
	p, ok := s.queuePath(e.ID)
	if !ok {
		return fmt.Errorf("非法插件 id: %q", e.ID)
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, data, 0o644)
}

// getEntry 读取某插件 id 的审核元数据。
func (s *Store) getEntry(id string) (*QueueEntry, error) {
	p, ok := s.queuePath(id)
	if !ok {
		return nil, fmt.Errorf("非法插件 id: %q", id)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var e QueueEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// listEntries 列出全部审核元数据，按上传时间倒序。
func (s *Store) listEntries() []*QueueEntry {
	files, err := filepath.Glob(filepath.Join(s.queue, "*.json"))
	if err != nil {
		return nil
	}
	var list []*QueueEntry
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var e QueueEntry
		if err := json.Unmarshal(data, &e); err != nil {
			log.Printf("[警告] 跳过损坏的队列文件 %s: %v", f, err)
			continue
		}
		list = append(list, &e)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].UploadedAt.After(list[j].UploadedAt)
	})
	return list
}

// Approve 将插件标记为通过。发布到 GitHub 由调用方（HTTP handler）在拿到锁后执行。
// 这里只负责状态落盘与暂存包清理。
func (s *Store) Approve(id, reviewer string) error {
	e, err := s.getEntry(id)
	if err != nil {
		return err
	}
	now := time.Now()
	e.Status = StatusApproved
	e.ReviewedBy = reviewer
	e.ReviewedAt = &now
	e.RejectReason = ""
	if err := s.saveEntry(e); err != nil {
		return err
	}
	// 发布成功后清理暂存 zip（由调用方在发布成功后调用 CleanupPackage）
	return nil
}

// CleanupPackage 删除暂存 zip 与包缓存（发布成功后调用）。
func (s *Store) CleanupPackage(id string) {
	e, err := s.getEntry(id)
	if err != nil {
		return
	}
	if e.PackagePath != "" {
		if p, ok := safeJoin(s.cfg.DataDir, e.PackagePath); ok {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				log.Printf("[警告] 删除暂存包失败 %s: %v", p, err)
			}
		}
	}
}

// Reject 拒绝插件：写原因到 data/rejected/<id>.txt 并改状态。
func (s *Store) Reject(id, reviewer, reason string) error {
	e, err := s.getEntry(id)
	if err != nil {
		return err
	}
	now := time.Now()
	e.Status = StatusRejected
	e.ReviewedBy = reviewer
	e.ReviewedAt = &now
	e.RejectReason = reason
	if err := s.saveEntry(e); err != nil {
		return err
	}
	// 写拒绝原因文件（供上传者/运营查看）
	if safeFilename(id) {
		txtPath := filepath.Join(s.rejDir, id+".txt")
		content := fmt.Sprintf("插件: %s\n版本: %s\n审核人: %s\n时间: %s\n原因: %s\n",
			e.ID, e.Version, reviewer, now.Format(time.RFC3339), reason)
		if err := atomicWrite(txtPath, []byte(content), 0o644); err != nil {
			log.Printf("[警告] 写拒绝原因失败: %v", err)
		}
	}
	// 拒绝后同样清理暂存包，避免堆积
	s.CleanupPackage(id)
	return nil
}

// ghRepoSlug 返回 GitHub 仓库 slug（owner/repo）。
func (s *Store) ghRepoSlug() string {
	return s.cfg.GHOwner + "/" + s.cfg.GHRepo
}
