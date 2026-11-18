package main

// 审计日志：把敏感操作（登录、审核通过、拒绝、下架）追加写入 data/audit.log，
// JSON Lines 格式，每行一条，便于后台查询与事后追溯。

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// 审计事件类型常量。
const (
	auditEventLogin           = "login"          // 登录成功
	auditEventLoginFailed     = "login_failed"   // 登录失败（凭据/动态码/人机验证）
	auditEventApprove         = "approve"        // 审核通过并发布
	auditEventReject          = "reject"         // 审核拒绝
	auditEventUnpublish       = "unpublish"      // 下架
	auditEventUpload          = "upload"         // 正式上传插件包
	auditEventUploadDryRun    = "upload_dryrun"  // 上传预检 dry-run
	auditEventPendingDownload    = "pending_download"    // 下载待审核包
	auditEventPublishedDownload  = "published_download"   // 下载已发布包
	auditEventLogout          = "logout"         // 注销
	auditEventLoginLocked      = "login_locked"   // 登录时 IP/账号处于锁定期被拒
	auditEventInspect          = "inspect"           // 预览待审核包内容（文件树/单文件）
	auditEventInspectEdit      = "inspect_edit"      // 修改待审核包内文件并重新打包
	auditEventBatchApprove     = "batch_approve"     // 批量审核通过并发布
	auditEventBatchReject      = "batch_reject"      // 批量拒绝
	auditEventIPBanAdd         = "ipban_add"         // 手动封禁 IP
	auditEventIPBanRemove      = "ipban_remove"      // 手动解封 IP
	auditEventOwnerChange      = "owner_change"      // 管理员修改待审核插件的所有者
)

// auditEvent 是审计日志中的一条记录（JSON Lines，落盘 data/audit.log）。
type auditEvent struct {
	Time   string `json:"time"`           // RFC3339
	Event  string `json:"event"`          // 事件类型（见 auditEvent* 常量）
	User   string `json:"user,omitempty"` // 操作者（登录失败时可能为尝试的用户名）
	IP     string `json:"ip,omitempty"`
	Target string `json:"target,omitempty"` // 目标插件 id
	Result string `json:"result,omitempty"` // ok / fail
	Detail string `json:"detail,omitempty"` // 补充信息（版本、拒绝原因等）
}

// auditMu 串行化审计日志追加，避免并发交错写坏一行。
var auditMu sync.Mutex

// writeAudit 追加一条审计记录到 data/audit.log。失败仅记运行日志，不影响主流程。
func (s *Store) writeAudit(ev auditEvent) {
	if ev.Time == "" {
		ev.Time = time.Now().Format(time.RFC3339)
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	f, err := os.OpenFile(s.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// readAudit 读取审计日志，返回倒序（最新在前）的记录，最多 limit 条。
// event 非空时按事件类型过滤。文件不存在或为空返回空切片。
func (s *Store) readAudit(event string, limit int) []auditEvent {
	if limit <= 0 {
		limit = 200
	}
	f, err := os.Open(s.auditPath)
	if err != nil {
		return []auditEvent{}
	}
	defer f.Close()

	var out []auditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev auditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if event != "" && ev.Event != event {
			continue
		}
		out = append(out, ev)
	}
	// 倒序：最新在前
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []auditEvent{}
	}
	return out
}
