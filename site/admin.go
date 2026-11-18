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
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookie = "store_session"
)

// handleAdminPage 返回内嵌的审核前端单页。所有 /admin 路径都回落到 index.html。
func (s *Store) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	serveWebAssets(w, r)
}

// handleLogin 处理管理员登录。
// 凭据来自环境变量（STORE_ADMIN_USER / STORE_ADMIN_PASS_HASH / STORE_ADMIN_TOTP_SECRET），不硬编码。
//
// 校验顺序：IP 锁 → 账号锁 → 算术 captcha_token → 用户名/密码 → TOTP 动态码。
// 任一步失败都会累计 IP + 账号 两个维度的失败计数；
// 密码与 TOTP 均正确时才清零两个维度（满足“输对密码+TOTP 即解锁”）。
func (s *Store) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		TOTP         string `json:"totp"`
		CaptchaToken string `json:"captcha_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	ip := clientIP(r)
	skipRL := isLoopbackIP(ip) || s.isWhitelistedIP(ip)

	// 1) IP 维度锁定短路（仅凭 IP 就拒绝，不泄露账号相关信息）
	//    本地回环地址（127.0.0.1/::1）与白名单 IP（环境变量 STORE_IP_WHITELIST，不写进代码/仓库）
	//    跳过 IP/账号锁检查与失败累计：便于本地调试与管理员固定 IP 不被限流误锁。
	//    真实用户经 Nginx 反代，clientIP() 取 X-Forwarded-For 首个公网 IP，不在白名单则照常限流。
	if !skipRL {
		if locked, until := s.loginRL.BlockedUntil(ip); locked {
			log.Printf("[安全] 登录拒绝：IP 处于锁定期（IP=%s）", ip)
			s.writeAudit(auditEvent{Event: auditEventLoginLocked, User: req.Username, IP: ip, Result: "fail", Detail: "IP 锁定期"})
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":           false,
				"error":        "失败次数过多，请稍后再试",
				"locked":       true,
				"locked_until": until.UTC().Format(time.RFC3339),
			})
			return
		}

		// 2) 账号维度锁定短路
		if locked, until := s.accountLock(req.Username); locked {
			log.Printf("[安全] 登录拒绝：账号处于锁定期（用户名=%q，IP=%s）", req.Username, ip)
			s.writeAudit(auditEvent{Event: auditEventLoginLocked, User: req.Username, IP: ip, Result: "fail", Detail: "账号锁定期"})
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":           false,
				"error":        "失败次数过多，请稍后再试",
				"locked":       true,
				"locked_until": until.UTC().Format(time.RFC3339),
			})
			return
		}
	}

	// 3) 算术人机验证：仅校验 token 有效性（peek，不消费）。
	//    无效/缺失则直接拒绝，让用户先完成验证；有效则继续校验凭据，token 留到最后成功时才消费，
	//    这样密码/动态码输错时 token 仍有效，用户改凭据重试即可，无需重做算术题。
	if !s.captcha.peek(req.CaptchaToken) {
		log.Printf("[安全] 登录失败：算术验证未通过（IP=%s，用户名=%q）", ip, req.Username)
		writeErr(w, http.StatusUnauthorized, "人机验证未通过，请重试")
		return
	}

	// 4) 校验凭据；用户名用常量时间比较，密码用 bcrypt
	//    凭据错误时【不消费】captcha_token，前端保留“已通过”的人机验证，仅清空对应字段便于重试。
	okUser := s.cfg.AdminUser != "" && safeEqual(req.Username, s.cfg.AdminUser)
	okPass := s.cfg.AdminPassHash != "" && verifyPassword(s.cfg.AdminPassHash, req.Password)
	if !okUser || !okPass {
		s.recordLoginFailure(ip, req.Username)
		log.Printf("[安全] 登录失败：用户名或密码错误（IP=%s，用户名=%q）", ip, req.Username)
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	// 5) TOTP 动态码：未配置密钥时跳过（向后兼容），配置后强制校验
	if !s.noTOTP {
		if !ValidateTOTP(s.cfg.AdminTOTPSecret, req.TOTP) {
			s.recordLoginFailure(ip, req.Username)
			log.Printf("[安全] 登录失败：TOTP 动态码错误（IP=%s，用户名=%q）", ip, req.Username)
			writeErr(w, http.StatusUnauthorized, "动态码错误或已过期")
			return
		}
	}

	// 6) 凭据全部正确，此处才真正消费 captcha_token（一次性，防重放）
	if !s.captcha.consume(req.CaptchaToken) {
		// 理论上 peek 已确认有效，并发/过期才会到这；按人机验证失败处理
		s.recordLoginFailure(ip, req.Username)
		log.Printf("[安全] 登录失败：算术 token 已失效（并发或过期）（IP=%s）", ip)
		writeErr(w, http.StatusUnauthorized, "人机验证未通过，请重试")
		return
	}

	// 7) 全部通过：清零两个维度的失败计数 + 建 session + 下发 Cookie
	s.loginRL.Success(ip)
	s.accountSuccess(req.Username)

	token, err := s.sessions.Create(req.Username)
	if err != nil {
		log.Printf("[错误] 创建 session 失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "创建会话失败")
		return
	}
	log.Printf("[信息] 管理员 %s 登录成功（IP=%s）", req.Username, ip)
	s.writeAudit(auditEvent{
		Event: auditEventLogin, User: req.Username, IP: ip, Result: "ok",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // 由 nginx 反代提供 HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": req.Username})
}

// recordLoginFailure 同时累计 IP 与账号两个维度的登录失败计数。
// 本地回环地址（白名单）不计入，避免本地调试触发限流/误锁账号。
func (s *Store) recordLoginFailure(ip, username string) {
	s.writeAudit(auditEvent{
		Event: auditEventLoginFailed, User: username, IP: ip, Result: "fail",
	})
	if isLoopbackIP(ip) || s.isWhitelistedIP(ip) {
		return
	}
	s.loginRL.Fail(ip)
	s.accountFail(username)
}

// isLoopbackIP 判断 IP 是否为本地回环地址（127.0.0.0/8 或 ::1）。
// 用于服务器本地调试白名单：直连 127.0.0.1 测试时不受登录限流约束。
func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// isWhitelistedIP 判断 IP 是否在管理员配置的白名单内（STORE_IP_WHITELIST 环境变量）。
// 白名单内容属敏感信息，只存于服务器 secrets，不写进代码或仓库。
func (s *Store) isWhitelistedIP(ip string) bool {
	for _, w := range s.cfg.IPWhitelist {
		if w == ip {
			return true
		}
	}
	return false
}

// handleLogout 注销当前会话。
func (s *Store) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	user := userFrom(r.Context())
	s.writeAudit(auditEvent{Event: auditEventLogout, User: user, IP: clientIP(r), Result: "ok"})
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // 立即删除
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// requireSession 中间件：除 login/upload 外的 /api/* 都需要有效 session。
func (s *Store) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		user, ok := s.sessions.Get(c.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "会话已过期，请重新登录")
			return
		}
		// 将当前用户名注入 context 供下游使用
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

// handleQueue 列出全部审核条目（待审核 + 已审核）。
func (s *Store) handleQueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	list := s.listEntries()
	if list == nil {
		list = []*QueueEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "items": list})
}

// handleApprove 审核通过 -> 发布到商店仓库 -> 清理暂存包 -> 状态改 approved。
func (s *Store) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || !safeFilename(req.ID) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	user := userFrom(r.Context())

	entry, err := s.getEntry(req.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "找不到该插件包记录")
		return
	}
	if entry.Status == StatusApproved {
		writeErr(w, http.StatusConflict, "该插件已通过审核")
		return
	}

	if !s.ghEnabled {
		writeErr(w, http.StatusServiceUnavailable, "GitHub 发布未配置（缺少 STORE_GH_TOKEN），无法发布")
		return
	}

	// 发布到商店仓库
	if err := s.publishToStore(r, entry); err != nil {
		log.Printf("[错误] 发布插件 %s v%s 失败: %v", entry.ID, entry.Version, err)
		writeErr(w, http.StatusBadGateway, "发布到商店仓库失败: "+sanitizeGHErr(err))
		return
	}

	// 发布成功：清理暂存包并落盘 approved 状态
	if err := s.Approve(req.ID, user); err != nil {
		log.Printf("[警告] 标记 approved 失败: %v", err)
	}
	s.CleanupPackage(req.ID)
	log.Printf("[信息] 插件 %s v%s 已由 %s 审核通过并发布", entry.ID, entry.Version, user)
	s.writeAudit(auditEvent{
		Event: auditEventApprove, User: user, IP: clientIP(r), Target: req.ID,
		Result: "ok", Detail: "version=" + entry.Version,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "已发布到商店仓库 " + s.ghRepoSlug(),
	})
}

// handleReject 拒绝插件：写原因到 data/rejected/<id>.txt，状态改 rejected。
func (s *Store) handleReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || !safeFilename(req.ID) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	user := userFrom(r.Context())
	if err := s.Reject(req.ID, user, strings.TrimSpace(req.Reason)); err != nil {
		writeErr(w, http.StatusNotFound, "找不到该插件包记录")
		return
	}
	log.Printf("[信息] 插件 %s 已由 %s 拒绝", req.ID, user)
	s.writeAudit(auditEvent{
		Event: auditEventReject, User: user, IP: clientIP(r), Target: req.ID,
		Result: "ok", Detail: strings.TrimSpace(req.Reason),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "已拒绝"})
}

// sanitizeGHErr 过滤 GitHub 错误信息，避免把 token 等敏感内容透传给前端。
func sanitizeGHErr(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "401") {
		return "GitHub 认证失败，请检查 STORE_GH_TOKEN"
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// ---------- 通用 JSON 响应 ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// API 响应（尤其算术验证 challenge/verify）禁止任何缓存，避免被 CDN/浏览器缓存导致挑战重放
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}

// ---------- 扩展：下架 / 审计 / 统计 / 待审核下载 ----------

// handleUnpublish 从商店下架插件：从 index.json 移除条目 + 删除 packages/<id>_<version>.zip，
// 并写审计日志。请求体：{"id":"...","version":"1.0.0"}（version 可选，缺省取 index.json 中该 id 最新版）。
func (s *Store) handleUnpublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !s.ghEnabled {
		writeErr(w, http.StatusServiceUnavailable, "GitHub 未配置（缺少 STORE_GH_TOKEN），无法下架")
		return
	}
	var req struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || !safeFilename(req.ID) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	user := userFrom(r.Context())
	version := strings.TrimSpace(req.Version)

	// 未指定版本时从 index.json 查该 id 的最新版本
	if version == "" {
		v, err := s.latestPublishedVersion(req.ID)
		if err != nil || v == "" {
			writeErr(w, http.StatusNotFound, "index.json 中未找到该插件")
			return
		}
		version = v
	}

	// 加全局发布锁，与 approve 串行，避免与并发发布写 index.json 冲突
	unlock := acquirePublishLock()
	defer unlock()

	if err := s.unpublishFromStore(r.Context(), req.ID, version); err != nil {
		s.writeAudit(auditEvent{
			Event: auditEventUnpublish, User: user, IP: clientIP(r), Target: req.ID,
			Result: "fail", Detail: "version=" + version + "; " + sanitizeGHErr(err),
		})
		log.Printf("[错误] 下架插件 %s v%s 失败: %v", req.ID, version, err)
		writeErr(w, http.StatusBadGateway, "下架失败: "+sanitizeGHErr(err))
		return
	}
	s.writeAudit(auditEvent{
		Event: auditEventUnpublish, User: user, IP: clientIP(r), Target: req.ID,
		Result: "ok", Detail: "version=" + version,
	})
	log.Printf("[信息] 插件 %s v%s 已由 %s 下架", req.ID, version, user)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": fmt.Sprintf("已下架 %s v%s", req.ID, version),
	})
}

// latestPublishedVersion 从仓库 index.json 查询某 id 的最新版本号（按 lastUpdate）。
func (s *Store) latestPublishedVersion(id string) (string, error) {
	if !s.ghEnabled {
		return "", fmt.Errorf("GitHub 未配置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	content, _, err := s.publisher.getFile(ctx, "index.json", s.cfg.GHBranch)
	if err != nil {
		return "", err
	}
	if len(content) == 0 {
		return "", nil
	}
	var idx indexFile
	if err := json.Unmarshal(content, &idx); err != nil {
		return "", err
	}
	latest := ""
	var latestTS int64 = -1
	for _, e := range idx.Plugins {
		if e.ID != id {
			continue
		}
		if e.LastUpdate > latestTS {
			latestTS = e.LastUpdate
			latest = e.Version
		}
	}
	return latest, nil
}

// handlePendingDownload 登录后从暂存目录下载待审核包，便于运营快速测试。
// GET /api/pending-download?id=<pluginId>
func (s *Store) handlePendingDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" || !safeFilename(id) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	e, err := s.getEntry(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "插件记录不存在")
		return
	}
	if e.PackagePath == "" {
		writeErr(w, http.StatusGone, "暂存包已被清理（可能已发布或已拒绝）")
		return
	}
	absPath, ok := safeJoin(s.cfg.DataDir, e.PackagePath)
	if !ok {
		writeErr(w, http.StatusBadRequest, "包路径非法")
		return
	}
	f, err := os.Open(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusGone, "暂存包已被清理")
			return
		}
		writeErr(w, http.StatusInternalServerError, "读取暂存包失败")
		return
	}
	defer f.Close()

	filename := e.OrigFilename
	if filename == "" {
		filename = fmt.Sprintf("%s_%s.zip", e.ID, e.Version)
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", sanitizeHeaderVal(filename)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.writeAudit(auditEvent{Event: auditEventPendingDownload, User: userFrom(r.Context()), IP: clientIP(r), Target: id, Result: "ok"})
	http.ServeContent(w, r, filename, time.Now(), f)
}

// handleOwner 查询插件所有者（公开接口，供 Android 客户端在更新前校验）。
// GET /api/owner?id=<pluginId>
// 优先返回待审核队列登记的 uploader，其次回退到已发布 index.json 的 author；两者均无则 exists=false。
func (s *Store) handleOwner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "缺少 id 参数")
		return
	}

	// 1. 待审核队列登记的上传者为准
	if entry, err := s.getEntry(id); err == nil && entry != nil && entry.Uploader != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "id": id, "owner": entry.Uploader, "exists": true,
		})
		return
	}

	// 2. 回退到已发布索引的作者
	if s.ghEnabled {
		if idx, err := s.publisher.fetchIndex(r.Context(), s.cfg.GHBranch); err == nil {
			for _, p := range idx.Plugins {
				if p.ID == id {
					writeJSON(w, http.StatusOK, map[string]any{
						"ok": true, "id": id, "owner": p.Author, "exists": true,
					})
					return
				}
			}
		}
	}

	// 3. 不存在
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "exists": false,
	})
}

// handleOwnerChange 修改待审核插件的所有者（管理员专用）。
// POST /api/owner/change  请求体：{"id":"pluginId","new_owner":"新作者"}
// 仅能改待审核队列里的所有者（已发布插件的所有者由 index.json 的 author 决定，随发布流程更新）。
func (s *Store) handleOwnerChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		ID       string `json:"id"`
		NewOwner string `json:"new_owner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.NewOwner = strings.TrimSpace(req.NewOwner)
	if req.ID == "" || req.NewOwner == "" {
		writeErr(w, http.StatusBadRequest, "id 和 new_owner 不能为空")
		return
	}

	entry, err := s.getEntry(req.ID)
	if err != nil || entry == nil {
		writeErr(w, http.StatusNotFound, "插件不存在（只能修改待审核插件的所有者）")
		return
	}
	oldOwner := entry.Uploader
	entry.Uploader = req.NewOwner
	if err := s.saveEntry(entry); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}

	user := userFrom(r.Context())
	s.writeAudit(auditEvent{Event: auditEventOwnerChange, User: user, IP: clientIP(r), Target: req.ID, Result: "ok", Detail: oldOwner + " -> " + req.NewOwner})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"id":      req.ID,
		"owner":   req.NewOwner,
		"message": "所有者已修改",
	})
}

// handlePublished 列出 index.json 中全部已发布插件。
// GET /api/published
func (s *Store) handlePublished(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !s.ghEnabled {
		writeErr(w, http.StatusServiceUnavailable, "GitHub 未配置")
		return
	}
	idx, err := s.publisher.fetchIndex(r.Context(), s.cfg.GHBranch)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "获取 index.json 失败: "+sanitizeGHErr(err))
		return
	}
	items := make([]map[string]any, 0, len(idx.Plugins))
	for _, e := range idx.Plugins {
		nameZh := e.Name.Extra["zh-CN"]
		if nameZh == "" {
			nameZh = e.Name.Default
		}
		descZh := e.Description.Extra["zh-CN"]
		if descZh == "" {
			descZh = e.Description.Default
		}
		items = append(items, map[string]any{
			"id":             e.ID,
			"name_zh":        nameZh,
			"version":        e.Version,
			"author":         e.Author,
			"tags":           e.Tags,
			"description_zh": descZh,
			"last_update":    e.LastUpdate,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"items": items,
		"total": len(items),
	})
}

// handlePublishedDownload 从商店仓库下载已发布包。
// GET /api/published-download?id=<pluginId>&version=<v>
// version 可选：缺省时从 index.json 取该 id 最近更新的版本。
func (s *Store) handlePublishedDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !s.ghEnabled {
		writeErr(w, http.StatusServiceUnavailable, "GitHub 未配置")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" || !safeFilename(id) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	version := strings.TrimSpace(r.URL.Query().Get("version"))
	if version != "" && !safeFilename(version) {
		writeErr(w, http.StatusBadRequest, "参数 version 非法")
		return
	}

	idx, err := s.publisher.fetchIndex(r.Context(), s.cfg.GHBranch)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "获取 index.json 失败: "+sanitizeGHErr(err))
		return
	}

	// 在 index 中查找目标条目：指定 version 时精确匹配；未指定时取 lastUpdate 最新的那条
	var found *indexEntry
	var latestTS int64 = -1
	for i := range idx.Plugins {
		if idx.Plugins[i].ID != id {
			continue
		}
		if version != "" && idx.Plugins[i].Version == version {
			found = &idx.Plugins[i]
			break
		}
		if version == "" && idx.Plugins[i].LastUpdate > latestTS {
			latestTS = idx.Plugins[i].LastUpdate
			found = &idx.Plugins[i]
		}
	}
	if found == nil {
		writeErr(w, http.StatusNotFound, "index.json 中未找到该插件")
		return
	}
	if version == "" {
		version = found.Version
	}

	// 防路径穿越：id 和 version 均已通过 safeFilename 校验，fmt.Sprintf 不会产生 ../ 段
	pkgRemote := fmt.Sprintf("packages/%s_%s.zip", id, version)
	data, _, err := s.publisher.getFile(r.Context(), pkgRemote, s.cfg.GHBranch)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "下载包失败: "+sanitizeGHErr(err))
		return
	}
	if len(data) == 0 {
		writeErr(w, http.StatusGone, "远程包不存在（可能已被下架）")
		return
	}

	filename := fmt.Sprintf("%s_%s.zip", id, version)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", sanitizeHeaderVal(filename)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.writeAudit(auditEvent{
		Event:  auditEventPublishedDownload,
		User:   userFrom(r.Context()),
		IP:     clientIP(r),
		Target: id,
		Result: "ok",
		Detail: "version=" + version,
	})
	http.ServeContent(w, r, filename, time.Now(), bytes.NewReader(data))
}

// sanitizeHeaderVal 过滤 Content-Disposition 里的非法字符，防 header 注入。
func sanitizeHeaderVal(s string) string {
	return strings.Map(func(c rune) rune {
		if c == '"' || c == '\\' || c == '\r' || c == '\n' {
			return '_'
		}
		return c
	}, s)
}

// handleAudit 返回审计日志（倒序，最多 200 条），可选 ?event= 过滤、?limit= 限制条数。
func (s *Store) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	event := strings.TrimSpace(r.URL.Query().Get("event"))
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "items": s.readAudit(event, limit)})
}

// handleStats 返回插件包下载量统计（解析源站 nginx access 日志，按 IP 去重）。
// 近似值：命中 QEdge CDN 边缘缓存的请求不会回源，前端需标注。
func (s *Store) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	logPath := strings.TrimSpace(s.cfg.NginxAccessLog)
	if logPath == "" {
		writeErr(w, http.StatusServiceUnavailable, "未配置访问日志路径（STORE_NGINX_ACCESS_LOG）")
		return
	}
	items, err := s.buildStatsFromIndex(r.Context())
	if err == nil {
		generated := time.Now().Format(time.RFC3339)
		// 写穿持久化；写失败只记录告警，不影响返回
		if serr := s.saveStats(items); serr != nil {
			log.Printf("[警告] 写入下载量统计缓存失败: %v", serr)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"items":     items,
			"approx":    true,
			"note":      "近似值（仅源站回源请求；CDN 边缘命中不回源，部分漏计）",
			"log_path":  logPath,
			"generated": generated,
			"stale":     false,
		})
		return
	}
	// 实时统计失败（GitHub 拉取 / 日志读取出错）：降级返回上次缓存
	log.Printf("[警告] 实时下载量统计失败，降级返回缓存: %v", err)
	cached, cachedAt, lerr := s.loadStats()
	if lerr != nil || cached == nil {
		writeErr(w, http.StatusInternalServerError, "统计失败且无可用缓存: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"items":     cached,
		"approx":    true,
		"note":      "近似值（仅源站回源请求；CDN 边缘命中不回源，部分漏计）；当前为缓存（实时获取失败）",
		"log_path":  logPath,
		"generated": cachedAt,
		"stale":     true,
	})
}

// ---------- 扩展：包内容预览/编辑、搜索、批量操作、更新对比、IP 黑名单 ----------

// maxBatchIDs 批量操作单次最多处理的插件数量。
const maxBatchIDs = 100

// inboxPackagePath 返回待审核包的本地路径（data/incoming/<id>_<version>.zip）。
// id/version 均已通过 safeFilename 校验，fmt.Sprintf 不会产生穿越段。
func (s *Store) inboxPackagePath(id, version string) (string, bool) {
	if !safeFilename(id) || !safeFilename(version) {
		return "", false
	}
	name := fmt.Sprintf("%s_%s.zip", id, version)
	return safeJoin(s.inbox, name)
}

// loadInboxZip 读取指定 id 的待审核 zip，返回 zip 读取器与原始字节。
func (s *Store) loadInboxZip(id string) (*zip.Reader, []byte, *QueueEntry, error) {
	entry, err := s.getEntry(id)
	if err != nil {
		return nil, nil, nil, err
	}
	path, ok := s.inboxPackagePath(entry.ID, entry.Version)
	if !ok {
		return nil, nil, nil, fmt.Errorf("插件 id/version 生成的不安全路径")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, nil, err
	}
	return zr, data, entry, nil
}

// zipFileInfoList 遍历 zip，返回前端展示用的文件列表（含是否目录/文本）。
func zipFileInfoList(zr *zip.Reader) []map[string]any {
	files := make([]map[string]any, 0, len(zr.File))
	for _, f := range zr.File {
		isDir := f.FileInfo().IsDir()
		isText := false
		if !isDir {
			rc, err := f.Open()
			if err == nil {
				content, rerr := io.ReadAll(io.LimitReader(rc, maxPreviewSize))
				rc.Close()
				if rerr == nil {
					isText = isTextContent(content)
				}
			}
		}
		files = append(files, map[string]any{
			"path":   f.Name,
			"size":   f.UncompressedSize64,
			"isDir":  isDir,
			"isText": isText,
		})
	}
	return files
}

// readInboxManifest 解析待审核包根目录的 plugin.json。
func readInboxManifest(zr *zip.Reader) (*Manifest, error) {
	content, err := readZipFile(zr, "plugin.json")
	if err != nil {
		return nil, fmt.Errorf("包内缺少 plugin.json")
	}
	var m Manifest
	if err := json.Unmarshal(content, &m); err != nil {
		return nil, fmt.Errorf("plugin.json 解析失败: %w", err)
	}
	return &m, nil
}

// handleInspect 预览待审核包内容：返回文件树 + plugin.json 内容。
// GET /api/inspect?id=<pluginId>
func (s *Store) handleInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" || !safeFilename(id) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	zr, _, entry, err := s.loadInboxZip(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "待审核包不存在或已被清理")
		return
	}
	manifest, merr := readInboxManifest(zr)
	var manifestOut any
	if merr == nil && manifest != nil {
		manifestOut = manifest
	}
	s.writeAudit(auditEvent{Event: auditEventInspect, User: userFrom(r.Context()), IP: clientIP(r), Target: id, Result: "ok", Detail: "version=" + entry.Version})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"files":    zipFileInfoList(zr),
		"manifest": manifestOut,
	})
}

// handleInspectFile 预览包内单个文本文件内容。
// GET /api/inspect/file?id=<pluginId>&path=<filePath>
func (s *Store) handleInspectFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	filePath := r.URL.Query().Get("path")
	if id == "" || !safeFilename(id) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	if _, ok := normalizeZipPath(filePath); !ok {
		writeErr(w, http.StatusBadRequest, "参数 path 非法")
		return
	}
	zr, _, _, err := s.loadInboxZip(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "待审核包不存在或已被清理")
		return
	}
	content, err := readZipFile(zr, filePath)
	if err != nil {
		writeErr(w, http.StatusNotFound, "文件不存在")
		return
	}
	if int64(len(content)) > maxPreviewSize {
		writeErr(w, http.StatusBadRequest, "文件超过 1MB，无法预览")
		return
	}
	if !isTextContent(content) {
		writeErr(w, http.StatusBadRequest, "二进制文件，无法预览")
		return
	}
	s.writeAudit(auditEvent{Event: auditEventInspect, User: userFrom(r.Context()), IP: clientIP(r), Target: id, Result: "ok", Detail: "file=" + filePath})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"content": string(content),
		"isText":  true,
	})
}

// handleInspectEdit 修改包内文本文件内容并重新打包覆盖待审核包。
// POST /api/inspect/edit body: {"id","path","content"}
func (s *Store) handleInspectEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		ID      string `json:"id"`
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPreviewSize+(1<<20))).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.ID == "" || !safeFilename(req.ID) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	cleaned, ok := normalizeZipPath(req.Path)
	if !ok {
		writeErr(w, http.StatusBadRequest, "参数 path 非法")
		return
	}
	newContent := []byte(req.Content)
	if int64(len(newContent)) > maxPreviewSize {
		writeErr(w, http.StatusBadRequest, "新内容超过 1MB，无法保存")
		return
	}
	if !isTextContent(newContent) {
		writeErr(w, http.StatusBadRequest, "仅支持编辑文本文件")
		return
	}
	user := userFrom(r.Context())
	zr, data, entry, err := s.loadInboxZip(req.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "待审核包不存在或已被清理")
		return
	}
	// 只允许编辑已存在的文本文件：先确认原文件为文本
	orig, err := readZipFile(zr, cleaned)
	if err != nil {
		writeErr(w, http.StatusNotFound, "文件不存在")
		return
	}
	if int64(len(orig)) > maxPreviewSize || !isTextContent(orig) {
		writeErr(w, http.StatusBadRequest, "二进制文件，无法编辑")
		return
	}
	newZip, err := replaceZipFile(data, cleaned, newContent)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "重新打包失败")
		return
	}
	path, ok := s.inboxPackagePath(entry.ID, entry.Version)
	if !ok {
		writeErr(w, http.StatusBadRequest, "插件 id/version 生成的不安全路径")
		return
	}
	if err := atomicWrite(path, newZip, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存修改后的包失败")
		return
	}
	log.Printf("[信息] 管理员 %s 修改了插件 %s v%s 包内文件 %s", user, entry.ID, entry.Version, cleaned)
	s.writeAudit(auditEvent{Event: auditEventInspectEdit, User: user, IP: clientIP(r), Target: req.ID, Result: "ok", Detail: "file=" + cleaned})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "已修改并重新打包",
	})
}

// handleQueueSearch 搜索/筛选审核条目。
// GET /api/queue/search?q=&status=&from=&to=（参数均可选）
func (s *Store) handleQueueSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	var from, to time.Time
	if v := strings.TrimSpace(r.URL.Query().Get("from")); v != "" {
		t, err := time.ParseInLocation("2006-01-02", v, time.Local)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "参数 from 格式非法（应为 YYYY-MM-DD）")
			return
		}
		from = t
	}
	if v := strings.TrimSpace(r.URL.Query().Get("to")); v != "" {
		t, err := time.ParseInLocation("2006-01-02", v, time.Local)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "参数 to 格式非法（应为 YYYY-MM-DD）")
			return
		}
		to = t.Add(24*time.Hour - time.Second) // 含当天
	}

	list := s.listEntries()
	items := make([]*QueueEntry, 0, len(list))
	for _, e := range list {
		if q != "" {
			haystack := strings.ToLower(e.ID + " " + e.Name + " " + e.Uploader)
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		if statusFilter != "" && statusFilter != "all" && string(e.Status) != statusFilter {
			continue
		}
		if !from.IsZero() && e.UploadedAt.Before(from) {
			continue
		}
		if !to.IsZero() && e.UploadedAt.After(to) {
			continue
		}
		items = append(items, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "items": items})
}

// approveCore 是审核通过的核心逻辑（发布到商店仓库 -> 标记 approved -> 清理暂存包）。
// 供 handleApprove（单条）与 handleQueueBatch（批量）共用；发布未配置时返回错误。
func (s *Store) approveCore(r *http.Request, id, user string) error {
	entry, err := s.getEntry(id)
	if err != nil {
		return fmt.Errorf("找不到该插件包记录")
	}
	if entry.Status == StatusApproved {
		return fmt.Errorf("已通过审核")
	}
	if !s.ghEnabled {
		return fmt.Errorf("GitHub 发布未配置，无法发布")
	}
	if err := s.publishToStore(r, entry); err != nil {
		return fmt.Errorf("发布到商店仓库失败: %w", sanitizeGHErr(err))
	}
	if err := s.Approve(id, user); err != nil {
		log.Printf("[警告] 标记 approved 失败: %v", err)
	}
	s.CleanupPackage(id)
	log.Printf("[信息] 插件 %s v%s 已由 %s 审核通过并发布", entry.ID, entry.Version, user)
	s.writeAudit(auditEvent{Event: auditEventApprove, User: user, IP: clientIP(r), Target: id, Result: "ok", Detail: "version=" + entry.Version})
	return nil
}

// rejectCore 是拒绝插件的核心逻辑（写拒绝原因文件 + 状态改 rejected + 清理暂存包）。
// 供 handleReject（单条）与 handleQueueBatch（批量）共用。
func (s *Store) rejectCore(r *http.Request, id, user, reason string) error {
	if err := s.Reject(id, user, strings.TrimSpace(reason)); err != nil {
		return fmt.Errorf("找不到该插件包记录")
	}
	log.Printf("[信息] 插件 %s 已由 %s 拒绝", id, user)
	s.writeAudit(auditEvent{Event: auditEventReject, User: user, IP: clientIP(r), Target: id, Result: "ok", Detail: strings.TrimSpace(reason)})
	return nil
}

// handleQueueBatch 批量通过/拒绝。
// POST /api/queue/batch body: {"action":"approve"|"reject","ids":[...],"reason":"..."}
func (s *Store) handleQueueBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		Action string   `json:"action"`
		IDs    []string `json:"ids"`
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	if req.Action != "approve" && req.Action != "reject" {
		writeErr(w, http.StatusBadRequest, "action 仅支持 approve 或 reject")
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, http.StatusBadRequest, "ids 不能为空")
		return
	}
	if len(req.IDs) > maxBatchIDs {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("ids 最多 %d 个", maxBatchIDs))
		return
	}
	user := userFrom(r.Context())
	succeeded := make([]string, 0, len(req.IDs))
	type failItem struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	failed := make([]failItem, 0)
	for _, id := range req.IDs {
		id = strings.TrimSpace(id)
		var err error
		if !safeFilename(id) {
			err = fmt.Errorf("参数 id 非法")
		} else if req.Action == "approve" {
			err = s.approveCore(r, id, user)
		} else {
			err = s.rejectCore(r, id, user, req.Reason)
		}
		if err != nil {
			failed = append(failed, failItem{ID: id, Error: err.Error()})
			continue
		}
		succeeded = append(succeeded, id)
	}
	event := auditEventBatchReject
	if req.Action == "approve" {
		event = auditEventBatchApprove
	}
	s.writeAudit(auditEvent{
		Event: event, User: user, IP: clientIP(r),
		Result: "ok", Detail: fmt.Sprintf("成功 %d 个，失败 %d 个", len(succeeded), len(failed)),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"succeeded": succeeded,
		"failed":    failed,
	})
}

// handleDiff 对比待审核更新包与 index.json 已发布版本的差异。
// GET /api/diff?id=<pluginId>
func (s *Store) handleDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" || !safeFilename(id) {
		writeErr(w, http.StatusBadRequest, "参数 id 非法")
		return
	}
	if !s.ghEnabled {
		writeErr(w, http.StatusServiceUnavailable, "GitHub 未配置，无法对比已发布版本")
		return
	}
	zr, _, _, err := s.loadInboxZip(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "待审核包不存在或已被清理")
		return
	}
	idx, err := s.publisher.fetchIndex(r.Context(), s.cfg.GHBranch)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "获取 index.json 失败: "+sanitizeGHErr(err))
		return
	}
	var oldEntry *indexEntry
	var latestTS int64 = -1
	for i := range idx.Plugins {
		if idx.Plugins[i].ID != id {
			continue
		}
		if idx.Plugins[i].LastUpdate > latestTS {
			latestTS = idx.Plugins[i].LastUpdate
			oldEntry = &idx.Plugins[i]
		}
	}
	if oldEntry == nil {
		writeErr(w, http.StatusBadRequest, "不是更新包，无需对比")
		return
	}
	newManifest, err := readInboxManifest(zr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "解析待审核包 plugin.json 失败")
		return
	}

	manifestChanges := map[string]map[string]string{}
	addChange := func(field, oldV, newV string) {
		if oldV != newV {
			manifestChanges[field] = map[string]string{"old": oldV, "new": newV}
		}
	}
	addChange("version", oldEntry.Version, newManifest.Version)
	addChange("name", oldEntry.Name.Default, newManifest.Name.Default)
	addChange("description", oldEntry.Description.Default, newManifest.Description.Default)
	addChange("tags", strings.Join(oldEntry.Tags, ", "), strings.Join(newManifest.inferTags(), ", "))

	// 已发布包内文件列表（用于文件级对比）
	pkgRemote := fmt.Sprintf("packages/%s_%s.zip", id, oldEntry.Version)
	oldData, _, err := s.publisher.getFile(r.Context(), pkgRemote, s.cfg.GHBranch)
	fileChanges := map[string][]string{"added": {}, "removed": {}, "modified": {}}
	if err == nil && len(oldData) > 0 {
		oldZr, oerr := zip.NewReader(bytes.NewReader(oldData), int64(len(oldData)))
		if oerr == nil {
			oldFiles := map[string]string{}
			for _, f := range oldZr.File {
				if f.FileInfo().IsDir() {
					continue
				}
				content, _ := readZipFile(oldZr, f.Name)
				oldFiles[f.Name] = fmt.Sprintf("%d:%x", len(content), sha256Sum(content))
			}
			newFiles := map[string]string{}
			for _, f := range zr.File {
				if f.FileInfo().IsDir() {
					continue
				}
				content, _ := readZipFile(zr, f.Name)
				newFiles[f.Name] = fmt.Sprintf("%d:%x", len(content), sha256Sum(content))
			}
			for p, h := range newFiles {
				oldH, existed := oldFiles[p]
				if !existed {
					fileChanges["added"] = append(fileChanges["added"], p)
				} else if oldH != h {
					fileChanges["modified"] = append(fileChanges["modified"], p)
				}
			}
			for p := range oldFiles {
				if _, existed := newFiles[p]; !existed {
					fileChanges["removed"] = append(fileChanges["removed"], p)
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"oldVersion":      oldEntry.Version,
		"newVersion":      newManifest.Version,
		"manifestChanges": manifestChanges,
		"fileChanges":     fileChanges,
	})
}

// handleIPBanList 查看当前仍生效的 IP 黑名单。
// GET /api/ipban
func (s *Store) handleIPBanList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	banned := s.loginRL.ListBanned()
	items := make([]map[string]any, 0, len(banned))
	for ip, e := range banned {
		lastFail := ""
		if !e.LastFail.IsZero() {
			lastFail = e.LastFail.UTC().Format(time.RFC3339)
		}
		items = append(items, map[string]any{
			"ip":       ip,
			"until":    e.LockedUntil.UTC().Format(time.RFC3339),
			"fails":    e.Fails,
			"lastFail": lastFail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "banned": items})
}

// handleIPBanAdd 手动封禁 IP。
// POST /api/ipban/add body: {"ip":"1.2.3.4","duration":"24h"|"7d"|"permanent","reason":"..."}
func (s *Store) handleIPBanAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		IP       string `json:"ip"`
		Duration string `json:"duration"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if net.ParseIP(req.IP) == nil {
		writeErr(w, http.StatusBadRequest, "IP 格式非法")
		return
	}
	var until time.Time
	switch req.Duration {
	case "24h":
		until = time.Now().Add(24 * time.Hour)
	case "7d":
		until = time.Now().Add(7 * 24 * time.Hour)
	case "permanent":
		until = time.Now().AddDate(100, 0, 0) // 100 年，等价永久
	default:
		writeErr(w, http.StatusBadRequest, "duration 仅支持 24h、7d 或 permanent")
		return
	}
	s.loginRL.Ban(req.IP, until)
	untilStr := until.UTC().Format(time.RFC3339)
	s.writeAudit(auditEvent{
		Event: auditEventIPBanAdd, User: userFrom(r.Context()), IP: clientIP(r), Target: req.IP,
		Result: "ok", Detail: "until=" + untilStr + "; reason=" + strings.TrimSpace(req.Reason),
	})
	log.Printf("[安全] 管理员 %s 手动封禁 IP %s 至 %s", userFrom(r.Context()), req.IP, untilStr)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "已封禁 " + req.IP + " 至 " + untilStr,
	})
}

// handleIPBanRemove 手动解封 IP。
// POST /api/ipban/remove body: {"ip":"1.2.3.4"}
func (s *Store) handleIPBanRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if net.ParseIP(req.IP) == nil {
		writeErr(w, http.StatusBadRequest, "IP 格式非法")
		return
	}
	s.loginRL.Unban(req.IP)
	s.writeAudit(auditEvent{
		Event: auditEventIPBanRemove, User: userFrom(r.Context()), IP: clientIP(r), Target: req.IP,
		Result: "ok",
	})
	log.Printf("[安全] 管理员 %s 手动解封 IP %s", userFrom(r.Context()), req.IP)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "已解封 " + req.IP,
	})
}

// sha256Sum 返回内容的 SHA-256 十六进制摘要，用于文件内容变化对比。
func sha256Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
