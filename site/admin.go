package main

import (
	"encoding/json"
	"log"
	"net/http"
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
// 校验顺序：IP 锁 → 账号锁 → 滑块 captcha_token → 用户名/密码 → TOTP 动态码。
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

	// 1) IP 维度锁定短路（仅凭 IP 就拒绝，不泄露账号相关信息）
	if locked, until := s.loginRL.BlockedUntil(ip); locked {
		log.Printf("[安全] 登录拒绝：IP 处于锁定期（IP=%s）", ip)
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
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"ok":           false,
			"error":        "失败次数过多，请稍后再试",
			"locked":       true,
			"locked_until": until.UTC().Format(time.RFC3339),
		})
		return
	}

	// 3) 滑块人机验证：captcha_token 必须有效且未使用过
	if !s.captcha.consume(req.CaptchaToken) {
		s.recordLoginFailure(ip, req.Username)
		log.Printf("[安全] 登录失败：滑块验证未通过（IP=%s，用户名=%q）", ip, req.Username)
		writeErr(w, http.StatusUnauthorized, "人机验证未通过，请重试")
		return
	}

	// 4) 校验凭据；用户名用常量时间比较，密码用 bcrypt
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

	// 6) 全部通过：清零两个维度的失败计数 + 建 session + 下发 Cookie
	s.loginRL.Success(ip)
	s.accountSuccess(req.Username)

	token, err := s.sessions.Create(req.Username)
	if err != nil {
		log.Printf("[错误] 创建 session 失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "创建会话失败")
		return
	}
	log.Printf("[信息] 管理员 %s 登录成功（IP=%s）", req.Username, ip)

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
func (s *Store) recordLoginFailure(ip, username string) {
	s.loginRL.Fail(ip)
	s.accountFail(username)
}

// handleLogout 注销当前会话。
func (s *Store) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
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
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}
