package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---------- 请求上下文中的当前用户 ----------

type ctxKey int

const ctxUserKey ctxKey = 1

// withUser 把当前登录用户名注入请求 context。
func withUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, ctxUserKey, user)
}

// userFrom 从请求 context 取出当前登录用户名。
func userFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxUserKey).(string); ok {
		return v
	}
	return "unknown"
}

// ---------- 安全响应头 ----------

// securityHeaders 为所有响应添加基础安全头。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'")
		h.Set("X-XSS-Protection", "0") // 现代浏览器已废弃，显式关闭避免误用
		next.ServeHTTP(w, r)
	})
}

// ---------- 限流器（登录/上传防刷） ----------

// rateEntry 记录某个 key（如 IP 或账号）的连续失败次数与锁定截止时间。
type rateEntry struct {
	Fails       int       `json:"fails"`
	LastFail    time.Time `json:"last_fail,omitempty"` // 最近一次失败时间，用于判断是否仍在计数窗口内
	LockedUntil time.Time `json:"locked_until,omitempty"`
}

// rateLimiter 是一个基于文件的简单固定窗口限流器。
// 连续失败达到阈值后锁定一段时间；成功操作会清零计数。
// 若 window > 0，则只有窗口内的失败才累计（超出窗口自动归零）。
type rateLimiter struct {
	mu       sync.Mutex
	path     string
	maxFails int
	lockDur  time.Duration
	window   time.Duration // 失败计数窗口；0 表示沿用旧语义（失败永久累计直至锁定）
	entries  map[string]*rateEntry
}

func newRateLimiter(path string, maxFails int, lockDur time.Duration) *rateLimiter {
	rl := &rateLimiter{
		path:     path,
		maxFails: maxFails,
		lockDur:  lockDur,
		entries:  make(map[string]*rateEntry),
	}
	rl.load()
	return rl
}

func (rl *rateLimiter) load() {
	data, err := os.ReadFile(rl.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &rl.entries)
}

func (rl *rateLimiter) save() {
	data, err := json.MarshalIndent(rl.entries, "", "  ")
	if err != nil {
		return
	}
	if err := atomicWrite(rl.path, data, 0o600); err != nil {
		log.Printf("[错误] 写限流文件失败: %v", err)
	}
}

// Blocked 返回该 key 当前是否处于锁定状态。
func (rl *rateLimiter) Blocked(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[key]
	if !ok {
		return false
	}
	if e.LockedUntil.After(time.Now()) {
		return true
	}
	// 锁定已过期，顺带清理
	if !e.LockedUntil.IsZero() {
		delete(rl.entries, key)
		rl.save()
	}
	return false
}

// Fail 记录一次失败；达到阈值则锁定。
// 若启用了 window，则上一次失败已超出窗口时先把计数归零再累加，
// 实现“窗口内连续 N 次”而不是“永久累计 N 次”。
func (rl *rateLimiter) Fail(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	e := rl.entries[key]
	if e == nil {
		e = &rateEntry{}
		rl.entries[key] = e
	}
	if rl.window > 0 && !e.LastFail.IsZero() && now.Sub(e.LastFail) > rl.window {
		e.Fails = 0
	}
	e.Fails++
	e.LastFail = now
	if e.Fails >= rl.maxFails {
		e.LockedUntil = now.Add(rl.lockDur)
		e.Fails = 0
		e.LastFail = time.Time{} // 锁定期内不再累计，等解锁后重新计
	}
	rl.save()
}

// Success 清零该 key 的失败计数。
func (rl *rateLimiter) Success(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.entries[key]; ok {
		delete(rl.entries, key)
		rl.save()
	}
}

// clientIP 从请求中提取客户端真实 IP。
//
// 安全说明：X-Forwarded-For 头可由客户端伪造。本服务仅监听 127.0.0.1、由本机
// nginx 反代对外，因此客户端直连到我们的 RemoteAddr 就是 nginx 的 127.0.0.1。
// 为了不因信任伪造头而绕过 IP 锁，默认以 RemoteAddr 为准（即所有外部请求都会
// 归为 127.0.0.1，IP 维度限流退化为全局限流）。
// 仅当通过 STORE_TRUST_PROXY=1 显式声明“前面是可信反代（nginx 已用
// $proxy_add_x_forwarded_for 覆盖而非追加 XFF）”时，才采信 XFF 首段，
// 以便多用户场景下按真实来源 IP 限流。未设置该变量时一律以 RemoteAddr 为准。
func clientIP(r *http.Request) string {
	if os.Getenv("STORE_TRUST_PROXY") == "1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- Session 管理 ----------

// session 是一条登录会话记录，持久化到 data/sessions/。
type session struct {
	User      string    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// newSessionStore 创建 session 存储，并清理已过期的旧 session。
func newSessionStore(dir string, ttl time.Duration) *sessionStore {
	_ = os.MkdirAll(dir, 0o700)
	ss := &sessionStore{dir: dir, ttl: ttl}
	ss.cleanup()
	return ss
}

type sessionStore struct {
	dir string
	ttl time.Duration
}

func (ss *sessionStore) sessionPath(token string) string {
	return filepath.Join(ss.dir, "sess_"+token+".json")
}

// Create 生成新 session（随机 token），持久化后返回 token。
func (ss *sessionStore) Create(user string) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now()
	sess := session{User: user, CreatedAt: now, ExpiresAt: now.Add(ss.ttl)}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	if err := atomicWrite(ss.sessionPath(token), data, 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// Get 校验 token 是否有效（存在且未过期），有效则返回用户名。
func (ss *sessionStore) Get(token string) (string, bool) {
	if token == "" || !safeFilename(token) {
		return "", false
	}
	data, err := os.ReadFile(ss.sessionPath(token))
	if err != nil {
		return "", false
	}
	var sess session
	if err := json.Unmarshal(data, &sess); err != nil {
		return "", false
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = os.Remove(ss.sessionPath(token))
		return "", false
	}
	return sess.User, true
}

// Delete 注销 session。
func (ss *sessionStore) Delete(token string) {
	if token == "" || !safeFilename(token) {
		return
	}
	_ = os.Remove(ss.sessionPath(token))
}

// cleanup 启动时删除所有过期 session 文件。
func (ss *sessionStore) cleanup() {
	files, err := filepath.Glob(filepath.Join(ss.dir, "sess_*.json"))
	if err != nil {
		return
	}
	now := time.Now()
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var sess session
		if err := json.Unmarshal(data, &sess); err != nil {
			_ = os.Remove(f)
			continue
		}
		if now.After(sess.ExpiresAt) {
			_ = os.Remove(f)
		}
	}
}

// randomToken 生成 n 字节的密码学随机 token（十六进制编码）。
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// verifyPassword 用 bcrypt 校验明文密码与存储的哈希。
// 使用 constant time 比较，避免时序侧信道。
func verifyPassword(hash, plain string) bool {
	if hash == "" || plain == "" {
		return false
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		return false
	}
	return true
}

// hashPassword 生成 bcrypt 哈希，供生成 STORE_ADMIN_PASS_HASH 使用。
func hashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// safeEqual 常量时间字符串比较（用于用户名比对）。
func safeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------- 路径与文件名安全 ----------

// safeFilename 判断 s 是否是安全的单段文件名（不含路径分隔符、.. 等）。
// 用于拼接 data 目录下文件路径前的防护。
func safeFilename(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	if strings.ContainsAny(s, "/\\") {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	return true
}

// safeJoin 安全地把 base 与 rel 拼起来，确保结果仍在 base 内，防路径穿越。
// 返回清理后的绝对/相对路径与是否安全。
func safeJoin(base, rel string) (string, bool) {
	cleanBase := filepath.Clean(base)
	full := filepath.Clean(filepath.Join(cleanBase, rel))
	// 必须等于 base 自身，或以 base + 分隔符为前缀
	if full == cleanBase {
		return full, true
	}
	if strings.HasPrefix(full, cleanBase+string(os.PathSeparator)) {
		return full, true
	}
	return "", false
}

// atomicWrite 先写临时文件再 rename，避免半写文件。
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
