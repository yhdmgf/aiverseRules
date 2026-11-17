package main

// 账号维度的登录失败锁定。
//
// 语义：在 window 窗口内累计失败达到 maxFails 次，则锁定 lockDur 时长。
// 本次配置为「1 分钟内失败 3 次 → 锁 30 分钟」，与 IP 维度（data/ipban.json）
// 同步生效；两者任一命中即拒绝登录，成功登录时两个维度一起清零。
//
// 实现：复用 security.go 中的 rateLimiter，仅补充"失败计数带时间窗"的能力——
// 原 rateLimiter 的失败计数是永久累计的，这里让计数在窗口外自动重置，避免
// 历史失败长期挂着误伤正常用户。

import (
	"path/filepath"
	"time"
)

// newWindowedRateLimiter 创建带失败计数时间窗的限流器。
// 与 newRateLimiter 的区别：window 内的失败才会累计，超出窗口自动归零。
func newWindowedRateLimiter(path string, maxFails int, window, lockDur time.Duration) *rateLimiter {
	rl := newRateLimiter(path, maxFails, lockDur)
	rl.window = window
	return rl
}

// BlockedUntil 返回该 key 是否处于锁定状态，并附带锁定截止时间。
// 未锁定时 ok=false；锁定中 ok=true 且 until 为 RFC3339 可序列化的绝对时间。
func (rl *rateLimiter) BlockedUntil(key string) (ok bool, until time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, found := rl.entries[key]
	if !found {
		return false, time.Time{}
	}
	if e.LockedUntil.After(time.Now()) {
		return true, e.LockedUntil
	}
	// 锁定已过期，顺带清理（Blocked 也会做，但这里需要写操作所以显式处理）
	if !e.LockedUntil.IsZero() {
		delete(rl.entries, key)
		rl.save()
	}
	return false, time.Time{}
}

// newAccountRateLimiter 创建账号维度的限流器，持久化到 data/accountban.json。
// key 为登录用户名（已通过 safeFilename 校验）。
func newAccountRateLimiter(dataDir string) *rateLimiter {
	return newWindowedRateLimiter(
		filepath.Join(dataDir, "accountban.json"),
		3,             // 1 分钟内失败 3 次
		time.Minute,   // 失败计数窗口
		30*time.Minute, // 锁定时长
	)
}

// cleanupExpired 清理限流文件中已过期的条目（锁定期结束 + 失败窗口已过），
// 防止文件随时间无限膨胀。启动时与登录成功时调用。
func (rl *rateLimiter) cleanupExpired() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	changed := false
	for key, e := range rl.entries {
		lockExpired := e.LockedUntil.IsZero() || e.LockedUntil.Before(now)
		failExpired := e.LastFail.IsZero() || now.Sub(e.LastFail) > rl.window
		if lockExpired && failExpired {
			delete(rl.entries, key)
			changed = true
		}
	}
	if changed {
		rl.save()
	}
}

// accountRLKey 把登录用户名转成限流 key。username 已由 safeFilename 校验过合法，
// 这里再做一次兜底，避免恶意字符串污染持久化文件名。
func accountRLKey(username string) (string, bool) {
	if username == "" || !safeFilename(username) {
		return "", false
	}
	return username, true
}

// accountLock 供 handler 调用：返回账号维度是否被锁定及截止时间。
func (s *Store) accountLock(username string) (bool, time.Time) {
	key, ok := accountRLKey(username)
	if !ok {
		return false, time.Time{}
	}
	return s.accountRL.BlockedUntil(key)
}

// accountFail 记录一次账号维度的登录失败。
func (s *Store) accountFail(username string) {
	if key, ok := accountRLKey(username); ok {
		s.accountRL.Fail(key)
	}
}

// accountSuccess 清零账号维度的失败计数（登录成功时调用）。
func (s *Store) accountSuccess(username string) {
	if key, ok := accountRLKey(username); ok {
		s.accountRL.Success(key)
	}
}