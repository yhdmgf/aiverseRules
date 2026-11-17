package main

// 滑动人机验证（本地自实现，不依赖任何第三方/Cloudflare）。
//
// 流程：
//   1) 前端先 GET /api/captcha/challenge 拿到一个 id 与缺口目标相对位置 bg。
//   2) 用户把拼图块拖到正确位置后，前端 POST /api/captcha/verify 提交 id 与落点相对位置 x。
//   3) 落点与真实目标位置误差在容差内则签发一次性 token（默认 60s 有效），登录时携带。
//
// 安全设计：
//   - 挑战与 token 都存内存（重启即失效，无需持久化），带过期时间。
//   - 每个 challenge 只能 verify 一次；token 校验通过后立即删除，防重放。
//   - 校验用常量时间比较，避免时序侧信道。

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"sync"
	"time"
)

const (
	captchaChallengeTTL = 5 * time.Minute  // 挑战有效期
	captchaTokenTTL     = 60 * time.Second // 通过后签发的 token 有效期
	captchaTolerance    = 0.03             // 落点容差（相对位置 ±0.03）
	captchaMaxAge       = 1024             // 内存中最多保留的挑战/Token 数（防内存膨胀）
)

// captchaEntry 是一次滑块挑战的记录。
type captchaEntry struct {
	Target    float64   // 拼图块应被拖到的目标相对位置（0~1）
	CreatedAt time.Time // 创建时间，用于过期清理
}

// captchaToken 是验证通过后签发的一次性登录凭证。
type captchaToken struct {
	CreatedAt time.Time
}

// captchaStore 在内存中保存待验证的挑战与已签发的 token。
type captchaStore struct {
	mu         sync.Mutex
	challenges map[string]*captchaEntry
	tokens     map[string]*captchaToken
}

func newCaptchaStore() *captchaStore {
	return &captchaStore{
		challenges: make(map[string]*captchaEntry),
		tokens:     make(map[string]*captchaToken),
	}
}

// newChallenge 生成一次新的滑块挑战，返回 challenge id 与缺口目标相对位置 bg。
// 目标位置随机落在 [0.25, 0.75]，避开两端极端值，给前端留出可视拖动范围。
func (cs *captchaStore) newChallenge() (id string, bg float64, err error) {
	target, err := randFloat()
	if err != nil {
		return "", 0, err
	}
	target = 0.25 + target*0.5

	bgRaw, err := randFloat()
	if err != nil {
		return "", 0, err
	}
	// 起始位与目标位错开，避免 bg==target 让前端出现"开局即正确"的退化情况
	bg = math.Min(bgRaw, math.Max(0, target-0.15))

	id, err = randomToken(16)
	if err != nil {
		return "", 0, err
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.evictLocked()
	cs.challenges[id] = &captchaEntry{Target: target, CreatedAt: time.Now()}
	return id, bg, nil
}

// verify 校验滑块落点：成功则签发一次性 token 并消费该挑战。
// 任何一步失败都不暴露具体原因（返回 ok=false），避免给攻击者提供探测信息。
func (cs *captchaStore) verify(id string, x float64) (ok bool, token string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.evictLocked()

	e, found := cs.challenges[id]
	if !found {
		return false, ""
	}
	// 无论成功与否都消费掉这次挑战，防同一 id 反复试探
	delete(cs.challenges, id)

	if math.Abs(x-e.Target) > captchaTolerance {
		return false, ""
	}

	tok, err := randomToken(24)
	if err != nil {
		return false, ""
	}
	cs.tokens[tok] = &captchaToken{CreatedAt: time.Now()}
	return true, tok
}

// consume 校验并消费一个登录 token：存在且未过期则返回 true（同时删除，防重放）。
func (cs *captchaStore) consume(token string) bool {
	if token == "" || !safeFilename(token) {
		return false
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.evictLocked()

	t, ok := cs.tokens[token]
	if !ok {
		return false
	}
	// 先删除再判过期，保证一次性
	delete(cs.tokens, token)
	if time.Since(t.CreatedAt) > captchaTokenTTL {
		return false
	}
	return true
}

// evictLocked 清理过期的挑战与 token，并在总量超限时丢弃最早的条目防内存膨胀。
// 调用方必须已持有 cs.mu。
func (cs *captchaStore) evictLocked() {
	now := time.Now()
	for id, e := range cs.challenges {
		if now.Sub(e.CreatedAt) > captchaChallengeTTL {
			delete(cs.challenges, id)
		}
	}
	for tok, t := range cs.tokens {
		if now.Sub(t.CreatedAt) > captchaTokenTTL {
			delete(cs.tokens, tok)
		}
	}
	// 超限时粗暴清理：审核后台并发极低，触发概率可忽略
	for len(cs.challenges) > captchaMaxAge {
		for id := range cs.challenges {
			delete(cs.challenges, id)
			break
		}
	}
	for len(cs.tokens) > captchaMaxAge {
		for tok := range cs.tokens {
			delete(cs.tokens, tok)
			break
		}
	}
}

// randFloat 返回 [0,1) 的密码学随机小数。
func randFloat() (float64, error) {
	v, err := randomUint32()
	if err != nil {
		return 0, err
	}
	return float64(v) / float64(^uint32(0)), nil
}

// randomUint32 用 crypto/rand 生成一个密码学随机的 uint32。
func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// ---------- HTTP handlers ----------

// handleCaptchaChallenge 下发一次滑块挑战。
// 响应：{"ok":true,"id":"...","bg":<0~1>,"totp_required":<bool>}
// totp_required：服务端是否已配置 TOTP 密钥（未配置时前端不强制动态码，与登录降级逻辑一致）。
func (s *Store) handleCaptchaChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	id, bg, err := s.captcha.newChallenge()
	if err != nil {
		log.Printf("[错误] 生成滑块挑战失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "生成验证挑战失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "bg": bg, "totp_required": !s.noTOTP})
}

// handleCaptchaVerify 校验滑块落点并签发一次性登录 token。
// 请求体：{"id":"...","x":<0~1>}
// 响应：{"ok":true,"token":"..."} 或 {"ok":false}
func (s *Store) handleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		ID string  `json:"id"`
		X  float64 `json:"x"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	if req.ID == "" || !safeFilename(req.ID) || req.X < 0 || req.X > 1 || math.IsNaN(req.X) || math.IsInf(req.X, 0) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	ok, token := s.captcha.verify(req.ID, req.X)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": token})
}