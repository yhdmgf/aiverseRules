package main

// 算术人机验证（本地自实现，不依赖任何第三方/Cloudflare）。
//
// 流程：
//   1) 前端先 GET /api/captcha/challenge 拿到一个 id 与算术题 question（如 "3+5"）。
//   2) 用户填写答案后，前端 POST /api/captcha/verify 提交 id 与 answer。
//   3) 答案正确则签发一次性 token（默认 60s 有效），登录时携带。
//
// 安全设计：
//   - 挑战与 token 都存内存（重启即失效，无需持久化），带过期时间。
//   - 每个 challenge 只能 verify 一次；token 校验通过后立即删除，防重放。
//   - 答案用常量时间比较，避免时序侧信道。

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	captchaChallengeTTL = 5 * time.Minute  // 挑战有效期
	captchaTokenTTL     = 60 * time.Second // 通过后签发的 token 有效期
	captchaMaxAge       = 1024             // 内存中最多保留的挑战/Token 数（防内存膨胀）
)

// captchaEntry 是一次算术题挑战的记录。
type captchaEntry struct {
	Answer    string    // 正确答案（十进制字符串）
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

// randInt 返回 [lo,hi] 范围内的密码学随机整数。
func randInt(lo, hi int) (int, error) {
	if hi <= lo {
		return lo, nil
	}
	n, err := randomUint32()
	if err != nil {
		return 0, err
	}
	return lo + int(n%uint32(hi-lo+1)), nil
}

// newChallenge 生成一次新的算术题挑战，返回 id 与题目文本（如 "7+5"）。
// 两个操作数落在 [2,9]，加减法都保证结果非负，避免出现负数干扰用户。
func (cs *captchaStore) newChallenge() (id string, question string, err error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.evictLocked()

	a, err := randInt(2, 9)
	if err != nil {
		return "", "", err
	}
	b, err := randInt(2, 9)
	if err != nil {
		return "", "", err
	}

	var answer int
	if a >= b {
		// 一半概率出加法，一半概率出减法（结果非负）
		coin, err2 := randInt(0, 1)
		if err2 != nil {
			return "", "", err2
		}
		if coin == 0 {
			question = strconv.Itoa(a) + "+" + strconv.Itoa(b)
			answer = a + b
		} else {
			question = strconv.Itoa(a) + "-" + strconv.Itoa(b)
			answer = a - b
		}
	} else {
		// a<b 时只出加法，避免负数
		question = strconv.Itoa(a) + "+" + strconv.Itoa(b)
		answer = a + b
	}

	id, err = randomToken(16)
	if err != nil {
		return "", "", err
	}

	cs.challenges[id] = &captchaEntry{Answer: strconv.Itoa(answer), CreatedAt: time.Now()}
	return id, question, nil
}

// verify 校验算术题答案：成功则签发一次性 token 并消费该挑战。
// 任何一步失败都不暴露具体原因（返回 ok=false），避免给攻击者提供探测信息。
func (cs *captchaStore) verify(id string, answer string) (ok bool, token string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.evictLocked()

	e, found := cs.challenges[id]
	if !found {
		return false, ""
	}
	// 无论成功与否都消费掉这次挑战，防同一 id 反复试探
	delete(cs.challenges, id)

	// 答案做基本规范化后用常量时间比较，避免时序侧信道
	given := normalizeAnswer(answer)
	if len(given) == 0 || len(given) != len(e.Answer) ||
		subtle.ConstantTimeCompare([]byte(given), []byte(e.Answer)) != 1 {
		return false, ""
	}

	tok, err := randomToken(24)
	if err != nil {
		return false, ""
	}
	cs.tokens[tok] = &captchaToken{CreatedAt: time.Now()}
	return true, tok
}

// normalizeAnswer 去除首尾空白，仅保留纯数字（非法输入返回空串）。
func normalizeAnswer(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	s = s[start:end]
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return ""
		}
	}
	return s
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

// randomUint32 用 crypto/rand 生成一个密码学随机的 uint32。
func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// ---------- HTTP handlers ----------

// handleCaptchaChallenge 下发一次算术题挑战。
// 响应：{"ok":true,"id":"...","question":"7+5","totp_required":<bool>}
// totp_required：服务端是否已配置 TOTP 密钥（未配置时前端不强制动态码，与登录降级逻辑一致）。
func (s *Store) handleCaptchaChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	id, question, err := s.captcha.newChallenge()
	if err != nil {
		log.Printf("[错误] 生成算术题挑战失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "生成验证挑战失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "question": question, "totp_required": !s.noTOTP})
}

// handleCaptchaVerify 校验算术题答案并签发一次性登录 token。
// 请求体：{"id":"...","answer":"12"}
// 响应：{"ok":true,"token":"..."} 或 {"ok":false}
func (s *Store) handleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		ID     string `json:"id"`
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	if req.ID == "" || !safeFilename(req.ID) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	ok, token := s.captcha.verify(req.ID, req.Answer)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": token})
}
