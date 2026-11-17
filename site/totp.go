package main

// TOTP 动态码（RFC 6238）纯标准库实现。
//
// 说明：
//   - 算法 HMAC-SHA1，6 位数字，步长 60 秒（按需求配置）。
//   - 校验时允许 ±1 个时间窗容错，缓解客户端与服务端的时钟漂移。
//   - 密钥只从环境变量 STORE_ADMIN_TOTP_SECRET（base32，无空格）读取，
//     绝不硬编码进代码或写进日志。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits    = 6                // 验证码位数
	totpStep      = 60 * time.Second // 时间步长（60s，按需求配置；扫码时 period 同步为 60）
	totpSkew      = 1                // 允许 ±1 个时间窗的时钟容错
	totpSecretLen = 20               // 生成密钥的字节数（160 bit）
)

// GenerateSecret 生成一个新的 base32 编码 TOTP 密钥（无 padding，无空格）。
// 供生成 STORE_ADMIN_TOTP_SECRET 使用（启动日志会给出一次性提示命令）。
func GenerateSecret() string {
	b := make([]byte, totpSecretLen)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属极端情况；返回空串让调用方走"未配置"分支
		return ""
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// normalizeSecret 把 base32 密钥统一成便于解码的形式：去空格、转大写、补 padding。
func normalizeSecret(secret string) string {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	// 补齐 base32 padding，容忍用户复制时漏掉 '='
	if m := len(s) % 8; m != 0 {
		s += strings.Repeat("=", 8-m)
	}
	return s
}

// hotp 按 RFC 4226 计算给定计数器下的 HMAC-based OTP（十进制字符串，左补零到 totpDigits 位）。
func hotp(secret string, counter uint64) string {
	key, err := base32.StdEncoding.DecodeString(normalizeSecret(secret))
	if err != nil {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// 动态截断（dynamic truncation）
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	code := bin % 1000000 // 10^totpDigits
	return fmt.Sprintf("%0*d", totpDigits, code)
}

// ValidateTOTP 校验用户输入的 6 位动态码是否在当前时间窗（含 ±totpSkew 容错）内有效。
// 输入会做去空格处理；长度不符或非纯数字直接返回 false；密钥非法也返回 false。
func ValidateTOTP(secret, code string) bool {
	return validateTOTP(secret, code)
}

// validateTOTP 是 ValidateTOTP 的实际实现，签名返回 bool。
func validateTOTP(secret, code string) bool {
	if secret == "" {
		return false
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return false
	}
	// 只接受纯数字，避免把用户名/密码等字符串当验证码去试
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	now := time.Now().Unix()
	for i := -int64(totpSkew); i <= int64(totpSkew); i++ {
		counter := uint64((now + i*int64(totpStep.Seconds())) / int64(totpStep.Seconds()))
		want := hotp(secret, counter)
		if want == "" {
			continue
		}
		// 常量时间比较，避免时序侧信道逐位猜测
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// OTPAuthURI 生成 otpauth:// URI，供认证器 App 扫码或手动录入。
// secret 应为 base32（无空格）；issuer/account 用于在 App 中显示条目名。
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	params := url.Values{}
	params.Set("secret", normalizeSecret(secret))
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", fmt.Sprintf("%d", totpDigits))
	params.Set("period", fmt.Sprintf("%d", int(totpStep.Seconds())))
	return "otpauth://totp/" + label + "?" + params.Encode()
}