package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 上传通知（Telegram 群提醒）。
//
// 目的：每当有人成功上传插件进入待审核队列，往指定 Telegram 群推一条提醒，
// 让运营第一时间知道"有人传了东西"，无需轮询审核后台。
//
// 设计原则：
//   - 全部配置来自环境变量，代码里不写死任何 token / chat id。
//   - 异步发送（goroutine），绝不让通知失败影响上传主流程：发不出去只打日志。
//   - 未配置 TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID 时静默跳过（不报错），
//     保证没有 Telegram 环境时上传依然完全可用。
//   - 自定义 Telegram API 反代：设置 TELEGRAM_API_BASE 可走自建代理（默认官方 api.telegram.org）。

var (
	notifyOnce   sync.Once
	tgBotToken   string
	tgChatID     string
	tgAPIBase    string
	tgHTTPClient = &http.Client{Timeout: 10 * time.Second}
)

// initNotify 从环境变量加载通知配置，仅在首次使用时执行一次。
func initNotify() {
	notifyOnce.Do(func() {
		tgBotToken = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
		tgChatID = strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
		tgAPIBase = strings.TrimSpace(os.Getenv("TELEGRAM_API_BASE"))
		if tgAPIBase == "" {
			tgAPIBase = "https://api.telegram.org"
		}
		tgAPIBase = strings.TrimRight(tgAPIBase, "/")
		if tgBotToken != "" && tgChatID != "" {
			log.Printf("[信息] 上传 Telegram 通知已启用（chat=%s）", maskChatID(tgChatID))
		} else {
			log.Println("[信息] 未配置 TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID，上传 Telegram 通知已跳过")
		}
	})
}

// notifyUploadAsync 异步推送一条"新插件上传"提醒到 Telegram 群。
// 任何错误只记日志，绝不向上传播（不影响上传结果）。
func notifyUploadAsync(pluginID, version, uploader, ip string, size int64, isUpdate bool) {
	initNotify()
	// 未配置则直接返回（不起 goroutine，零开销）
	if tgBotToken == "" || tgChatID == "" {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[警告] 上传通知发送 panic（已忽略）: %v", r)
			}
		}()
		text := buildUploadNotifyText(pluginID, version, uploader, ip, size, isUpdate)
		if err := sendTelegramMessage(text); err != nil {
			log.Printf("[警告] 发送上传 Telegram 通知失败: %v", err)
		}
	}()
}

// buildUploadNotifyText 组装提醒文案（纯文本，Telegram 默认解析）。
func buildUploadNotifyText(pluginID, version, uploader, ip string, size int64, isUpdate bool) string {
	kind := "新插件"
	if isUpdate {
		kind = "插件更新"
	}
	title := fmt.Sprintf("📦 %s上传待审核", kind)
	lines := []string{
		title,
		"",
		"插件：" + pluginID,
		"版本：v" + version,
		"上传者：" + uploader,
		"来源 IP：" + ip,
		"大小：" + humanSize(size),
		"时间：" + time.Now().Format("2006-01-02 15:04:05"),
	}
	return strings.Join(lines, "\n")
}

// sendTelegramMessage 调用 Telegram Bot API sendMessage 发送纯文本。
func sendTelegramMessage(text string) error {
	url := fmt.Sprintf("%s/bot%s/sendMessage", tgAPIBase, tgBotToken)
	payload := map[string]any{
		"chat_id": tgChatID,
		"text":    text,
	}
	// 群消息默认不解析 markdown/html，纯文本最稳妥，避免特殊字符导致 400。
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("编码请求失败: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := tgHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("请求 Telegram 失败: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		ErrorCode   int    `json:"error_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("解析 Telegram 响应失败（HTTP %d）: %w", resp.StatusCode, err)
	}
	if !out.OK {
		return fmt.Errorf("Telegram 返回错误 %d: %s", out.ErrorCode, out.Description)
	}
	return nil
}

// maskChatID 打日志时对 chat id 做轻度掩码，避免完整 id 出现在日志里。
func maskChatID(id string) string {
	if len(id) <= 5 {
		return id
	}
	return id[:4] + "****" + id[len(id)-3:]
}

// humanSize 把字节数转成人类可读大小。
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
