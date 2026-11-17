// Command pluginstore 是 AiVerse 插件商店的人工审核后端。
//
// 它替代原先「GitHub Actions 自动扫描 inbox → 商店」的流程，改为：
//   上传插件 zip 包 -> 进入待审核队列 -> 人工在审核后台通过/拒绝 -> 通过后自动发布到商店仓库。
//
// 安全原则（务必保持）：
//   - 所有凭据（GitHub token、管理员用户名、密码哈希）只从环境变量读取，绝不硬编码。
//   - 上传接口做扩展名黑名单 + zip 条目校验（防 Zip Slip）+ 大小限制。
//   - 管理接口全部需要 session；登录与上传都做限流。
//
// 仅监听 127.0.0.1，由 nginx 反代对外，因此本身不直接暴露公网。
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Config 汇总所有来自环境变量的配置。启动时读取一次。
type Config struct {
	ListenAddr string // 监听地址，默认 127.0.0.1:8088
	DataDir    string // 数据目录，默认 ./data

	AdminUser     string // 管理员用户名（STORE_ADMIN_USER）
	AdminPassHash string // 管理员密码哈希（STORE_ADMIN_PASS_HASH，bcrypt）
	AdminTOTPSecret string // TOTP 动态码密钥（STORE_ADMIN_TOTP_SECRET，base32 无空格）；空则降级跳过 TOTP
	GHToken       string // GitHub token（STORE_GH_TOKEN）

	GHOwner string // 商店仓库 owner，默认 yhdmgf
	GHRepo  string // 商店仓库名，默认 aiverserules
	GHBranch string // 商店仓库分支，默认 main

	SessionTTL time.Duration // session 有效期，默认 12h
}

// loadConfig 从环境变量加载配置。缺失关键凭据时打日志但不崩溃，
// 对应功能（登录/发布）在运行期会返回明确的错误。
func loadConfig() Config {
	cfg := Config{
		ListenAddr: envOr("STORE_LISTEN", "127.0.0.1:8088"),
		DataDir:    envOr("STORE_DATA_DIR", "data"),
		AdminUser:  os.Getenv("STORE_ADMIN_USER"),
		AdminPassHash: os.Getenv("STORE_ADMIN_PASS_HASH"),
		AdminTOTPSecret: strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(os.Getenv("STORE_ADMIN_TOTP_SECRET")), " ", "")),
		GHToken:       os.Getenv("STORE_GH_TOKEN"),
		GHOwner:       envOr("STORE_GH_OWNER", "yhdmgf"),
		GHRepo:        envOr("STORE_GH_REPO", "aiverserules"),
		GHBranch:      envOr("STORE_GH_BRANCH", "main"),
		SessionTTL:    12 * time.Hour,
	}
	if v := os.Getenv("STORE_SESSION_TTL_HOURS"); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			cfg.SessionTTL = time.Duration(h) * time.Hour
		}
	}
	return cfg
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// newMux 构造所有路由。安全头通过中间件统一添加。
func newMux(s *Store) *http.ServeMux {
	mux := http.NewServeMux()

	// 审核前端（embed 静态资源）
	mux.Handle("/admin", http.HandlerFunc(s.handleAdminPage))
	mux.Handle("/admin/", http.HandlerFunc(s.handleAdminPage))

	// 公开接口（/api/ 前缀，nginx /api/ 反代到这里）
	mux.HandleFunc("/api/captcha/challenge", s.handleCaptchaChallenge) // 下发滑块挑战
	mux.HandleFunc("/api/captcha/verify", s.handleCaptchaVerify)       // 校验滑块并签发一次性 token
	mux.HandleFunc("/api/upload", s.handleUpload)                      // 上传（自身限流）
	mux.HandleFunc("/api/login", s.handleLogin)                        // 登录（IP + 账号 双维度限流 + 滑块 + TOTP）

	// 需登录的管理接口
	mux.Handle("/api/queue", s.requireSession(http.HandlerFunc(s.handleQueue)))
	mux.Handle("/api/approve", s.requireSession(http.HandlerFunc(s.handleApprove)))
	mux.Handle("/api/reject", s.requireSession(http.HandlerFunc(s.handleReject)))
	mux.Handle("/api/logout", s.requireSession(http.HandlerFunc(s.handleLogout)))

	// 旧 /admin/api/ 前缀保留向后兼容
	mux.HandleFunc("/admin/api/upload", s.handleUpload)
	mux.HandleFunc("/admin/api/login", s.handleLogin)
	mux.Handle("/admin/api/queue", s.requireSession(http.HandlerFunc(s.handleQueue)))
	mux.Handle("/admin/api/approve", s.requireSession(http.HandlerFunc(s.handleApprove)))
	mux.Handle("/admin/api/reject", s.requireSession(http.HandlerFunc(s.handleReject)))
	mux.Handle("/admin/api/logout", s.requireSession(http.HandlerFunc(s.handleLogout)))

	return mux
}

func main() {
	cfg := loadConfig()
	s, err := NewStore(cfg)
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}

	// 启动时报告凭据/功能可用状态（不打印任何敏感值）。
	if cfg.AdminUser == "" || cfg.AdminPassHash == "" {
		log.Println("[警告] STORE_ADMIN_USER / STORE_ADMIN_PASS_HASH 未设置，登录功能将不可用")
	} else {
		log.Printf("[信息] 管理员登录已启用（用户名=%s）", cfg.AdminUser)
	}
	// TOTP 动态码：未配置则降级（登录跳过 TOTP），并给出一次性生成命令提示。
	if cfg.AdminTOTPSecret == "" {
		log.Println("[警告] STORE_ADMIN_TOTP_SECRET 未设置，TOTP 动态码校验将被跳过（仅为向后兼容，强烈建议尽快配置）")
		log.Printf("[提示] 可在 site/ 目录下运行一次性程序生成 base32 密钥（调用本包 GenerateSecret()），填入环境变量后重启即强制校验")
	} else {
		log.Println("[信息] TOTP 动态码校验已启用")
	}
	if cfg.GHToken == "" {
		log.Println("[警告] STORE_GH_TOKEN 未设置，审核通过后的发布功能将被禁用（仍可拒绝/管理队列）")
	} else {
		log.Printf("[信息] GitHub 发布已启用（仓库=%s/%s 分支=%s）", cfg.GHOwner, cfg.GHRepo, cfg.GHBranch)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(newMux(s)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second, // 发布到 GitHub 可能耗时
		IdleTimeout:       60 * time.Second,
	}

	// 优雅关闭
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("[信息] 收到退出信号，开始优雅关闭…")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			log.Printf("[错误] 关闭服务出错: %v", err)
		}
		close(done)
	}()

	log.Printf("[信息] 插件商店审核后端已启动，监听 http://%s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务异常退出: %v", err)
	}
	<-done
	log.Println("[信息] 已完全关闭")
}
