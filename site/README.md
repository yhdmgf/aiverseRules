# 插件商店审核后端（plugin-store-backend）

AiVerse 插件商店的**人工审核后端**，替代原先「GitHub Actions 自动扫描 inbox → 商店」的流程：

```
上传插件 zip → 进入待审核队列 → 管理员在审核后台通过/拒绝
                                   ├─ 通过 → 自动发布到商店仓库（GitHub API）→ 删除暂存包
                                   └─ 拒绝 → 写拒绝原因 → 状态改 rejected
```

- 后端：Go 标准库 + `golang.org/x/crypto/bcrypt`（密码哈希），审核前端通过 `embed` 编译进单个二进制。
- 术语统一用「插件」（不是「脚本」）。
- 所有凭据只从环境变量读取，**代码里没有任何明文令牌/密码**。

---

## 一、目录结构

```
plugin-store-backend/
├── main.go                 # 入口：加载配置、装配路由、优雅关闭
├── security.go             # 安全头、限流器、session、bcrypt、clientIP、路径安全、原子写
├── ratelimit.go            # 账号维度登录失败锁定（data/accountban.json）+ 带时间窗的限流器扩展
├── totp.go                 # TOTP 动态码（RFC 6238，纯标准库：生成/校验/otpauth URI）
├── captcha.go              # 滑动人机验证（本地自实现，challenge + 一次性 token）
├── manifest.go             # plugin.json 解析/校验、tags 推断、扩展名黑名单
├── upload.go               # POST /api/upload：zip 安全校验（Zip Slip / 黑名单 / 大小）
├── admin.go                # 登录/登出/队列/通过/拒绝 handler + session 中间件
├── github.go               # 发布到商店仓库（Contents API：传 zip + 更新 index.json）
├── store.go                # Store：data/ 目录、队列元数据、状态流转
├── web.go                  # embed 审核前端并静态服务 /admin
├── go.mod
├── store-backend.service   # systemd unit（部署用）
├── web/                    # 审核前端（embed）
│   ├── index.html          # 登录 + 列表（待审核/已审核 tab）+ 拒绝弹窗
│   ├── style.css
│   └── review.js           # 原生 JS：登录态探测、渲染、通过/拒绝
└── data/                   # 运行期数据（自动创建）
    ├── incoming/           # 暂存 zip：<插件id>_<版本>.zip
    ├── queue/              # 审核元数据 <插件id>.json
    ├── rejected/           # 拒绝原因 <插件id>.txt
    ├── sessions/           # 登录会话 token
    ├── packages/           # 发布缓存
    ├── ipban.json          # 登录限流（同 IP 1 分钟内失败 3 次锁 30 分钟）
    ├── accountban.json     # 登录限流（同账号 1 分钟内失败 3 次锁 30 分钟）
    └── upload_ratelimit.json  # 上传限流（同 IP 5 分钟 10 次）
```

---

## 二、编译

需要 Go 1.22+。

```bash
cd plugin-store-backend
# 拉取依赖（bcrypt）
go mod tidy
# 编译为静态二进制
CGO_ENABLED=0 go build -o store-backend .
```

> 可选交叉编译（例如在 CI 上产出 linux/amd64）：
> ```bash
> CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o store-backend .
> ```

编译产物 `store-backend` 与 `web/` 已通过 `embed` 打包，**只需部署一个二进制** + 配置文件。

---

## 三、环境变量

| 变量 | 必需 | 说明 |
|------|------|------|
| `STORE_ADMIN_USER` | ✅ | 管理员用户名。缺失则登录功能禁用（只打日志，不崩）。 |
| `STORE_ADMIN_PASS_HASH` | ✅ | 管理员密码的 **bcrypt 哈希**（不存明文）。缺失则登录禁用。 |
| `STORE_ADMIN_TOTP_SECRET` | 建议 | TOTP 动态码密钥（**base32，无空格**）。未设置时登录**跳过 TOTP 校验**（向后兼容，仅打印警告）；一旦设置，登录必须附 6 位动态码。 |
| `STORE_TRUST_PROXY` |  | 仅当设为 `1` 时才信 `X-Forwarded-For` 首段按真实来源 IP 限流。**默认不信任**（以 `RemoteAddr` 为准），防伪造 XFF 绕过 IP 锁。见「clientIP 与可信代理」。 |
| `STORE_GH_TOKEN` | 发布必需 | GitHub token，需对 `yhdmgf/aiverserules` 有写权限。缺失则「通过并发布」返回 503，仍可拒绝/管理队列。 |
| `STORE_LISTEN` |  | 监听地址，默认 `127.0.0.1:8088`（只听本机，由 nginx 反代）。 |
| `STORE_DATA_DIR` |  | 数据目录，默认 `./data`。 |
| `STORE_GH_OWNER` |  | 商店仓库 owner，默认 `yhdmgf`。 |
| `STORE_GH_REPO` |  | 商店仓库名，默认 `aiverserules`。 |
| `STORE_GH_BRANCH` |  | 商店仓库分支，默认 `main`。 |
| `STORE_SESSION_TTL_HOURS` |  | 会话有效期（小时），默认 12。 |

### 生成密码哈希（不要手写）

用仓库自带的辅助方式生成 bcrypt 哈希。最简单是临时跑一段 Go：

```bash
cd plugin-store-backend
cat > /tmp/genhash.go <<'EOF'
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run genhash.go <明文密码>")
		os.Exit(1)
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(os.Args[1]), bcrypt.DefaultCost)
	fmt.Println(string(h))
}
EOF
go run /tmp/genhash.go '你的强密码'
```

输出的 `$2a$...` 字符串即为 `STORE_ADMIN_PASS_HASH` 的值。

### 生成 TOTP 密钥（不要手写）

`STORE_ADMIN_TOTP_SECRET` 是一段 **base32 无空格** 字符串（建议 160 bit，即 32 字符）。可在 `site/` 下临时写一段 `package main` 代码调用内置的 `GenerateSecret()` 生成（注意 site 下所有 `.go` 同属 `package main`，无法跨包 import，临时跑完删掉即可），或直接用任意标准 TOTP 工具（如 `oathtool`）生成 base32 密钥。

拿到密钥后：

1. 写入 `secrets.env`：`STORE_ADMIN_TOTP_SECRET=<base32>`，重启服务。
2. 用认证器 App（Google Authenticator / 1Password 等）添加条目，手动输入密钥或扫 `otpauth://totp/...` 二维码（`OTPAuthURI` 可生成对应 URI；算法 SHA1、6 位、步长 60s）。
3. 重启后登录除用户名/密码外还须填当前 6 位动态码（服务端允许 ±1 个时间窗容错）。

> ⚠️ 未配置 `STORE_ADMIN_TOTP_SECRET` 时 TOTP 校验被跳过，登录仅靠密码 + 滑块；配置后立即强制校验。换密钥会让旧条目失效。

### secrets 文件（systemd）

`/opt/aiverse-store/secrets.env`（**权限 0600，仅运行用户可读**，内容用占位符示意，请勿填真实值进仓库）：

```ini
STORE_ADMIN_USER=<from-env>
STORE_ADMIN_PASS_HASH=<from-env>
STORE_ADMIN_TOTP_SECRET=<from-env>
STORE_GH_TOKEN=<from-env>
```

> ⚠️ 绝不把真实 token/密码提交进 git 或写进 unit 文件。

---

## 四、运行

直接运行（开发）：

```bash
export STORE_ADMIN_USER=admin
export STORE_ADMIN_PASS_HASH='$2a$10$....'
export STORE_GH_TOKEN=ghp_xxx
./store-backend
# 监听 http://127.0.0.1:8088
```

生产用 systemd：

```bash
# 1) 放置二进制与配置
sudo mkdir -p /opt/aiverse-store/data
sudo cp store-backend /opt/aiverse-store/
sudo chown -R store:store /opt/aiverse-store

# 2) 安装 unit
sudo cp store-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now store-backend

# 3) 查看日志
journalctl -u store-backend -f
```

> 首次部署前：创建低权限运行用户、把 `secrets.env` 权限设为 0600 并归属该用户、确保 `/opt/aiverse-store/data` 可写。

---

## 五、nginx 反代要点

后端只监听 `127.0.0.1:8088`，由 nginx 对外提供 HTTPS 并反代。

```nginx
server {
    listen 443 ssl http2;
    server_name store.example.com;      # 换成你的域名

    # ... ssl_certificate / ssl_certificate_key ...

    # 审核后台页面
    location /admin {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 后端 API（上传/登录/审核）
    location /api/ {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;   # 限流按此 IP
        proxy_set_header X-Forwarded-Proto $scheme;

        # 插件包上限 16MB，放开 client body
        client_max_body_size 20m;
        client_body_timeout 60s;
        proxy_read_timeout 120s;   # 发布到 GitHub 可能较慢
        proxy_send_timeout 60s;
    }

    # 可选：把根路径跳到审核后台
    location = / { return 302 /admin; }
}
```

要点：
- **`client_max_body_size`** 必须 ≥ 16MB（建议 20m），否则 nginx 会 413 拦掉大包。
- **`X-Forwarded-For`** 必须传，否则登录/上传限流会按 nginx 的 IP 统计（所有用户共享）。
- 站点必须走 **HTTPS**：session cookie 设了 `Secure`，HTTP 下浏览器不会回传。
- 只反代 `/admin` 与 `/api/`，不要把整个后端根路径暴露出去。

---

## 六、API 一览

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/api/captcha/challenge` | 无 | 下发一次滑块拼图挑战。返回 `{"ok":true,"id":"...","bg":<0~1>}`。 |
| POST | `/api/captcha/verify` | 无 | 校验滑块落点。body `{"id":"...","x":<0~1>}`；通过返回 `{"ok":true,"token":"..."}`（一次性，60s），失败 `{"ok":false}`。 |
| POST | `/api/upload` | 无（限流） | 上传插件 zip（multipart 字段名 `file`，可选 `uploader`）。 |
| POST | `/api/login` | 无（限流） | 登录。body `{"username","password","totp","captcha_token"}`；成功 `{"ok":true,"user":"..."}` 并发 session cookie；被锁定时 `429` + `{"ok":false,"error":"...","locked":true,"locked_until":"<RFC3339>"}`。 |
| POST | `/api/logout` | ✅ | 退出登录。 |
| GET | `/api/queue` | ✅ | 列出待审核 + 已审核全部条目。 |
| POST | `/api/approve` | ✅ | 通过并发布到商店仓库。body: `{"id":"..."}`。 |
| POST | `/api/reject` | ✅ | 拒绝。body: `{"id":"...","reason":"..."}`。 |
| GET | `/admin` | 无 | 审核前端页面（登录 + 列表）。 |

### 登录保护（三层）

登录前先做人机校验，登录时依次校验动态码与凭据，并按 **IP + 账号** 双维度限流：

1. **滑动人机验证**（本地自实现，不依赖第三方/Cloudflare）
   - 前端先 `GET /api/captcha/challenge` 拿到 `id` 与滑块起始位 `bg`，拖动拼图块后 `POST /api/captcha/verify` 提交落点 `x`。
   - 落点与真实目标位误差 ≤ ±0.03 才通过，签发**一次性 token（60s 有效）**；挑战与 token 均存内存、带过期、用后即删（防重放）。
2. **TOTP 动态码**（RFC 6238，纯标准库 `crypto/hmac`+`sha1`+`base32`，零第三方）
   - 配置了 `STORE_ADMIN_TOTP_SECRET` 后强制校验 6 位动态码，允许 ±1 个时间窗容错防时钟漂移；常量时间比较防侧信道。
3. **失败锁定（IP + 账号 双维度）**
   - **IP 维度**：1 分钟内失败 ≥ 3 次 → 锁 30 分钟（`data/ipban.json`）。
   - **账号维度**：同用户名 1 分钟内失败 ≥ 3 次 → 锁 30 分钟（`data/accountban.json`）。
   - 登录校验顺序：查 IP 锁 → 查账号锁 → 校验 captcha_token → 校验用户名/密码 → 校验 TOTP；任一步失败均同时累计 IP 与账号两个维度的失败计数。
   - **输对密码 + TOTP 即解锁**：全部校验通过时两个维度失败计数同时清零（即使此前已被锁，凭正确凭据登录也会解锁）。
   - 被锁时返回 `429` 与 `locked_until`（RFC3339），不区分是 IP 锁还是账号锁，不泄露账号是否存在。

### clientIP 与可信代理

- 默认**不信任** `X-Forwarded-For`（客户端可伪造），`clientIP` 一律以 `RemoteAddr` 为准。本服务仅监听 `127.0.0.1`、由本机 nginx 反代，因此所有外部请求的 IP 都是 `127.0.0.1`，IP 维度限流退化为全局限流（仍能有效防暴露）。
- 仅当确认前置反代可信（nginx 用 `$proxy_add_x_forwarded_for` **覆盖**而非追加 XFF）时，设 `STORE_TRUST_PROXY=1` 才采信 XFF 首段，按真实来源 IP 限流。

### 上传校验（安全第一）

- 只接受 `.zip`；拒绝 `.php/.exe/.sh/.so/.dex/.apk/.jar/.wasm/.class/.py` 等一切可执行/脚本扩展。
- 解压遍历每个条目：
  - 拒绝 `..` / 绝对路径 / 以 `/` 开头 / 反斜杠 / 盘符（防 Zip Slip 路径穿越）；
  - 拒绝黑名单扩展（同上）；
  - 单文件 ≤ 2MB，整包（解压后）≤ 16MB。
- 包根必须含 `plugin.json`，校验 `manifestVersion=1`、`id` 形如 `发布者.插件名`、`version` 为 semver、`contributes` 非空。
- 任一校验失败：**返回具体原因，且不落地文件**。

### index.json 条目格式（严格一致）

发布时读取仓库 `index.json`，追加/更新条目后写回（**幂等**：同 id 同版本则更新）：

```json
{
  "schema_version": 1,
  "plugins": [
    {
      "id": "demo.chat-bridge",
      "name": { "default": "Chat Bridge", "zh-cn": "对话桥" },
      "description": { "default": "...", "zh-cn": "..." },
      "author": "demo",
      "repository": "https://github.com/yhdmgf/aiverserules",
      "version": "1.2.0",
      "license": "MIT",
      "tags": ["ui"],
      "lastUpdate": 1794810513842
    }
  ]
}
```

- `name` / `description` 取自 `plugin.json`（保留 `zh-cn` 等本地化键）。
- `author` 取 `plugin.json.author`，否则取 id 的发布者段。
- `tags` 由 `contributes` 推断（`uiEntries`→`ui`、`tools`→`tool`、`commands/slashCommands`→`command`、…），并合并插件自带 tags。
- `lastUpdate` 为当前毫秒时间戳。
- zip 上传到仓库 `packages/<插件id>_<版本>.zip`（Contents API PUT）。

---

## 七、安全清单

- [x] 上传：扩展名黑名单 + Zip Slip 防护 + 单文件/整包大小限制 + 校验失败不落地。
- [x] 登录限流（IP 维度）：1 分钟内同 IP 失败 3 次锁 30 分钟（`data/ipban.json`）。
- [x] 登录限流（账号维度）：1 分钟内同账号失败 3 次锁 30 分钟（`data/accountban.json`）；输对密码+TOTP 两维度同时清零。
- [x] 滑动人机验证：本地自实现 challenge/verify，一次性 token 60s，防重放，无第三方依赖。
- [x] TOTP 动态码：RFC 6238 纯标准库，±1 窗容错，常量时间比较；未配置密钥时降级跳过并告警。
- [x] clientIP 默认以 `RemoteAddr` 为准，防伪造 XFF 绕过 IP 锁（需显式 `STORE_TRUST_PROXY=1` 才信 XFF）。
- [x] 上传限流：同 IP 5 分钟最多 10 次。
- [x] session：随机 token、持久化、带过期、cookie `HttpOnly/Secure/SameSite=Strict`。
- [x] 除 `login/upload` 外所有 `/api/*` 都要 session 校验。
- [x] 路径统一 `filepath.Clean` + 前缀校验（`safeJoin`），防穿越。
- [x] 凭据只从环境变量；启动缺失只打日志并禁用对应功能，不崩。
- [x] token 绝不写日志、不返回前端（GitHub 错误经 `sanitizeGHErr` 过滤）。
- [x] 响应安全头：`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`X-Frame-Options: DENY`、CSP。
- [x] 优雅关闭（SIGINT/SIGTERM）、日志到 stdout（journald 接管）。

---

## 八、待主代理确认的部署点

1. **Go 版本**：`go.mod` 声明 `go 1.22`，编译机需 Go ≥ 1.22。
2. **systemd**：unit 里 `User=store`、`WorkingDirectory=/opt/aiverse-store`、`EnvironmentFile=/opt/aiverse-store/secrets.env`、`STORE_DATA_DIR=/opt/aiverse-store/data` —— 需按实际服务器调整（运行用户名、部署路径）。
3. **nginx**：`server_name`、证书路径、`client_max_body_size`（≥16MB）、`X-Forwarded-For` 透传、只反代 `/admin` 与 `/api/`。
4. **GitHub token 权限**：需对 `yhdmgf/aiverserules` 有 Contents 读写权限（classic token 勾 `repo`，或 fine-grained token 授权该仓库 Contents: Read and write）。
5. **首次初始化**：确认仓库已有 `index.json`（无则首次发布会自动创建 `{"schema_version":1,"plugins":[]}`）。
6. **HTTPS**：session cookie 带 `Secure`，必须经 HTTPS 访问，否则登录后 cookie 不回传。
