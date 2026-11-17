<p align="center">
  <a href="README.md">简体中文</a> · <a href="README.en.md">English</a>
</p>

# AiVerse 插件商店仓库

本仓库是 [AiVerse](https://github.com/yhdmgf/AiVerse) 的**官方插件商店**，承载插件索引 `index.json` 与插件包（`packages/` 目录下的 zip）。插件基于 **manifest（`plugin.json`）+ JSON-RPC 进程协议**，可在对话内为 AI 注入工具、技能、子代理、MCP、Provider 等能力，并提供独立的插件配置页面。

## 插件包是什么

每个插件是一个 zip 压缩包，根目录包含 `plugin.json` 清单，声明：

- `id`（稳定标识，格式 `发布者.插件名`）、`version`、`license`；
- 本地化的 `name` / `description`；
- `contributes` 贡献项：`tools`（AI 工具）、`skills`、`agents`、`workspaceTools`、`uiEntries`、`hooks`、`mcp`、`providers`、`shizuku` / `overlay` / `backup` / `modelAccess`、`configPage` 等；
- 需要授权的权限项由对应 `contributes` 声明，安装时 AiVerse 提示用户确认。

插件运行在独立进程，通过 JSON-RPC 与宿主通信；宿主按授权策略约束危险动作。

## 安装方式

在 AiVerse「**插件**」页 → 点右上角「**从仓库**」→ 填本仓库地址：

```
https://github.com/yhdmgf/aiverserules
```

即可列出并安装下面的插件。安装前会展示插件提供的能力清单，确认后启用。

## 插件列表

| 插件 | 版本 | 分类 | 简介 |
|---|---|---|---|
| `aiverse.desktop-pet` | 1.0.0 | 桌面宠物 | 可拖拽、可点击互动的桌面宠物：跟随 AI 运行状态变化，支持 Deepy 鲸与鲸娘两种形态动画，长按打开菜单，可在配置页调整大小与显示时机。 |

全部插件以 GPL-3.0-or-later 协议开源（素材来源见插件包内 README）。

## 仓库结构

```
aiverserules/
├── index.json          # 插件索引：名称 / 简介 / 版本 / 分类 / 更新时间
├── packages/           # 插件包，文件名 {id}_{version}.zip
│   ├── aiverse.desktop-pet_1.0.0.zip
│   └── …
└── site/               # 插件商店审核后端源码（Go 后端 + 内嵌前端），负责插件包的安全审核与发布，详见 [`site/README.md`](site/README.md)
```

## 客户端如何拉取

AiVerse 客户端**只从 main 分支**读取：

1. 拉取 `index.json` 列出插件（名称、简介、版本、分类 `tags`、更新时间）；
2. 从 `packages/{id}_{version}.zip` 下载对应插件包；
3. 校验通过后安装并按需申请授权。

仓库或 `packages/` 中没有目标插件包时，客户端会直接提示未找到。

## 发布新插件

1. 在插件商店提交插件包（zip，文件名建议 `{id}_{version}.zip`）；
2. 提交由后端人工审核（拦截路径越界、可执行产物、`eval` / `Runtime` / `su` 等高危调用；Node / Python 的常规标准库使用放行）；
3. 审核通过后，后端把插件包写入 `packages/` 并更新 `index.json`，均提交到 main 分支；
4. 商店页**下拉刷新**即可拉到最新列表。

更新插件时递增 `version` 再提交即可，重复的 `id` + `version` 幂等覆盖。

## 审核后台安全机制（site/）

人工审核后台（`site/`）在用户名/密码之外新增了三道防线，保障管理入口不被暴力破解：

1. **算术人机验证**：登录前先完成本地自实现的算术题挑战（`/api/captcha/challenge` → `/api/captcha/verify`），通过才拿到一次性 `captcha_token`（60s 有效，防重放）。不依赖任何第三方 / Cloudflare。
2. **TOTP 动态码**：配置环境变量 `STORE_ADMIN_TOTP_SECRET`（base32 密钥）后，登录必须附 6 位动态码（RFC 6238，纯标准库实现，步长 60s，±1 个时间窗容错）。未配置时跳过 TOTP 以保持向后兼容，启动日志会告警。
3. **失败锁定（IP + 账号 双维度）**：1 分钟内登录失败 3 次，即分别对来源 IP（`data/ipban.json`）和尝试的账号名（`data/accountban.json`）锁定 30 分钟；**输对密码 + TOTP 会同时清零两个维度的计数并解锁**。默认不信任 `X-Forwarded-For`（防伪造绕过 IP 锁），仅当显式设 `STORE_TRUST_PROXY=1` 时才信。

环境变量与部署细节见 [`site/README.md`](site/README.md) 的「环境变量」与「安全清单」章节。
