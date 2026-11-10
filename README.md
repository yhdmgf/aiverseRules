# AiVerse 脚本插件仓库

本仓库是 [AiVerse](https://github.com/yhdmgf/AiVerse) 的**脚本插件仓库**：存放可直接安装的脚本插件（zip 包 + `index.json` 清单）。安装后插件会注册为 AiVerse 的**工具**，AI（Agent）就能在对话中调用它执行操作。

## 脚本插件是干什么的？

脚本插件用 JavaScript 定义一个或多个**工具**（`name` + `description` + `parameters` + `handler`），安装到 AiVerse 后自动注册给 AI。AI 在对话里能看到这些工具（工具描述会注入上下文），当你要它做对应操作时（如「读取剪贴板」「发个通知」），它就调用插件的 `handler` 执行，把结果返回给你。

每个插件按需声明权限（`clipboard` / `notify` 等），安装时 AiVerse 会提示授权。

## 安装方式

在 AiVerse「**脚本插件**」页 → 点右上角「**从仓库**」→ 填本仓库地址 `https://github.com/yhdmgf/aiverseRules` → 列出并安装。

## 插件列表

### 剪贴板工具（v1.0.0）

- 包名 `com.aiverse.clipboard`，权限 `clipboard`。
- 描述：读取系统剪贴板文本内容。
- 工具：

| 工具名 | 参数 | 说明 |
|---|---|---|
| `get` | 无 | 读取剪贴板文本，返回内容 |

- **AI 调用示例**：你对 AI 说「**读取剪贴板**」→ AI 调 `剪贴板工具.get()`，把剪贴板文本返回给你。

### 通知工具（v1.0.1）

- 包名 `com.aiverse.notify`，权限 `notify`。
- 描述：发送系统状态栏通知（点击打开 App）。
- 工具：

| 工具名 | 参数 | 说明 |
|---|---|---|
| `send` | `title`（必填，通知标题）、`body`（必填，通知内容） | 发送一条通知 |

- **AI 调用示例**：你对 AI 说「**发个通知，标题『任务完成』，内容『已写入 3 个文件』**」→ AI 调 `通知工具.send({ title: "任务完成", body: "已写入 3 个文件" })`。

## AI 如何调用（使用方式）

安装插件后，AI 会把插件工具当普通工具使用：

1. **安装**：AiVerse → 脚本插件 → 从仓库 → 填本仓库 URL → 安装（按需授权）。
2. **对话触发**：在聊天里直接用自然语言让 AI 做事。插件工具的描述会出现在 AI 的工具清单里，AI 知道何时该用、怎么传参。
3. **权限**：插件声明的权限（`clipboard` / `notify`）在安装时向 AiVerse 申请，授权后 AI 才能调用；不授权则工具不可用。

## 目录结构

- `index.json`：插件清单（名称 / 版本 / 权限 / 包名），AiVerse 据此列出可安装插件。
- `*.zip`：每个插件的 zip 包（内含 `plugin.json` 描述 + `main.js` 定义工具），文件名对应 `index.json` 条目。

## 更新插件

修改插件后，更新对应 zip 与 `index.json`（版本、权限、`lastUpdate`），提交并推送即可。
