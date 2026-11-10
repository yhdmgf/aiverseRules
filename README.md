# AiVerse 脚本插件仓库

本仓库是 [AiVerse](https://github.com/yhdmgf/AiVerse) 的**脚本插件仓库**：存放可直接安装的脚本插件（zip 包 + `index.json` 清单）。

## 安装方式

在 AiVerse「脚本插件」页 → 点右上角「**从仓库**」→ 填本仓库地址（`https://github.com/yhdmgf/aiverseRules`），即可列出并安装插件。

## 插件列表

| 插件 | 版本 | 权限 | 说明 |
|---|---|---|---|
| 剪贴板工具 | 1.0.0 | `clipboard` | 读取 / 写入剪贴板 |
| 通知工具 | 1.0.1 | `notify` | 发送系统通知 |

## 目录结构

- `index.json`：插件清单（名称 / 版本 / 权限 / 包名），AiVerse 据此列出可安装插件。
- `*.zip`：每个插件的 zip 包，文件名对应 `index.json` 里的条目。

## 更新插件

修改插件后，更新对应 zip 与 `index.json`（版本号、权限、`lastUpdate`），提交并推送即可。
