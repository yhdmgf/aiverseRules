package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Manifest 对应插件包根目录的 plugin.json。
// 只解析商店/审核关心的字段，其余忽略。
type Manifest struct {
	ManifestVersion int                  `json:"manifestVersion"`
	ID              string               `json:"id"`
	Name            LocalizedText        `json:"name"`
	Description     LocalizedText        `json:"description"`
	Version         string               `json:"version"`
	Author          string               `json:"author"`
	License         string               `json:"license"`
	Tags            []string             `json:"tags,omitempty"`
	Contributes     ManifestContributes  `json:"contributes"`
}

// LocalizedText 支持多语言文本（default + 各语言 key）。
type LocalizedText struct {
	Default string            `json:"default"`
	Extra   map[string]string `json:"-"`
}

// UnmarshalJSON 同时保留 default 与其它语言键（如 zh-cn）。
func (l *LocalizedText) UnmarshalJSON(data []byte) error {
	raw := make(map[string]string)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	l.Default = raw["default"]
	delete(raw, "default")
	if len(raw) > 0 {
		l.Extra = raw
	}
	return nil
}

// MarshalJSON 写回 default + 其它语言键，保证与 index.json 的 name/description 结构一致。
func (l LocalizedText) MarshalJSON() ([]byte, error) {
	out := make(map[string]string, len(l.Extra)+1)
	for k, v := range l.Extra {
		out[k] = v
	}
	out["default"] = l.Default
	return json.Marshal(out)
}

// ManifestContributes 声明插件贡献的能力，用于校验非空 + 推断 tags。
type ManifestContributes struct {
	UIEntries     []json.RawMessage `json:"uiEntries,omitempty"`
	Tools         []json.RawMessage `json:"tools,omitempty"`
	Commands      []json.RawMessage `json:"commands,omitempty"`
	SlashCommands []json.RawMessage `json:"slashCommands,omitempty"`
	Providers     []json.RawMessage `json:"providers,omitempty"`
	Agents        []json.RawMessage `json:"agents,omitempty"`
	Hooks         []json.RawMessage `json:"hooks,omitempty"`
	Settings      []json.RawMessage `json:"settings,omitempty"`
	Rules         []json.RawMessage `json:"rules,omitempty"`
	Prompts       []json.RawMessage `json:"prompts,omitempty"`
	Search        []json.RawMessage `json:"search,omitempty"`
	Knowledge     []json.RawMessage `json:"knowledge,omitempty"`
}

// isZero 判断 contributes 是否全为空（要求至少贡献一项能力）。
func (c ManifestContributes) isZero() bool {
	return len(c.UIEntries) == 0 && len(c.Tools) == 0 && len(c.Commands) == 0 &&
		len(c.SlashCommands) == 0 && len(c.Providers) == 0 && len(c.Agents) == 0 &&
		len(c.Hooks) == 0 && len(c.Settings) == 0 && len(c.Rules) == 0 &&
		len(c.Prompts) == 0 && len(c.Search) == 0 && len(c.Knowledge) == 0
}

// inferTags 依据 contributes 与显式 tags 推断商店 index.json 的 tags 字段。
func (m Manifest) inferTags() []string {
	seen := map[string]bool{}
	var tags []string
	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}
	c := m.Contributes
	if len(c.UIEntries) > 0 {
		add("ui")
	}
	if len(c.Tools) > 0 {
		add("tool")
	}
	if len(c.Commands) > 0 || len(c.SlashCommands) > 0 {
		add("command")
	}
	if len(c.Providers) > 0 {
		add("provider")
	}
	if len(c.Agents) > 0 {
		add("agent")
	}
	if len(c.Hooks) > 0 {
		add("hook")
	}
	if len(c.Settings) > 0 {
		add("settings")
	}
	if len(c.Rules) > 0 {
		add("rules")
	}
	if len(c.Prompts) > 0 {
		add("prompt")
	}
	if len(c.Search) > 0 {
		add("search")
	}
	if len(c.Knowledge) > 0 {
		add("knowledge")
	}
	// 合并插件自带 tags（去重）
	for _, t := range m.Tags {
		add(strings.ToLower(strings.TrimSpace(t)))
	}
	// 关键：把推断结果规范化到 APP 白名单内，杜绝非法 tag 写进 index.json。
	return normalizeTags(tags)
}

var (
	// pluginIDPattern 形如「发布者.插件名」：段由字母/数字/-/_ 组成。
	pluginIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$`)
	// semverPattern 宽松 semver：MAJOR.MINOR.PATCH（可带 -prerelease）。
	semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

// reservedAuthor 是官方保留的作者标识：插件作者不可用此名（防冒充官方）。
// 精确匹配（不分大小写），不误伤 aiverse-test 等含 aiverse 但非官方的作者。
const reservedAuthor = "aiverse"

// idPublisher 从「发布者.插件名」格式的 id 里取发布者段（第一个 '.' 之前）。
// authorOf 在 author 为空时会回退到这个值，故防冒充需一并校验。
func idPublisher(id string) string {
	if i := strings.Index(id, "."); i > 0 {
		return id[:i]
	}
	return ""
}

// appLegalTags 是 APP 端 PluginTags.ALL 白名单（权威来源：
// app/.../plugins/data/index/PluginIndexModels.kt 的 PluginTags.ALL）。
// 写进 index.json 的 tags 必须全部落在此集合内，否则 APP 会判定「tags 含未知值」
// 并拒绝加载整个商店索引。后端据此把推断/显式 tags 规范化到合法值。
var appLegalTags = map[string]string{
	"provider":    "provider",
	"tool":        "tool",
	"skill":       "skill",
	"agent":       "agent",
	"mcp":         "mcp",
	"ui":          "ui",
	"integration": "integration",
	"other":       "other",
	// 常见推断值 → APP 合法值的映射（保留语义，落到最近的白名单桶）。
	"command":    "other",
	"commands":   "other",
	"hook":       "other",
	"hooks":      "other",
	"rules":      "other",
	"rule":       "other",
	"prompt":     "other",
	"prompts":    "other",
	"knowledge":  "other",
	"search":     "other",
	"settings":   "ui",
	"config":     "ui",
	"page":       "ui",
	"plugin":     "other",
	"utility":    "tool",
	"extension":  "integration",
}

// normalizeTags 把 tags 规范化到 APP 白名单内：小写去空白、按 appLegalTags 映射、
// 去重保序；全不合法时兜底为 ["other"]。保证写进 index.json 的 tags 永远合法。
func normalizeTags(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		key := strings.ToLower(strings.TrimSpace(t))
		if key == "" {
			continue
		}
		mapped, ok := appLegalTags[key]
		if !ok {
			mapped = "other" // 未知值一律收敛到 other，绝不写入非法 tag
		}
		if !seen[mapped] {
			seen[mapped] = true
			out = append(out, mapped)
		}
	}
	if len(out) == 0 {
		out = []string{"other"}
	}
	return out
}

// validateManifest 校验 plugin.json 关键字段，返回可读的错误原因。
// isAdmin=true 时（后台管理员上传官方包）跳过防冒充保留字校验。
func validateManifest(m *Manifest, isAdmin bool) error {
	if m == nil {
		return fmt.Errorf("plugin.json 解析结果为空")
	}
	// 显式 tags：出现任何 APP 白名单外的值（且无法映射）时直接拒绝上传，
	// 提示合法值，避免非法 tag 流到审核/上架环节破坏商店索引。
	for _, t := range m.Tags {
		key := strings.ToLower(strings.TrimSpace(t))
		if key == "" {
			continue
		}
		if _, ok := appLegalTags[key]; !ok {
			return fmt.Errorf("tags 含不支持的值 %q；允许的值：provider, tool, skill, agent, mcp, ui, integration, other", t)
		}
	}
	if m.ManifestVersion != 1 {
		return fmt.Errorf("manifestVersion 必须为 1，当前为 %d", m.ManifestVersion)
	}
	if !pluginIDPattern.MatchString(m.ID) {
		return fmt.Errorf("插件 id 形如「发布者.插件名」（字母/数字/-/_），当前不合法: %q", m.ID)
	}
	// 防冒充官方：保留字 aiverse 不可用作作者身份。
	// 两条冒充路径都堵住——
	//   1) author 字段直接填 aiverse；
	//   2) author 留空时 authorOf 会回退取 id 的发布者段，故发布者段也不能是 aiverse。
	// 用精确匹配（不分大小写），不误伤 aiverse-test 等含 aiverse 但非官方的作者。
	if !isAdmin {
		if strings.EqualFold(strings.TrimSpace(m.Author), reservedAuthor) {
			return fmt.Errorf("author %q 为官方保留字，不可用作插件作者", reservedAuthor)
		}
		if publisher := idPublisher(m.ID); strings.EqualFold(publisher, reservedAuthor) {
			return fmt.Errorf("插件 id 的发布者段 %q 为官方保留字，请换一个发布者名", publisher)
		}
	}
	if !semverPattern.MatchString(m.Version) {
		return fmt.Errorf("version 必须为 semver（如 1.2.0），当前不合法: %q", m.Version)
	}
	if strings.TrimSpace(m.Name.Default) == "" {
		return fmt.Errorf("name.default 不能为空")
	}
	if m.Contributes.isZero() {
		return fmt.Errorf("contributes 不能为空，插件至少需要贡献一项能力")
	}
	return nil
}

// ---------- 危险扩展名黑名单 ----------

// blockedUploadExt 上传包本身的扩展名黑名单：拒绝一切可执行/脚本/动态库。
var blockedUploadExt = map[string]bool{
	".php": true, ".phtml": true, ".php5": true, ".php7": true,
	".exe": true, ".com": true, ".bat": true, ".cmd": true,
	".sh": true, ".bash": true, ".zsh": true, ".ksh": true, ".csh": true,
	".so": true, ".o": true, ".a": true, ".out": true,
	".dex": true, ".apk": true, ".jar": true, ".class": true,
	".wasm": true, ".py": true, ".pyc": true, ".rb": true, ".pl": true,
	".ps1": true, ".psm1": true, ".vbs": true, ".jsnode": true,
	".msi": true, ".dll": true, ".bin": true, ".elf": true,
	".cgi": true, ".fcgi": true, ".scr": true, ".wsf": true, ".hta": true,
}

// blockedEntryExt zip 条目（包内文件）的扩展名黑名单。
// 与上传黑名单一致，额外明确覆盖常见服务端脚本与可执行格式。
var blockedEntryExt = blockedUploadExt

// extBlocked 判断文件名（或路径）的扩展名是否在黑名单内。
func extBlocked(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return blockedEntryExt[ext]
}

// isImagePath 判断是否允许的图片资源扩展名（用于包内资源提示，不作为准入条件）。
func isImagePath(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico":
		return true
	}
	return false
}
