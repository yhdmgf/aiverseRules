package main

// 插件包下载量统计：以 GitHub index.json 为全量清单基准，
// 解析源站 nginx 访问日志按包聚合、按 IP 去重，并持久化到 data/download_stats.json。
//
// 口径说明（前端需标注"近似值"）：
//   - 仅统计到达源站的请求；命中 QEdge CDN 边缘缓存的请求不会回源，会漏计。
//   - 只计 HTTP 200 的 GET packages/*.zip。
//   - 兼容两种历史路径格式（前缀 + 文件名连字符/下划线变体）：
//       /https://raw.githubusercontent.com/<owner>/<repo>/main/packages/<file>.zip
//       /raw.githubusercontent.com/<owner>/<repo>/main/packages/<file>.zip

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// pkgStat 是单个插件包的下载量统计。
type pkgStat struct {
	Id        string `json:"id"`         // 插件 id，形如 aiverse.desktop-pet
	NameZh    string `json:"name_zh"`    // 中文名（index name 的 zh-CN，回退 default）
	Version   string `json:"version"`    // 版本号
	File      string `json:"file"`       // 规范包文件名，如 aiverse.desktop-pet_1.0.0.zip
	UniqueIPs int    `json:"unique_ips"` // 独立下载 IP 数（去重）
	Total     int    `json:"total"`      // 总下载次数（HTTP 200）
	LastAt    string `json:"last_at"`    // 最近一次下载时间（RFC3339，空=无）
}

// statsFile 是 data/download_stats.json 的持久化结构（可被 loadStats 读回）。
type statsFile struct {
	Generated string    `json:"generated"` // 生成时间（RFC3339）
	Items     []pkgStat `json:"items"`     // 全量包统计（以 index.json 为基准）
}

// zipReqRE 匹配 nginx combined 日志中针对 packages/*.zip 的成功(200) GET。
// 日志示例：
//
//	1.2.3.4 - - [17/Nov/2026:13:06:24 +0000] "GET /raw.githubusercontent.com/yhdmgf/aiverserules/main/packages/aiverse.desktop-pet_1.0.0.zip HTTP/1.1" 200 522487 "-" "Mozilla/5.0"
//
// 捕获组：1=包文件名 2=状态码。
var zipReqRE = regexp.MustCompile(`"GET \S*/packages/([A-Za-z0-9._-]+\.zip) HTTP/[^"]*" (\d{3}) `)

// nginxTimeLayout 解析 nginx 日志里的时间字段（[17/Nov/2026:13:06:24 +0000]）。
const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

// pkgAgg 是单个包在日志中的聚合中间结果。
type pkgAgg struct {
	ips    map[string]struct{}
	total  int
	lastAt time.Time
}

// normPkgKey 把包标识归一化为可比对的 key：
// 去 .zip 后缀、转小写、把连字符与下划线统一为下划线。
// 用于消除日志里 `<id>_<version>.zip` 与 `<id>-<version>.zip` 两种变体的差异。
func normPkgKey(s string) string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".zip")
	return strings.ReplaceAll(s, "-", "_")
}

// computePkgAgg 解析 nginx access 日志，返回"归一化包 key -> 聚合"的映射。
// 仅统计 HTTP 200 的 packages/*.zip GET，按来源 IP（combined 首字段，已 real_ip 还原）去重。
func computePkgAgg(logPath string) map[string]*pkgAgg {
	out := map[string]*pkgAgg{}
	if strings.TrimSpace(logPath) == "" {
		return out
	}
	f, err := os.Open(logPath)
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		m := zipReqRE.FindStringSubmatch(line)
		if m == nil || m[2] != "200" {
			continue // 仅统计成功下载
		}
		// 取来源 IP（combined 首字段，nginx 已用 real_ip 还原为真实客户端 IP）
		ip := line
		if k := strings.IndexByte(line, ' '); k > 0 {
			ip = line[:k]
		}
		key := normPkgKey(m[1])
		a := out[key]
		if a == nil {
			a = &pkgAgg{ips: map[string]struct{}{}}
			out[key] = a
		}
		a.ips[ip] = struct{}{}
		a.total++
		// 尝试解析时间取最近一次
		if lb := strings.IndexByte(line, '['); lb >= 0 {
			if rb := strings.IndexByte(line[lb:], ']'); rb > 0 {
				ts := line[lb+1 : lb+rb]
				if t, err := time.Parse(nginxTimeLayout, ts); err == nil && t.After(a.lastAt) {
					a.lastAt = t
				}
			}
		}
	}
	return out
}

// buildStatsFromIndex 以 GitHub index.json 为全量清单，left-join 日志统计生成结果。
// index 里每个已发布包都会输出（无下载记录则计数为 0）；不在 index 的日志包一律不输出。
// 排序：独立 IP 数降序 → 总次数降序 → 中文名升序（稳定的、无下载的排后面）。
func (s *Store) buildStatsFromIndex(ctx context.Context) ([]pkgStat, error) {
	idx, err := s.publisher.fetchIndex(ctx, s.cfg.GHBranch)
	if err != nil {
		return nil, err
	}
	agg := computePkgAgg(s.cfg.NginxAccessLog)

	items := make([]pkgStat, 0, len(idx.Plugins))
	for _, e := range idx.Plugins {
		st := pkgStat{
			Id:      e.ID,
			NameZh:  e.Name.Extra["zh-CN"],
			Version: e.Version,
			File:    fmt.Sprintf("%s_%s.zip", e.ID, e.Version),
		}
		if st.NameZh == "" {
			st.NameZh = e.Name.Default
		}
		if a := agg[normPkgKey(e.ID+"_"+e.Version)]; a != nil {
			st.UniqueIPs = len(a.ips)
			st.Total = a.total
			if !a.lastAt.IsZero() {
				st.LastAt = a.lastAt.Format(time.RFC3339)
			}
		}
		items = append(items, st)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UniqueIPs != items[j].UniqueIPs {
			return items[i].UniqueIPs > items[j].UniqueIPs
		}
		if items[i].Total != items[j].Total {
			return items[i].Total > items[j].Total
		}
		return items[i].NameZh < items[j].NameZh
	})
	return items, nil
}

// saveStats 把统计结果写穿持久化到 data/download_stats.json（带 generated 时间戳）。
func (s *Store) saveStats(items []pkgStat) error {
	if s.statsPath == "" {
		return fmt.Errorf("统计持久化路径未配置")
	}
	data, err := json.MarshalIndent(statsFile{
		Generated: time.Now().Format(time.RFC3339),
		Items:     items,
	}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.statsPath, data, 0o644)
}

// loadStats 读回上次持久化的统计缓存，返回条目与生成时间。
// GitHub 拉取或日志读取失败时用于降级返回。
func (s *Store) loadStats() ([]pkgStat, string, error) {
	if s.statsPath == "" {
		return nil, "", fmt.Errorf("统计持久化路径未配置")
	}
	data, err := os.ReadFile(s.statsPath)
	if err != nil {
		return nil, "", err
	}
	var f statsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, "", err
	}
	return f.Items, f.Generated, nil
}
