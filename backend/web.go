package main

import (
	"embed"
	"net/http"
	"path"
	"strings"
)

// webFS 内嵌审核前端静态资源（web/ 目录），编译进单个二进制，便于部署。
//
//go:embed web
var webFS embed.FS

// serveWebAssets 服务 /admin 下的前端资源。
// /admin 或 /admin/ 返回 index.html；其它路径按静态文件返回。
func serveWebAssets(w http.ResponseWriter, r *http.Request) {
	// 去掉 /admin 前缀，得到相对路径
	rel := strings.TrimPrefix(r.URL.Path, "/admin")
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		rel = "index.html"
	}

	// 防穿越：只允许纯文件名/子路径，拒绝 ..
	clean := path.Clean(rel)
	if strings.HasPrefix(clean, "..") || strings.Contains(clean, "..") {
		http.NotFound(w, r)
		return
	}

	data, err := webFS.ReadFile(path.Join("web", clean))
	if err != nil {
		// 未命中具体资源时回落到 index.html（前端单页 tab 切换）
		data, err = webFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "审核前端资源缺失", http.StatusInternalServerError)
			return
		}
		clean = "index.html"
	}

	w.Header().Set("Content-Type", contentTypeFor(clean))
	w.Header().Set("Cache-Control", "no-store") // 审核后台不缓存
	_, _ = w.Write(data)
}

// contentTypeFor 依据扩展名返回 MIME 类型（仅覆盖前端用到的几种）。
func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	default:
		return "application/octet-stream"
	}
}
