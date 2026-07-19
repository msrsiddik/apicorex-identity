package main

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

// adminFS is the platform-admin UI: a Next.js app statically exported to
// admin/out and embedded into the binary. It's a self-contained SPA that logs
// in through /auth/login and calls the JSON API with the resulting device token
// (Bearer token in localStorage). It carries no server-side session — auth is
// exactly the same JWT path every other client uses, so Core's gateway enforces
// it.
//
// The app is built with basePath "/console", so every asset it references lives
// under /console/_next/... — which is where Core proxies this UI. serveAdmin
// maps those request paths onto files inside admin/out. (The route is /console,
// not /admin: Core's gateway firewall blocks the reserved /admin/ prefix.)
//
//go:embed all:admin/out
var adminFS embed.FS

// adminOut is adminFS rooted at admin/out, so a path like "_next/static/x"
// resolves directly.
var adminOut = mustSub(adminFS, "admin/out")

func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic("admin: embed sub " + dir + ": " + err.Error())
	}
	return sub
}

// serveAdmin serves the exported Next.js app under /console. Core registers
// this on the wildcard route /console/*filepath, so filepath is the asset path
// relative to /console — "/" for the app entry, or e.g.
// "/_next/static/chunks/main.js" for an asset.
func serveAdmin(c *gin.Context) {
	rel := strings.TrimPrefix(c.Param("filepath"), "/")
	if rel == "" {
		rel = "index.html"
	}

	data, ctype, ok := readAdminFile(rel)
	if !ok {
		// Unknown path — hand back the SPA entry so client-side routing can take
		// over, matching how a static host with a catch-all would behave.
		data, ctype, ok = readAdminFile("index.html")
		if !ok {
			c.String(http.StatusInternalServerError, "admin UI missing")
			return
		}
	}
	c.Data(http.StatusOK, ctype, data)
}

// readAdminFile reads an embedded asset and picks a content type from its
// extension. A bare path with no file resolves to that directory's index.html
// (Next.js emits foo/index.html for trailingSlash routes).
func readAdminFile(rel string) (data []byte, contentType string, ok bool) {
	b, err := fs.ReadFile(adminOut, rel)
	if err != nil {
		// Try directory-style index.html for extension-less paths.
		if path.Ext(rel) == "" {
			if b2, err2 := fs.ReadFile(adminOut, path.Join(rel, "index.html")); err2 == nil {
				return b2, "text/html; charset=utf-8", true
			}
		}
		return nil, "", false
	}
	return b, contentTypeFor(rel), true
}

func contentTypeFor(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".png":
		return "image/png"
	case ".woff2":
		return "font/woff2"
	case ".woff":
		return "font/woff"
	default:
		return "application/octet-stream"
	}
}
