package main

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

// adminHTML is the platform-admin single-page UI: login form + tenant/plugin
// admin management, calling the JSON API directly from the browser (Bearer
// token in localStorage). It carries no server-side session — auth is exactly
// the same JWT path every other client uses, so Core's gateway enforces it.
//
//go:embed admin.html
var adminHTML []byte

func serveAdmin(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", adminHTML)
}
