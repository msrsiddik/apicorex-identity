package plugin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The generated OpenAPI spec must declare the bearer scheme and require it
// globally, so Scalar's "Authorize" button applies across every plugin route
// (without this, users have to hand-type the Authorization header).
func TestPlugin_OpenAPISecurityDeclared(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p := New(Config{Name: "test-plugin", Version: "1.0.0"})
	p.GET("/widgets", func(c *gin.Context) { c.Status(200) })

	m := p.buildManifest()
	specJSON, ok := m["openapi_spec"].(json.RawMessage)
	if !ok {
		t.Fatalf("openapi_spec missing or wrong type: %T", m["openapi_spec"])
	}

	var doc struct {
		Security   []map[string][]string `json:"security"`
		Components struct {
			SecuritySchemes map[string]struct {
				Type   string `json:"type"`
				Scheme string `json:"scheme"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(specJSON, &doc); err != nil {
		t.Fatalf("unmarshal spec: %v (%s)", err, specJSON)
	}

	scheme, ok := doc.Components.SecuritySchemes["bearerAuth"]
	if !ok {
		t.Fatal("components.securitySchemes.bearerAuth not declared")
	}
	if scheme.Type != "http" || !strings.EqualFold(scheme.Scheme, "bearer") {
		t.Errorf("bearerAuth scheme = %+v, want http/bearer", scheme)
	}

	if len(doc.Security) == 0 {
		t.Fatal("root-level security requirement missing — Authorize won't apply globally")
	}
	if _, ok := doc.Security[0]["bearerAuth"]; !ok {
		t.Errorf("root security = %v, want to reference bearerAuth", doc.Security)
	}
}
