package plugin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// ctxWithHeaders builds a gin context whose request carries the given headers.
func ctxWithHeaders(h map[string]string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/orders", nil)
	for k, v := range h {
		c.Request.Header.Set(k, v)
	}
	return c, w
}

func TestBranchScope(t *testing.T) {
	// with a branch header
	c, _ := ctxWithHeaders(map[string]string{HeaderBranchID: "br_123"})
	bid, err := BranchScope(c)
	if err != nil || bid != "br_123" {
		t.Errorf("BranchScope with header = (%q, %v), want (br_123, nil)", bid, err)
	}

	// without one
	c2, _ := ctxWithHeaders(nil)
	if _, err := BranchScope(c2); !errors.Is(err, ErrNoBranchContext) {
		t.Errorf("BranchScope without header err = %v, want ErrNoBranchContext", err)
	}
}

func TestRequireBranch(t *testing.T) {
	// present → ok, no response written
	c, w := ctxWithHeaders(map[string]string{HeaderBranchID: "br_123"})
	bid, ok := RequireBranch(c)
	if !ok || bid != "br_123" {
		t.Errorf("RequireBranch with header = (%q, %v), want (br_123, true)", bid, ok)
	}
	if w.Code != http.StatusOK { // recorder default 200, untouched
		t.Errorf("RequireBranch wrote a response unexpectedly: %d", w.Code)
	}

	// absent → 400 and ok=false
	c2, w2 := ctxWithHeaders(nil)
	if _, ok := RequireBranch(c2); ok {
		t.Error("RequireBranch without header should return ok=false")
	}
	if w2.Code != http.StatusBadRequest {
		t.Errorf("RequireBranch without header status = %d, want 400", w2.Code)
	}
}
