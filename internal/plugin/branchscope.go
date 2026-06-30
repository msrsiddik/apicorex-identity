package plugin

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Branch scoping for plugins.
//
// Branch isolation is *logical*: branch-scoped data lives in the tenant schema
// with a `branch_id` column, and every read/write must be filtered by the
// caller's active branch (from the verified token, injected by Core as
// X-ApiCoreX-Branch-ID). Forgetting that filter leaks data across branches, so
// this file gives plugins one obvious way to do it instead of hand-rolling the
// header read + filter at each call site.
//
// Usage in a branch-scoped plugin:
//
//	r.GET("/orders", func(c *gin.Context) {
//	    bid, ok := plugin.RequireBranch(c)   // 400 if no branch context
//	    if !ok { return }
//	    orders := db.Orders().Where(order.BranchID(bid)).All(ctx)
//	    ...
//	})
//
// And on writes, stamp the branch rather than trusting the body:
//
//	db.Orders().Create().SetBranchID(bid)....
//
// ErrNoBranchContext is returned by BranchScope when the request carries no
// branch. A branch-scoped route must reject such requests rather than querying
// unfiltered (which would span every branch in the tenant).
var ErrNoBranchContext = errors.New("no branch context: this route is branch-scoped")

// BranchScope returns the caller's active branch id, or ErrNoBranchContext if
// the request has no branch. Use this in service code that must not run a
// branch-spanning query.
func BranchScope(c *gin.Context) (string, error) {
	bid := BranchID(c)
	if bid == "" {
		return "", ErrNoBranchContext
	}
	return bid, nil
}

// RequireBranch is the handler-side guard: it returns the active branch id, or
// writes a 400 and returns ok=false when there is no branch context. A handler
// for a branch-scoped route calls this first and returns on !ok.
func RequireBranch(c *gin.Context) (branchID string, ok bool) {
	bid := BranchID(c)
	if bid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrNoBranchContext.Error()})
		return "", false
	}
	return bid, true
}
