package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/plugin"
	"github.com/msrsiddik/apicorex-identity/internal/pluginmgr"
	"github.com/msrsiddik/apicorex-identity/internal/tenant"
	"github.com/oaswrap/spec/option"
)

// --- Request / Response types ---

type RegisterRequest struct {
	Slug     string `json:"slug"      example:"acme"`
	Name     string `json:"name"      example:"Acme Corp"`
	Plan     string `json:"plan"      example:"starter"`
	Email    string `json:"email"     example:"owner@acme.com"`
	Password string `json:"password"  example:"secret123"`
	FullName string `json:"full_name" example:"Ada Owner"`
	Phone    string `json:"phone"     example:"+1-555-0100"`
	JobTitle string `json:"job_title" example:"CEO"`
}

type RegisterResponse struct {
	Message string `json:"message" example:"tenant registered"`
}

type LoginRequest struct {
	Slug     string `json:"slug"     example:"acme"`
	Email    string `json:"email"    example:"owner@acme.com"`
	Password string `json:"password" example:"secret123"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TenantChooserResponse is returned when a user belongs to multiple tenants and
// no slug was supplied; the client picks one and retries login with the slug.
type TenantChooserResponse struct {
	Message string              `json:"message" example:"select a tenant"`
	Tenants []auth.TenantOption `json:"tenants"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutResponse struct {
	Message string `json:"message" example:"logged out"`
}

type MeResponse struct {
	UserID           string   `json:"user_id"`
	TenantID         string   `json:"tenant_id"`
	TenantSlug       string   `json:"tenant_slug"`
	UserType         string   `json:"user_type"`
	Roles            []string `json:"roles"`
	FullName         string   `json:"full_name,omitempty"`
	Phone            string   `json:"phone,omitempty"`
	JobTitle         string   `json:"job_title,omitempty"`
	InstalledPlugins []string `json:"installed_plugins"`
}

type InstallPluginRequest struct {
	TenantID   string `json:"tenant_id"`
	PluginName string `json:"plugin_name"`
}

type InstallPluginResponse struct {
	Message string `json:"message" example:"plugin installed"`
}

type UninstallPluginRequest struct {
	TenantID   string `json:"tenant_id"`
	PluginName string `json:"plugin_name"`
	DropData   bool   `json:"drop_data" example:"false"` // true = permanently drop tenant tables
}

type UninstallPluginResponse struct {
	Message string `json:"message" example:"plugin uninstalled"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// handlers holds dependencies for the Gin route handlers.
type handlers struct {
	authSvc   *auth.Service
	saga      *tenant.Saga
	installer *pluginmgr.Installer
}

// registerRoutes wires all identity routes onto the plugin.
func registerRoutes(p *plugin.Plugin, h *handlers) {
	p.Public("/auth/register")
	p.Public("/auth/login")
	p.Public("/auth/refresh")

	p.POST("/auth/register", h.register,
		option.Summary("Register a new tenant"),
		option.Tags("auth"),
		option.Request(new(RegisterRequest)),
		option.Response(http.StatusCreated, new(RegisterResponse)),
		option.Response(http.StatusInternalServerError, new(ErrorResponse)),
	)
	p.POST("/auth/login", h.login,
		option.Summary("Login"),
		option.Description("Returns access_token (15min) + refresh_token (7 days). "+
			"If the user belongs to multiple tenants and no slug is supplied, returns "+
			"409 with a TenantChooserResponse — pick a tenant and retry with its slug."),
		option.Tags("auth"),
		option.Request(new(LoginRequest)),
		option.Response(http.StatusOK, new(LoginResponse)),
		option.Response(http.StatusConflict, new(TenantChooserResponse)),
		option.Response(http.StatusUnauthorized, new(ErrorResponse)),
	)
	p.POST("/auth/refresh", h.refresh,
		option.Summary("Refresh access token"),
		option.Tags("auth"),
		option.Request(new(RefreshRequest)),
		option.Response(http.StatusOK, new(LoginResponse)),
	)
	p.POST("/auth/logout", h.logout,
		option.Summary("Logout"),
		option.Description("Revokes the refresh token and denylists the access token"),
		option.Tags("auth"),
		option.Request(new(LogoutRequest)),
		option.Response(http.StatusOK, new(LogoutResponse)),
	)
	p.GET("/me", h.me,
		option.Summary("Get current user"),
		option.Tags("auth"),
		option.Response(http.StatusOK, new(MeResponse)),
	)
	p.POST("/plugins/install", h.install,
		option.Summary("Install a plugin for a tenant"),
		option.Tags("plugins"),
		option.Request(new(InstallPluginRequest)),
		option.Response(http.StatusOK, new(InstallPluginResponse)),
	)
	p.POST("/plugins/uninstall", h.uninstall,
		option.Summary("Uninstall a plugin for a tenant"),
		option.Description("drop_data=false keeps tenant tables (re-install restores them); drop_data=true permanently drops them"),
		option.Tags("plugins"),
		option.Request(new(UninstallPluginRequest)),
		option.Response(http.StatusOK, new(UninstallPluginResponse)),
	)
}

func (h *handlers) register(c *gin.Context) {
	var in RegisterRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if err := tenant.ValidateSlug(in.Slug); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if err := h.saga.Register(c.Request.Context(), tenant.RegisterInput{
		Slug: in.Slug, Name: in.Name, Plan: in.Plan,
		OwnerEmail: in.Email, OwnerPassword: in.Password,
		OwnerFullName: in.FullName, OwnerPhone: in.Phone, OwnerJobTitle: in.JobTitle,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusCreated, RegisterResponse{Message: "tenant registered"})
}

func (h *handlers) login(c *gin.Context) {
	var in LoginRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	res, err := h.authSvc.Login(c.Request.Context(), auth.LoginInput{
		Slug: in.Slug, Email: in.Email, Password: in.Password,
	})
	if err != nil {
		// multi-tenant chooser: valid credentials, but the user must pick a tenant.
		// 409 Conflict — the request is ambiguous until a tenant is chosen.
		var mt *auth.MultiTenantError
		if errors.As(err, &mt) {
			c.JSON(http.StatusConflict, TenantChooserResponse{
				Message: "select a tenant", Tenants: mt.Tenants,
			})
			return
		}
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, LoginResponse{AccessToken: res.AccessToken, RefreshToken: res.RefreshToken})
}

func (h *handlers) refresh(c *gin.Context) {
	var in RefreshRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	res, err := h.authSvc.Refresh(c.Request.Context(), in.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, LoginResponse{AccessToken: res.AccessToken, RefreshToken: res.RefreshToken})
}

func (h *handlers) logout(c *gin.Context) {
	var in LogoutRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	// extract the access token's jti + exp from the Authorization header so we can denylist it
	jti, exp := accessTokenJTIExp(c)
	if err := h.authSvc.Logout(c.Request.Context(), in.RefreshToken, jti, exp); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, LogoutResponse{Message: "logged out"})
}

func (h *handlers) me(c *gin.Context) {
	userID := plugin.UserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	resp := MeResponse{
		UserID:           userID,
		TenantID:         plugin.TenantID(c),
		TenantSlug:       plugin.TenantSlug(c),
		UserType:         plugin.UserType(c),
		Roles:            plugin.Roles(c),
		InstalledPlugins: h.authSvc.InstalledPlugins(c.Request.Context(), plugin.TenantID(c)),
	}
	// load PII profile from the tenant schema (best-effort)
	if schema := plugin.SchemaName(c); schema != "" {
		if p, err := h.authSvc.LoadProfile(c.Request.Context(), schema, userID); err == nil {
			resp.FullName = p.FullName
			resp.Phone = p.Phone
			resp.JobTitle = p.JobTitle
		}
	}
	c.JSON(http.StatusOK, resp)
}

func (h *handlers) install(c *gin.Context) {
	var in InstallPluginRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if in.TenantID == "" || in.PluginName == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "tenant_id and plugin_name required"})
		return
	}
	// A caller may only install plugins for their own tenant. Core injects the
	// trusted tenant_id from the verified JWT; reject any mismatch.
	if caller := plugin.TenantID(c); caller == "" || caller != in.TenantID {
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "cannot install plugins for another tenant"})
		return
	}
	if err := h.installer.Install(c.Request.Context(), pluginmgr.InstallInput{
		TenantID: in.TenantID, PluginName: in.PluginName,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, InstallPluginResponse{Message: "plugin installed"})
}

func (h *handlers) uninstall(c *gin.Context) {
	var in UninstallPluginRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if in.TenantID == "" || in.PluginName == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "tenant_id and plugin_name required"})
		return
	}
	// A caller may only uninstall plugins for their own tenant.
	if caller := plugin.TenantID(c); caller == "" || caller != in.TenantID {
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "cannot uninstall plugins for another tenant"})
		return
	}
	if err := h.installer.Uninstall(c.Request.Context(), pluginmgr.UninstallInput{
		TenantID: in.TenantID, PluginName: in.PluginName, DropData: in.DropData,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	msg := "plugin uninstalled (data kept)"
	if in.DropData {
		msg = "plugin uninstalled (data dropped)"
	}
	c.JSON(http.StatusOK, UninstallPluginResponse{Message: msg})
}

// accessTokenJTIExp parses (without verifying — Core already verified) the bearer
// token to read its jti and expiry, for denylisting on logout.
func accessTokenJTIExp(c *gin.Context) (string, time.Time) {
	header := c.GetHeader("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", time.Time{}
	}
	tokenStr := strings.TrimPrefix(header, "Bearer ")
	var claims jwt.RegisteredClaims
	parser := jwt.NewParser()
	_, _, err := parser.ParseUnverified(tokenStr, &claims)
	if err != nil {
		return "", time.Time{}
	}
	var exp time.Time
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	return claims.ID, exp
}
