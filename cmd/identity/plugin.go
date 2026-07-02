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
	"github.com/msrsiddik/apicorex-identity/internal/rbac"
	"github.com/msrsiddik/apicorex-identity/internal/tenant"
	"github.com/oaswrap/spec/option"
)

// --- Request / Response types ---

type RegisterRequest struct {
	Slug     string `json:"slug"      example:"acme"` // optional; auto-generated from name if omitted
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
	Slug    string `json:"slug"    example:"acme"` // the final slug (provided or generated)
}

type SlugAvailableResponse struct {
	Slug      string `json:"slug"`
	Available bool   `json:"available"`
	Valid     bool   `json:"valid"`            // false if the slug is malformed
	Reason    string `json:"reason,omitempty"` // why it's unavailable/invalid
}

type SlugSuggestResponse struct {
	Name string `json:"name"`
	Slug string `json:"slug"` // a valid, available slug derived from name
}

type UpdateTenantRequest struct {
	Name string `json:"name" example:"Acme Corporation"`
	Plan string `json:"plan" example:"pro"`
	// slug is immutable and intentionally not accepted here.
}

type TenantResponse struct {
	Tenant auth.TenantInfo `json:"tenant"`
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
	BranchID         string   `json:"branch_id,omitempty"`
	BranchSlug       string   `json:"branch_slug,omitempty"`
	UserType         string   `json:"user_type"`
	Roles            []string `json:"roles"`
	Permissions      []string `json:"permissions"`
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

type ReconcilePluginRequest struct {
	PluginName string `json:"plugin_name" example:"billing"`
}

type ReconcilePluginResponse struct {
	PluginName string                     `json:"plugin_name"`
	Tenants    []pluginmgr.ReconcileResult `json:"tenants"`
}

type ListPlatformAdminsResponse struct {
	Admins []auth.PlatformAdminInfo `json:"admins"`
}

type GrantPlatformAdminRequest struct {
	Email string `json:"email" example:"ops@yourcompany.com"`
}

type PlatformAdminResponse struct {
	Admin auth.PlatformAdminInfo `json:"admin"`
}

type CreateBranchRequest struct {
	Slug string `json:"slug" example:"dhaka"`
	Name string `json:"name" example:"Dhaka Office"`
}

type UpdateBranchRequest struct {
	Name   string `json:"name"   example:"Dhaka HQ"`
	Status string `json:"status" example:"archived"` // active | archived
}

type BranchResponse struct {
	Branch auth.BranchInfo `json:"branch"`
}

type ListBranchesResponse struct {
	Branches []auth.BranchInfo `json:"branches"`
}

type AddMemberRequest struct {
	Email    string `json:"email"     example:"member@acme.com"`
	Role     string `json:"role"      example:"member"`
	Password string `json:"password"  example:"temp-pass-123"` // required only when the user is new
	FullName string `json:"full_name" example:"New Member"`
	Phone    string `json:"phone"     example:"+1-555-0101"`
	JobTitle string `json:"job_title" example:"Staff"`
}

type AddMemberResponse struct {
	Message string `json:"message" example:"member added"`
}

type SwitchBranchRequest struct {
	BranchID string `json:"branch_id" example:"br_1a2b3c4d"`
}

type SetDefaultBranchRequest struct {
	BranchID string `json:"branch_id" example:"br_1a2b3c4d"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type CreateRoleRequest struct {
	Slug        string   `json:"slug"        example:"auditor"`
	Name        string   `json:"name"        example:"Auditor"`
	Permissions []string `json:"permissions" example:"user:read,branch:read"`
}

type UpdateRoleRequest struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type RoleResponse struct {
	Role auth.RoleInfo `json:"role"`
}

type ListRolesResponse struct {
	Roles []auth.RoleInfo `json:"roles"`
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
	p.Public("/auth/slug-available")
	p.Public("/auth/slug-suggest")

	p.POST("/auth/register", h.register,
		option.Summary("Register a new tenant"),
		option.Description("slug is optional — if omitted, one is generated from name and made unique. "+
			"The final slug is returned in the response."),
		option.Tags("auth"),
		option.Request(new(RegisterRequest)),
		option.Response(http.StatusCreated, new(RegisterResponse)),
		option.Response(http.StatusInternalServerError, new(ErrorResponse)),
	)
	p.GET("/auth/slug-available", h.slugAvailable,
		option.Summary("Check whether a tenant slug is available"),
		option.Description("Public. Returns valid=false for a malformed slug, available=false if taken."),
		option.Tags("auth"),
		option.Response(http.StatusOK, new(SlugAvailableResponse)),
	)
	p.GET("/auth/slug-suggest", h.slugSuggest,
		option.Summary("Suggest a valid, available slug from a name"),
		option.Description("Public. name is required. Returns a slug-safe, unique slug derived from name."),
		option.Tags("auth"),
		option.Request(new(struct {
			Name string `query:"name" example:"Acme Corp"`
		})),
		option.Response(http.StatusOK, new(SlugSuggestResponse)),
		option.Response(http.StatusUnprocessableEntity, new(ErrorResponse)),
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
	p.POST("/plugins/reconcile", h.reconcilePlugin,
		option.Summary("Roll out a plugin's pending migrations to every tenant that has it installed"),
		option.Description("Platform admin only. Applies newly-added migrations to all existing installs of "+
			"plugin_name (each tenant's applied versions are tracked, so this is safe to re-run). New tenants "+
			"already get the plugin automatically at registration — this is for tenants that installed it earlier."),
		option.Tags("plugins"),
		option.Request(new(ReconcilePluginRequest)),
		option.Response(http.StatusOK, new(ReconcilePluginResponse)),
		option.Response(http.StatusForbidden, new(ErrorResponse)),
	)

	p.GET("/platform-admins", h.listPlatformAdmins,
		option.Summary("List platform admins"),
		option.Description("Platform admin only."),
		option.Tags("platform-admins"),
		option.Response(http.StatusOK, new(ListPlatformAdminsResponse)),
	)
	p.POST("/platform-admins", h.grantPlatformAdmin,
		option.Summary("Grant an existing user platform admin"),
		option.Description("Platform admin only. The user must already have a global account (matched by email). "+
			"Takes effect immediately on every identity instance (it's a DB write, unlike the PLATFORM_ADMIN_EMAILS "+
			"boot-time bootstrap)."),
		option.Tags("platform-admins"),
		option.Request(new(GrantPlatformAdminRequest)),
		option.Response(http.StatusOK, new(PlatformAdminResponse)),
	)
	p.Handle(http.MethodDelete, "/platform-admins/:email", h.revokePlatformAdmin,
		option.Summary("Revoke a user's platform admin"),
		option.Description("Platform admin only."),
		option.Tags("platform-admins"),
		option.Response(http.StatusOK, new(MessageResponse)),
	)

	p.GET("/branches", h.listBranches,
		option.Summary("List branches of the caller's tenant"),
		option.Tags("branches"),
		option.Response(http.StatusOK, new(ListBranchesResponse)),
	)
	p.POST("/branches", h.createBranch,
		option.Summary("Create a branch in the caller's tenant"),
		option.Description("Owner/admin only. Slug must be unique within the tenant."),
		option.Tags("branches"),
		option.Request(new(CreateBranchRequest)),
		option.Response(http.StatusCreated, new(BranchResponse)),
		option.Response(http.StatusForbidden, new(ErrorResponse)),
	)
	p.Handle(http.MethodPatch, "/branches/:id", h.updateBranch,
		option.Summary("Rename or archive a branch"),
		option.Description("Owner/admin only."),
		option.Tags("branches"),
		option.Request(new(UpdateBranchRequest)),
		option.Response(http.StatusOK, new(BranchResponse)),
	)
	p.POST("/branches/:id/members", h.addMember,
		option.Summary("Add a user to a branch"),
		option.Description("Owner/admin only. If the email has no global account, a new user is created (password required) along with a tenant PII profile; otherwise the existing user is reused."),
		option.Tags("branches"),
		option.Request(new(AddMemberRequest)),
		option.Response(http.StatusOK, new(AddMemberResponse)),
	)
	p.POST("/branches/switch", h.switchBranch,
		option.Summary("Switch the active branch"),
		option.Description("Issues a fresh token pair scoped to another branch the caller belongs to in their current tenant."),
		option.Tags("branches"),
		option.Request(new(SwitchBranchRequest)),
		option.Response(http.StatusOK, new(LoginResponse)),
		option.Response(http.StatusForbidden, new(ErrorResponse)),
	)
	p.POST("/branches/default", h.setDefaultBranch,
		option.Summary("Set the caller's default branch"),
		option.Description("The branch login lands on for this tenant going forward."),
		option.Tags("branches"),
		option.Request(new(SetDefaultBranchRequest)),
		option.Response(http.StatusOK, new(MessageResponse)),
	)

	p.GET("/roles", h.listRoles,
		option.Summary("List roles (system + tenant custom)"),
		option.Tags("roles"),
		option.Response(http.StatusOK, new(ListRolesResponse)),
	)
	p.POST("/roles", h.createRole,
		option.Summary("Create a custom role"),
		option.Tags("roles"),
		option.Request(new(CreateRoleRequest)),
		option.Response(http.StatusCreated, new(RoleResponse)),
	)
	p.Handle(http.MethodPatch, "/roles/:id", h.updateRole,
		option.Summary("Update a custom role"),
		option.Tags("roles"),
		option.Request(new(UpdateRoleRequest)),
		option.Response(http.StatusOK, new(RoleResponse)),
	)
	p.Handle(http.MethodDelete, "/roles/:id", h.deleteRole,
		option.Summary("Delete a custom role"),
		option.Tags("roles"),
		option.Response(http.StatusOK, new(MessageResponse)),
	)

	p.Handle(http.MethodPatch, "/tenant", h.updateTenant,
		option.Summary("Update the caller's tenant"),
		option.Description("Changes the display name and/or plan. The slug is immutable "+
			"(it names the tenant's schema and is the login key) and cannot be changed."),
		option.Tags("tenant"),
		option.Request(new(UpdateTenantRequest)),
		option.Response(http.StatusOK, new(TenantResponse)),
	)

	// Route permissions — Core enforces these at the gateway before proxying.
	p.RequirePermission(http.MethodGet, "/branches", rbac.PermBranchRead)
	p.RequirePermission(http.MethodPost, "/branches", rbac.PermBranchWrite)
	p.RequirePermission(http.MethodPatch, "/branches/:id", rbac.PermBranchManage)
	p.RequirePermission(http.MethodPost, "/branches/:id/members", rbac.PermUserInvite)
	p.RequirePermission(http.MethodPost, "/plugins/install", rbac.PermPluginInstall)
	p.RequirePermission(http.MethodPost, "/plugins/uninstall", rbac.PermPluginUninstall)
	p.RequirePermission(http.MethodGet, "/roles", rbac.PermTenantManage)
	p.RequirePermission(http.MethodPost, "/roles", rbac.PermTenantManage)
	p.RequirePermission(http.MethodPatch, "/roles/:id", rbac.PermTenantManage)
	p.RequirePermission(http.MethodDelete, "/roles/:id", rbac.PermTenantManage)
	p.RequirePermission(http.MethodPatch, "/tenant", rbac.PermTenantManage)
	// /branches/switch and /branches/default act on the caller's own membership —
	// any authenticated user may; no permission required.
}

// requirePerm aborts with 403 unless the caller holds perm. Defense-in-depth:
// Core's gateway already enforces the route permission before proxying. Returns
// true when allowed.
func requirePerm(c *gin.Context, perm string) bool {
	if plugin.HasPermission(c, perm) {
		return true
	}
	c.JSON(http.StatusForbidden, ErrorResponse{Error: "missing permission: " + perm})
	return false
}

// isPlatformAdmin reports whether the caller is a platform admin, with no
// side effect — used to bypass a same-tenant check (e.g. install/uninstall)
// rather than gate a whole endpoint (see requirePlatformAdmin for that).
func isPlatformAdmin(c *gin.Context) bool {
	return plugin.UserType(c) == "platform_admin"
}

// requirePlatformAdmin aborts with 403 unless the caller is a platform admin.
// This is a cross-tenant operation — no tenant-scoped RBAC permission applies,
// since it isn't scoped to the caller's own tenant.
func requirePlatformAdmin(c *gin.Context) bool {
	if isPlatformAdmin(c) {
		return true
	}
	c.JSON(http.StatusForbidden, ErrorResponse{Error: "platform admin required"})
	return false
}

func (h *handlers) register(c *gin.Context) {
	var in RegisterRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	// slug is optional: validate it only when provided; otherwise the saga
	// generates one from the name.
	if in.Slug != "" {
		if err := tenant.ValidateSlug(in.Slug); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
	} else if in.Name == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "name is required to generate a slug"})
		return
	}
	slug, err := h.saga.Register(c.Request.Context(), tenant.RegisterInput{
		Slug: in.Slug, Name: in.Name, Plan: in.Plan,
		OwnerEmail: in.Email, OwnerPassword: in.Password,
		OwnerFullName: in.FullName, OwnerPhone: in.Phone, OwnerJobTitle: in.JobTitle,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusCreated, RegisterResponse{Message: "tenant registered", Slug: slug})
}

func (h *handlers) slugSuggest(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "name query parameter required"})
		return
	}
	slug, err := h.saga.SuggestSlug(c.Request.Context(), name)
	if err != nil {
		// only failure is "no slug can be derived from name"
		c.JSON(http.StatusUnprocessableEntity, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, SlugSuggestResponse{Name: name, Slug: slug})
}

func (h *handlers) slugAvailable(c *gin.Context) {
	slug := c.Query("slug")
	if slug == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "slug query parameter required"})
		return
	}
	// well-formedness first, so the caller learns *why* an invalid slug is unusable
	if err := tenant.ValidateSlug(slug); err != nil {
		c.JSON(http.StatusOK, SlugAvailableResponse{Slug: slug, Available: false, Valid: false, Reason: err.Error()})
		return
	}
	ok, err := h.saga.SlugAvailable(c.Request.Context(), slug)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	resp := SlugAvailableResponse{Slug: slug, Available: ok, Valid: true}
	if !ok {
		resp.Reason = "slug already taken"
	}
	c.JSON(http.StatusOK, resp)
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
		BranchID:         plugin.BranchID(c),
		BranchSlug:       plugin.BranchSlug(c),
		UserType:         plugin.UserType(c),
		Roles:            plugin.Roles(c),
		Permissions:      plugin.Permissions(c),
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
	// A caller may only install plugins for their own tenant, unless they're a
	// platform admin (cross-tenant by design — e.g. provisioning a plugin for a
	// tenant on their behalf). Core injects the trusted tenant_id from the
	// verified JWT; reject any mismatch for everyone else.
	if caller := plugin.TenantID(c); !isPlatformAdmin(c) && (caller == "" || caller != in.TenantID) {
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
	// A caller may only uninstall plugins for their own tenant, unless they're
	// a platform admin (cross-tenant by design).
	if caller := plugin.TenantID(c); !isPlatformAdmin(c) && (caller == "" || caller != in.TenantID) {
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

func (h *handlers) reconcilePlugin(c *gin.Context) {
	if !requirePlatformAdmin(c) {
		return
	}
	var in ReconcilePluginRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if in.PluginName == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "plugin_name required"})
		return
	}
	results, err := h.installer.ReconcileAll(c.Request.Context(), in.PluginName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, ReconcilePluginResponse{PluginName: in.PluginName, Tenants: results})
}

func (h *handlers) listPlatformAdmins(c *gin.Context) {
	if !requirePlatformAdmin(c) {
		return
	}
	admins, err := h.authSvc.ListPlatformAdmins(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, ListPlatformAdminsResponse{Admins: admins})
}

func (h *handlers) grantPlatformAdmin(c *gin.Context) {
	if !requirePlatformAdmin(c) {
		return
	}
	var in GrantPlatformAdminRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if in.Email == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "email required"})
		return
	}
	admin, err := h.authSvc.GrantPlatformAdmin(c.Request.Context(), in.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, PlatformAdminResponse{Admin: *admin})
}

func (h *handlers) revokePlatformAdmin(c *gin.Context) {
	if !requirePlatformAdmin(c) {
		return
	}
	email := c.Param("email")
	if err := h.authSvc.RevokePlatformAdmin(c.Request.Context(), email); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, MessageResponse{Message: "platform admin revoked"})
}

func (h *handlers) listBranches(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	branches, err := h.authSvc.ListBranches(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, ListBranchesResponse{Branches: branches})
}

func (h *handlers) createBranch(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermBranchWrite) {
		return
	}
	var in CreateBranchRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	b, err := h.authSvc.CreateBranch(c.Request.Context(), tenantID, in.Slug, in.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusCreated, BranchResponse{Branch: *b})
}

func (h *handlers) updateBranch(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermBranchManage) {
		return
	}
	var in UpdateBranchRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	b, err := h.authSvc.UpdateBranch(c.Request.Context(), tenantID, c.Param("id"), in.Name, in.Status)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, BranchResponse{Branch: *b})
}

func (h *handlers) addMember(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermUserInvite) {
		return
	}
	var in AddMemberRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if in.Email == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "email required"})
		return
	}
	if err := h.authSvc.AddMember(c.Request.Context(), tenantID, c.Param("id"), auth.AddMemberInput{
		Email: in.Email, Role: in.Role, Password: in.Password,
		FullName: in.FullName, Phone: in.Phone, JobTitle: in.JobTitle,
	}); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, AddMemberResponse{Message: "member added"})
}

func (h *handlers) switchBranch(c *gin.Context) {
	userID, tenantID := plugin.UserID(c), plugin.TenantID(c)
	if userID == "" || tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	var in SwitchBranchRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	res, err := h.authSvc.SwitchBranch(c.Request.Context(), userID, tenantID, in.BranchID)
	if err != nil {
		c.JSON(http.StatusForbidden, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, LoginResponse{AccessToken: res.AccessToken, RefreshToken: res.RefreshToken})
}

func (h *handlers) setDefaultBranch(c *gin.Context) {
	userID, tenantID := plugin.UserID(c), plugin.TenantID(c)
	if userID == "" || tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	var in SetDefaultBranchRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if err := h.authSvc.SetDefaultBranch(c.Request.Context(), userID, tenantID, in.BranchID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, MessageResponse{Message: "default branch updated"})
}

func (h *handlers) listRoles(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermTenantManage) {
		return
	}
	roles, err := h.authSvc.ListRoles(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, ListRolesResponse{Roles: roles})
}

func (h *handlers) createRole(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermTenantManage) {
		return
	}
	var in CreateRoleRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	r, err := h.authSvc.CreateRole(c.Request.Context(), tenantID, in.Slug, in.Name, in.Permissions)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusCreated, RoleResponse{Role: *r})
}

func (h *handlers) updateRole(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermTenantManage) {
		return
	}
	var in UpdateRoleRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	r, err := h.authSvc.UpdateRole(c.Request.Context(), tenantID, c.Param("id"), in.Name, in.Permissions)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, RoleResponse{Role: *r})
}

func (h *handlers) deleteRole(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermTenantManage) {
		return
	}
	if err := h.authSvc.DeleteRole(c.Request.Context(), tenantID, c.Param("id")); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, MessageResponse{Message: "role deleted"})
}

func (h *handlers) updateTenant(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermTenantManage) {
		return
	}
	var in UpdateTenantRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	t, err := h.authSvc.UpdateTenant(c.Request.Context(), tenantID, in.Name, in.Plan)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, TenantResponse{Tenant: *t})
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
