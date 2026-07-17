package main

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
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

type ListTenantPluginsResponse struct {
	Plugins []string `json:"plugins"`
}

type ListTenantsResponse struct {
	Tenants []auth.TenantSummary `json:"tenants"`
}

type SetTenantStatusRequest struct {
	Status string `json:"status" example:"suspended"` // "active" or "suspended"
}

type TenantSummaryResponse struct {
	Tenant auth.TenantSummary `json:"tenant"`
}

type LoginRequest struct {
	Slug     string `json:"slug"     example:"acme"`
	Email    string `json:"email"    example:"owner@acme.com"`
	Password string `json:"password" example:"secret123"`
}

// GoogleLoginRequest is a password-free login: idToken is a Google-issued OpenID
// Connect ID token; slug is optional (picks the tenant for a multi-tenant user).
type GoogleLoginRequest struct {
	IDToken string `json:"idToken" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6..."`
	Slug    string `json:"slug"    example:"acme"`
}

// LoginResponse carries the single opaque device token. There is no refresh
// token and no expiry — the token stays valid until revoked (logout, member
// removal/suspension of its owner).
type LoginResponse struct {
	Token string `json:"token"`
}

// TenantChooserResponse is returned when a user belongs to multiple tenants and
// no slug was supplied; the client picks one and retries login with the slug.
type TenantChooserResponse struct {
	Message string              `json:"message" example:"select a tenant"`
	Tenants []auth.TenantOption `json:"tenants"`
}

type LogoutResponse struct {
	Message string `json:"message" example:"logged out"`
}

// IntrospectRequest is Core's plugin-to-plugin token resolution call. token_hash
// is the sha256 of the raw bearer; acting_user_id is the PIN-unlocked user the
// device claims (empty = the token's owner).
type IntrospectRequest struct {
	TokenHash    string `json:"token_hash"`
	ActingUserID string `json:"acting_user_id"`
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
	// Device-unlock PIN: has_pin says whether one is set; pin_hash is the caller's
	// OWN bcrypt hash, returned so their device can verify the PIN offline. Only
	// ever the caller's own hash — never another member's.
	HasPin           bool     `json:"has_pin"`
	PinHash          string   `json:"pin_hash,omitempty"`
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

type InstallAllRequest struct {
	PluginName string `json:"plugin_name" example:"billing"`
}

type InstallAllResponse struct {
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

// SetMemberStatusRequest suspends or reactivates a member. status: "active" | "suspended".
type SetMemberStatusRequest struct {
	Status string `json:"status" example:"suspended"`
}

type SwitchBranchRequest struct {
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

type ListMembersResponse struct {
	Members []auth.MemberInfo `json:"members"`
}

type UpdateMemberRoleRequest struct {
	Role string `json:"role" example:"admin"`
}

type SetPinRequest struct {
	Pin string `json:"pin" example:"1234"` // 4 digits; empty clears the PIN
}

type VerifyPinResponse struct {
	Ok bool `json:"ok"`
}

// ResolvePinResponse identifies which member a PIN belongs to (shared-till
// unlock by PIN alone).
type ResolvePinResponse struct {
	UserID   string `json:"user_id"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
}

// PinAvailableRequest checks whether a PIN is free within the tenant, optionally
// excluding one member (so they can keep their own PIN when re-saving).
type PinAvailableRequest struct {
	Pin          string `json:"pin"`
	ExceptUserID string `json:"except_user_id"`
}

// UpdateProfileRequest patches the caller's own PII. Empty fields are unchanged.
type UpdateProfileRequest struct {
	FullName string `json:"full_name"`
	Phone    string `json:"phone"`
	JobTitle string `json:"job_title"`
}

type PinAvailableResponse struct {
	Available bool `json:"available"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type SetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	// Optional machine-readable code so clients can branch on a specific refusal
	// (e.g. "last_manager") instead of matching on the human message.
	Code string `json:"code,omitempty"`
}

// handlers holds dependencies for the Gin route handlers.
type handlers struct {
	authSvc   *auth.Service
	saga      *tenant.Saga
	installer *pluginmgr.Installer
	pluginKey string // shared PLUGIN_API_KEY guarding /internal/* plugin-to-plugin routes
}

// registerRoutes wires all identity routes onto the plugin.
func registerRoutes(p *plugin.Plugin, h *handlers) {
	p.Public("/auth/register")
	p.Public("/auth/login")
	p.Public("/auth/google")
	p.Public("/auth/slug-available")
	p.Public("/auth/slug-suggest")
	p.Public("/admin")

	// Plugin-to-plugin: Core resolves every request's bearer through this. Not
	// in the manifest — Core never proxies it publicly; it's guarded by the
	// shared PLUGIN_API_KEY instead of a user token.
	p.Internal(http.MethodPost, "/internal/introspect", h.introspect)

	p.GET("/admin", serveAdmin,
		option.Summary("Platform admin UI"),
		option.Description("A self-contained HTML page. It authenticates itself via /auth/login and calls "+
			"the JSON API with the resulting token — no separate session or server-side auth of its own."),
		option.Tags("platform-admins"),
	)

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
		option.Description("Returns a single opaque device token (no expiry — valid until revoked). "+
			"If the user belongs to multiple tenants and no slug is supplied, returns "+
			"409 with a TenantChooserResponse — pick a tenant and retry with its slug."),
		option.Tags("auth"),
		option.Request(new(LoginRequest)),
		option.Response(http.StatusOK, new(LoginResponse)),
		option.Response(http.StatusConflict, new(TenantChooserResponse)),
		option.Response(http.StatusUnauthorized, new(ErrorResponse)),
	)
	p.POST("/auth/google", h.googleLogin,
		option.Summary("Login with Google"),
		option.Description("Password-free login with a Google ID token. The token is verified "+
			"(signature, audience, expiry, verified email); the matching staff account must "+
			"already exist (Google login never self-registers). Same tenant model as /auth/login: "+
			"returns a device token, or 409 with a TenantChooserResponse when the user has "+
			"multiple tenants and no slug is supplied. 401 if the token is invalid or no account "+
			"matches the email."),
		option.Tags("auth"),
		option.Request(new(GoogleLoginRequest)),
		option.Response(http.StatusOK, new(LoginResponse)),
		option.Response(http.StatusConflict, new(TenantChooserResponse)),
		option.Response(http.StatusUnauthorized, new(ErrorResponse)),
	)
	p.POST("/auth/logout", h.logout,
		option.Summary("Logout"),
		option.Description("Revokes the calling device token"),
		option.Tags("auth"),
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
	p.GET("/tenants/:id/plugins", h.listTenantPlugins,
		option.Summary("List a tenant's installed plugins"),
		option.Description("Platform admin only (use /me's installed_plugins for your own tenant)."),
		option.Tags("plugins"),
		option.Response(http.StatusOK, new(ListTenantPluginsResponse)),
		option.Response(http.StatusForbidden, new(ErrorResponse)),
	)
	p.POST("/plugins/install-all", h.installAll,
		option.Summary("Install a plugin for every active tenant that doesn't already have it"),
		option.Description("Platform admin only. Provisioning/suspended tenants are skipped; tenants that "+
			"already have the plugin are reported as a no-op success, so this is safe to call repeatedly."),
		option.Tags("plugins"),
		option.Request(new(InstallAllRequest)),
		option.Response(http.StatusOK, new(InstallAllResponse)),
		option.Response(http.StatusForbidden, new(ErrorResponse)),
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

	p.GET("/tenants", h.listTenants,
		option.Summary("List all tenants"),
		option.Description("Platform admin only."),
		option.Tags("platform-admins"),
		option.Response(http.StatusOK, new(ListTenantsResponse)),
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
		option.Description("Re-scopes the calling device token to another branch the caller belongs to "+
			"in their current tenant. The token string itself is unchanged."),
		option.Tags("branches"),
		option.Request(new(SwitchBranchRequest)),
		option.Response(http.StatusOK, new(BranchResponse)),
		option.Response(http.StatusForbidden, new(ErrorResponse)),
	)
	p.GET("/members", h.listMembers,
		option.Summary("List the tenant's members"),
		option.Description("Every user with access to the caller's tenant — email, name, role, and current branch. Scoped to the caller's tenant."),
		option.Tags("members"),
		option.Response(http.StatusOK, new(ListMembersResponse)),
	)
	p.Handle(http.MethodPatch, "/members/:userId", h.updateMemberRole,
		option.Summary("Change a member's role"),
		option.Description("Owner/admin only. Refused when it would demote the tenant's last manager."),
		option.Tags("members"),
		option.Request(new(UpdateMemberRoleRequest)),
		option.Response(http.StatusOK, new(MessageResponse)),
	)
	p.Handle(http.MethodPatch, "/members/:userId/status", h.setMemberStatus,
		option.Summary("Suspend or reactivate a member"),
		option.Description("Owner/admin only. Sets status active|suspended. A suspended member can't sign in, refresh, or unlock until reactivated (reversible, unlike remove). Refused for yourself or the last manager."),
		option.Tags("members"),
		option.Request(new(SetMemberStatusRequest)),
		option.Response(http.StatusOK, new(MessageResponse)),
	)
	p.Handle(http.MethodDelete, "/members/:userId", h.removeMember,
		option.Summary("Remove a member from the tenant"),
		option.Description("Owner/admin only. Deletes the membership and tenant profile; the global user survives. Refused for yourself or the last manager."),
		option.Tags("members"),
		option.Response(http.StatusOK, new(MessageResponse)),
	)
	p.Handle(http.MethodPatch, "/me/pin", h.setOwnPin,
		option.Summary("Set your own device-unlock PIN"),
		option.Description("Any signed-in user. Stores a bcrypt hash; /me returns it so the device can unlock offline. Empty pin clears it."),
		option.Tags("members"),
		option.Request(new(SetPinRequest)),
		option.Response(http.StatusOK, new(MessageResponse)),
	)
	p.Handle(http.MethodPatch, "/members/:userId/pin", h.setMemberPin,
		option.Summary("Set a member's device-unlock PIN"),
		option.Description("Owner/admin only. Lets an owner provision a staff member's PIN centrally. "+
			"Refused (409, code pin_taken) if another active member already uses that PIN."),
		option.Tags("members"),
		option.Request(new(SetPinRequest)),
		option.Response(http.StatusOK, new(MessageResponse)),
		option.Response(http.StatusConflict, new(ErrorResponse)),
	)
	p.Handle(http.MethodPost, "/members/pin/available", h.pinAvailable,
		option.Summary("Check whether a device-unlock PIN is free in the tenant"),
		option.Description("Owner/admin only. Realtime uniqueness check for the member form: returns "+
			"available=false when another active member already uses the PIN. except_user_id keeps a "+
			"member's own PIN available when re-saving."),
		option.Tags("members"),
		option.Request(new(PinAvailableRequest)),
		option.Response(http.StatusOK, new(PinAvailableResponse)),
	)
	p.Handle(http.MethodPost, "/me/pin/verify", h.verifyOwnPin,
		option.Summary("Verify your PIN against the stored hash"),
		option.Description("Any signed-in user. Used to activate a PIN (set by you elsewhere, or by an owner) on a new device before caching it for offline unlock."),
		option.Tags("members"),
		option.Request(new(SetPinRequest)),
		option.Response(http.StatusOK, new(VerifyPinResponse)),
	)
	p.Handle(http.MethodPost, "/me/pin/resolve", h.resolvePin,
		option.Summary("Resolve which member a device-unlock PIN belongs to"),
		option.Description("Shared-till unlock: given a PIN, returns the active member of the "+
			"caller's tenant whose PIN matches — so ANY staff can unlock a device by PIN alone, "+
			"even one who never enrolled on it. Authorized by the device token; no permission "+
			"required (the PIN itself decides the acting user). 401 when no active member matches."),
		option.Tags("members"),
		option.Request(new(SetPinRequest)),
		option.Response(http.StatusOK, new(ResolvePinResponse)),
		option.Response(http.StatusUnauthorized, new(ErrorResponse)),
	)
	p.Handle(http.MethodPatch, "/me/profile", h.updateOwnProfile,
		option.Summary("Update your own name / phone / job title"),
		option.Description("Any signed-in user edits their own PII. Empty fields are left unchanged."),
		option.Tags("members"),
		option.Request(new(UpdateProfileRequest)),
		option.Response(http.StatusOK, new(MessageResponse)),
	)
	p.Handle(http.MethodPatch, "/me/password", h.changeOwnPassword,
		option.Summary("Change your own password"),
		option.Description("Any signed-in user, after proving the current password."),
		option.Tags("members"),
		option.Request(new(ChangePasswordRequest)),
		option.Response(http.StatusOK, new(MessageResponse)),
	)
	p.Handle(http.MethodPatch, "/members/:userId/password", h.setMemberPassword,
		option.Summary("Reset a member's password"),
		option.Description("Owner/admin only. Sets a new password for a staff member without the old one."),
		option.Tags("members"),
		option.Request(new(SetPasswordRequest)),
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
	p.Handle(http.MethodPatch, "/tenants/:id/status", h.setTenantStatus,
		option.Summary("Suspend or reactivate a tenant"),
		option.Description("Platform admin only. Suspended blocks login for every user of the tenant "+
			"without touching membership, roles, or data — reactivating restores access exactly as it was."),
		option.Tags("platform-admins"),
		option.Request(new(SetTenantStatusRequest)),
		option.Response(http.StatusOK, new(TenantSummaryResponse)),
		option.Response(http.StatusForbidden, new(ErrorResponse)),
	)

	// Route permissions — Core enforces these at the gateway before proxying.
	p.RequirePermission(http.MethodGet, "/branches", rbac.PermBranchRead)
	p.RequirePermission(http.MethodPost, "/branches", rbac.PermBranchWrite)
	p.RequirePermission(http.MethodPatch, "/branches/:id", rbac.PermBranchManage)
	p.RequirePermission(http.MethodPost, "/branches/:id/members", rbac.PermUserInvite)
	p.RequirePermission(http.MethodGet, "/members", rbac.PermUserRead)
	p.RequirePermission(http.MethodPatch, "/members/:userId", rbac.PermUserInvite)
	p.RequirePermission(http.MethodDelete, "/members/:userId", rbac.PermUserInvite)
	p.RequirePermission(http.MethodPatch, "/members/:userId/status", rbac.PermUserInvite)
	p.RequirePermission(http.MethodPatch, "/members/:userId/pin", rbac.PermUserInvite)
	p.RequirePermission(http.MethodPost, "/members/pin/available", rbac.PermUserInvite)
	p.RequirePermission(http.MethodPatch, "/members/:userId/password", rbac.PermUserInvite)
	// /me/pin and /me/password act on the caller's own profile — no permission required.
	p.RequirePermission(http.MethodPost, "/plugins/install", rbac.PermPluginInstall)
	p.RequirePermission(http.MethodPost, "/plugins/uninstall", rbac.PermPluginUninstall)
	p.RequirePermission(http.MethodGet, "/roles", rbac.PermTenantManage)
	p.RequirePermission(http.MethodPost, "/roles", rbac.PermTenantManage)
	p.RequirePermission(http.MethodPatch, "/roles/:id", rbac.PermTenantManage)
	p.RequirePermission(http.MethodDelete, "/roles/:id", rbac.PermTenantManage)
	p.RequirePermission(http.MethodPatch, "/tenant", rbac.PermTenantManage)
	// /branches/switch acts on the caller's own membership — any authenticated
	// user may; no permission required.
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
	c.JSON(http.StatusOK, LoginResponse{Token: res.Token})
}

// googleLogin is the password-free counterpart of login: it takes a Google ID
// token instead of email+password. Shares the same responses — device token on
// success, 409 tenant chooser for multi-tenant users, 401 on a bad token or an
// email with no account.
func (h *handlers) googleLogin(c *gin.Context) {
	var in GoogleLoginRequest
	if err := c.ShouldBindJSON(&in); err != nil || in.IDToken == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	res, err := h.authSvc.LoginWithGoogle(c.Request.Context(), auth.GoogleLoginInput{
		IDToken: in.IDToken, Slug: in.Slug,
	})
	if err != nil {
		var mt *auth.MultiTenantError
		if errors.As(err, &mt) {
			c.JSON(http.StatusConflict, TenantChooserResponse{
				Message: "select a tenant", Tenants: mt.Tenants,
			})
			return
		}
		// Everything else (bad token, unknown email, disabled) is a 401 — the
		// client can't tell why, which is what we want for an auth endpoint.
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, LoginResponse{Token: res.Token})
}

// introspect is Core's per-request token resolution (plugin-to-plugin, guarded
// by the shared PLUGIN_API_KEY — never proxied publicly). It turns a device
// token hash + optional acting user into the trusted request identity.
func (h *handlers) introspect(c *gin.Context) {
	if h.pluginKey == "" ||
		subtle.ConstantTimeCompare([]byte(c.GetHeader("X-Plugin-Key")), []byte(h.pluginKey)) != 1 {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid plugin key"})
		return
	}
	var in IntrospectRequest
	if err := c.ShouldBindJSON(&in); err != nil || in.TokenHash == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	res, err := h.authSvc.Introspect(c.Request.Context(), in.TokenHash, in.ActingUserID)
	switch {
	case errors.Is(err, auth.ErrInvalidToken):
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid token"})
	case errors.Is(err, auth.ErrMembershipRevoked):
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "membership revoked"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, res)
	}
}

func (h *handlers) logout(c *gin.Context) {
	// Core injects the trusted hash of the calling bearer; revoke exactly that row.
	if err := h.authSvc.Logout(c.Request.Context(), plugin.TokenHash(c)); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, LogoutResponse{Message: "logged out"})
}

// orEmpty returns a non-nil slice so it marshals as [] rather than null.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (h *handlers) me(c *gin.Context) {
	userID := plugin.UserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	// Re-check membership on every /me: the JWT stays valid until it expires, but
	// an owner may have removed this user since it was issued. Rejecting here is
	// what lets the device boot a removed staff the next time it comes online.
	// Only meaningful for tenant-scoped users; a token with no tenant (e.g. a
	// platform admin) skips the check.
	if tenantID := plugin.TenantID(c); tenantID != "" {
		if ok, err := h.authSvc.IsMember(c.Request.Context(), tenantID, userID); err == nil && !ok {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "membership revoked"})
			return
		}
	}
	resp := MeResponse{
		UserID:     userID,
		TenantID:   plugin.TenantID(c),
		TenantSlug: plugin.TenantSlug(c),
		BranchID:   plugin.BranchID(c),
		BranchSlug: plugin.BranchSlug(c),
		UserType:   plugin.UserType(c),
		// Non-nil slices so they marshal as [] not null — a platform admin (or
		// any role with no perms) has empty lists, and clients decode
		// roles/permissions as non-optional arrays (a null would fail decoding).
		Roles:            orEmpty(plugin.Roles(c)),
		Permissions:      orEmpty(plugin.Permissions(c)),
		InstalledPlugins: h.authSvc.InstalledPlugins(c.Request.Context(), plugin.TenantID(c)),
	}
	// load PII profile from the tenant schema (best-effort)
	if schema := plugin.SchemaName(c); schema != "" {
		if p, err := h.authSvc.LoadProfile(c.Request.Context(), schema, userID); err == nil {
			resp.FullName = p.FullName
			resp.Phone = p.Phone
			resp.JobTitle = p.JobTitle
			resp.HasPin = p.PinHash != ""
			resp.PinHash = p.PinHash // caller's own hash, for offline unlock
		}
	}
	c.JSON(http.StatusOK, resp)
}

func (h *handlers) listTenantPlugins(c *gin.Context) {
	if !requirePlatformAdmin(c) {
		return
	}
	tenantID := c.Param("id")
	c.JSON(http.StatusOK, ListTenantPluginsResponse{
		Plugins: h.authSvc.InstalledPlugins(c.Request.Context(), tenantID),
	})
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

func (h *handlers) installAll(c *gin.Context) {
	if !requirePlatformAdmin(c) {
		return
	}
	var in InstallAllRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if in.PluginName == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "plugin_name required"})
		return
	}
	results, err := h.installer.InstallAll(c.Request.Context(), in.PluginName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, InstallAllResponse{PluginName: in.PluginName, Tenants: results})
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

func (h *handlers) listTenants(c *gin.Context) {
	if !requirePlatformAdmin(c) {
		return
	}
	tenants, err := h.authSvc.ListTenants(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, ListTenantsResponse{Tenants: tenants})
}

func (h *handlers) setTenantStatus(c *gin.Context) {
	if !requirePlatformAdmin(c) {
		return
	}
	tenantID := c.Param("id")
	var in SetTenantStatusRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	t, err := h.authSvc.SetTenantStatus(c.Request.Context(), tenantID, in.Status)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, TenantSummaryResponse{Tenant: *t})
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
	b, err := h.authSvc.SwitchBranch(c.Request.Context(), userID, tenantID, in.BranchID, plugin.TokenHash(c))
	if err != nil {
		c.JSON(http.StatusForbidden, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, BranchResponse{Branch: *b})
}

func (h *handlers) listMembers(c *gin.Context) {
	// tenantID comes only from the gateway-verified header, never the request —
	// it is the sole thing keeping one tenant's members out of another's list.
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermUserRead) {
		return
	}
	members, err := h.authSvc.ListMembers(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, ListMembersResponse{Members: members})
}

func (h *handlers) updateMemberRole(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermUserInvite) {
		return
	}
	var in UpdateMemberRoleRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	err := h.authSvc.UpdateMemberRole(c.Request.Context(), tenantID, c.Param("userId"), in.Role)
	switch {
	case errors.Is(err, auth.ErrMemberNotFound):
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "member not found"})
	case errors.Is(err, auth.ErrLastManager):
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "cannot demote the tenant's last manager", Code: "last_manager"})
	case err != nil:
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, MessageResponse{Message: "role updated"})
	}
}

func (h *handlers) removeMember(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermUserInvite) {
		return
	}
	// Guard against locking yourself out: you can't remove your own membership.
	if c.Param("userId") == plugin.UserID(c) {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "you cannot remove yourself", Code: "self_remove"})
		return
	}
	err := h.authSvc.RemoveMember(c.Request.Context(), tenantID, c.Param("userId"))
	switch {
	case errors.Is(err, auth.ErrMemberNotFound):
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "member not found"})
	case errors.Is(err, auth.ErrLastManager):
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "cannot remove the tenant's last manager", Code: "last_manager"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, MessageResponse{Message: "member removed"})
	}
}

func (h *handlers) setMemberStatus(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermUserInvite) {
		return
	}
	// You can't suspend yourself — same lock-yourself-out guard as remove.
	if c.Param("userId") == plugin.UserID(c) {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "you cannot suspend yourself", Code: "self_suspend"})
		return
	}
	var in SetMemberStatusRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	err := h.authSvc.SetMemberStatus(c.Request.Context(), tenantID, c.Param("userId"), in.Status)
	switch {
	case errors.Is(err, auth.ErrMemberNotFound):
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "member not found"})
	case errors.Is(err, auth.ErrLastManager):
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "cannot suspend the tenant's last manager", Code: "last_manager"})
	case err != nil:
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, MessageResponse{Message: "member status updated"})
	}
}

func (h *handlers) setOwnPin(c *gin.Context) {
	tenantID, userID := plugin.TenantID(c), plugin.UserID(c)
	if tenantID == "" || userID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	var in SetPinRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	switch err := h.authSvc.SetOwnPin(c.Request.Context(), tenantID, userID, in.Pin); {
	case errors.Is(err, auth.ErrInvalidPin):
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "pin must be 4 digits", Code: "invalid_pin"})
	case errors.Is(err, auth.ErrPinTaken):
		c.JSON(http.StatusConflict, ErrorResponse{Error: "pin already used by another member", Code: "pin_taken"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, MessageResponse{Message: "pin set"})
	}
}

func (h *handlers) updateOwnProfile(c *gin.Context) {
	tenantID, userID := plugin.TenantID(c), plugin.UserID(c)
	if tenantID == "" || userID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	var in UpdateProfileRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	if err := h.authSvc.UpdateOwnProfile(c.Request.Context(), tenantID, userID, in.FullName, in.Phone, in.JobTitle); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, MessageResponse{Message: "profile updated"})
}

func (h *handlers) pinAvailable(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	var in PinAvailableRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	ok, err := h.authSvc.PinAvailable(c.Request.Context(), tenantID, in.Pin, in.ExceptUserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, PinAvailableResponse{Available: ok})
}

func (h *handlers) verifyOwnPin(c *gin.Context) {
	tenantID, userID := plugin.TenantID(c), plugin.UserID(c)
	if tenantID == "" || userID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	var in SetPinRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	ok, err := h.authSvc.VerifyOwnPin(c.Request.Context(), tenantID, userID, in.Pin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, VerifyPinResponse{Ok: ok})
}

func (h *handlers) resolvePin(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	var in SetPinRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	m, err := h.authSvc.ResolvePin(c.Request.Context(), tenantID, in.Pin)
	switch {
	case errors.Is(err, auth.ErrInvalidPin):
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid pin", Code: "invalid_pin"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, ResolvePinResponse{UserID: m.UserID, FullName: m.FullName, Email: m.Email})
	}
}

func (h *handlers) setMemberPin(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermUserInvite) {
		return
	}
	var in SetPinRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	switch err := h.authSvc.SetMemberPin(c.Request.Context(), tenantID, c.Param("userId"), in.Pin); {
	case errors.Is(err, auth.ErrMemberNotFound):
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "member not found"})
	case errors.Is(err, auth.ErrInvalidPin):
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "pin must be 4 digits", Code: "invalid_pin"})
	case errors.Is(err, auth.ErrPinTaken):
		c.JSON(http.StatusConflict, ErrorResponse{Error: "pin already used by another member", Code: "pin_taken"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, MessageResponse{Message: "pin set"})
	}
}

func (h *handlers) changeOwnPassword(c *gin.Context) {
	userID := plugin.UserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	var in ChangePasswordRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	switch err := h.authSvc.ChangeOwnPassword(c.Request.Context(), userID, in.CurrentPassword, in.NewPassword); {
	case errors.Is(err, auth.ErrWrongPassword):
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "current password is wrong", Code: "wrong_password"})
	case errors.Is(err, auth.ErrWeakPassword):
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "password too short", Code: "weak_password"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, MessageResponse{Message: "password changed"})
	}
}

func (h *handlers) setMemberPassword(c *gin.Context) {
	tenantID := plugin.TenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
		return
	}
	if !requirePerm(c, rbac.PermUserInvite) {
		return
	}
	var in SetPasswordRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}
	switch err := h.authSvc.SetMemberPassword(c.Request.Context(), tenantID, c.Param("userId"), in.NewPassword); {
	case errors.Is(err, auth.ErrMemberNotFound):
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "member not found"})
	case errors.Is(err, auth.ErrWeakPassword):
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "password too short", Code: "weak_password"})
	case err != nil:
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	default:
		c.JSON(http.StatusOK, MessageResponse{Message: "password reset"})
	}
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

