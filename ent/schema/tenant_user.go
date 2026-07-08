package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// TenantUser is the membership linking a global User to a Tenant, carrying the
// user's role for that tenant (role is tenant-level, not branch-level). Exactly
// one row per (user, tenant): a user is only ever active in one branch of a
// tenant at a time. branch_id is that current branch — switching branches
// updates this row in place rather than creating a second membership. An
// explicit join entity (not ent's bare M2M) so it can hold role/branch payload
// and be queried directly in login/saga. Lives in the shared (public) schema.
type TenantUser struct {
	ent.Schema
}

func (TenantUser) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (TenantUser) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(), // "tu_<uuid8>"
		field.String("user_id"),
		field.String("tenant_id"),
		field.String("branch_id"),          // the branch this user is currently active in
		field.String("role_id"),            // -> roles.id (system or tenant role); tenant-level, unaffected by branch switch
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

func (TenantUser) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("tenant_users").Field("user_id").Unique().Required(),
		edge.From("tenant", Tenant.Type).Ref("tenant_users").Field("tenant_id").Unique().Required(),
	}
}

func (TenantUser) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "tenant_id").Unique(), // one membership per (user, tenant) — single active branch
		index.Fields("tenant_id"),
	}
}
