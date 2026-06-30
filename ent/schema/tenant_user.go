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

// TenantUser is the membership linking a global User to a Tenant *branch*,
// carrying the user's role for that branch. One row per (user, tenant, branch):
// a user in two branches of the same tenant has two rows, possibly with
// different roles. Exactly one row per (user, tenant) is the default branch
// (is_default), which login lands on. An explicit join entity (not ent's bare
// M2M) so it can hold role/branch payload and be queried directly in login/saga.
// Lives in the shared (public) schema.
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
		field.String("branch_id"),               // the branch this membership is scoped to
		field.String("role_id"),                  // -> roles.id (system or tenant role)
		field.Bool("is_default").Default(false),  // login lands the user on this branch
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
		index.Fields("user_id", "tenant_id", "branch_id").Unique(), // one membership per (user, tenant, branch)
		index.Fields("user_id", "tenant_id"),                       // membership lookup / chooser
		index.Fields("tenant_id"),
	}
}
