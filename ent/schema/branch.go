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

// Branch is a sub-organization within a Tenant (e.g. a company's regional office).
// One Tenant has many Branches; a user's membership (TenantUser) is scoped to a
// branch, carrying the role for that branch. Lives in the shared (public) schema.
// Branch-scoped business data lives in the tenant schema, isolated logically via
// a branch_id column on those tables.
type Branch struct {
	ent.Schema
}

func (Branch) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (Branch) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(), // "br_<uuid8>"
		field.String("tenant_id"),
		field.String("slug"), // unique per tenant, not global
		field.String("name"),
		field.String("status").Default("active"), // active | archived
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

func (Branch) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("branches").Field("tenant_id").Unique().Required(),
	}
}

func (Branch) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "slug").Unique(), // slug unique within a tenant
		index.Fields("tenant_id"),
	}
}
