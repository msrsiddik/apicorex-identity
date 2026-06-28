package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// User holds GLOBAL credentials only (no PII, no per-tenant role). One row per
// person regardless of how many tenants they belong to. Lives in the shared
// (public) schema. PII goes in the per-tenant user_profiles table.
type User struct {
	ent.Schema
}

func (User) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(), // "u_<uuid8>"
		field.String("email").Unique(),
		field.String("password_hash").Sensitive(),
		field.Bool("is_platform_admin").Default(false),
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("tenant_users", TenantUser.Type),
	}
}
