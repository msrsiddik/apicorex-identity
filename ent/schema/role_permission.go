package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RolePermission grants one permission (a "resource:action" string, with "*"
// wildcards allowed) to a Role. Lives in the shared (public) schema.
type RolePermission struct {
	ent.Schema
}

func (RolePermission) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (RolePermission) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(), // "rp_<uuid8>"
		field.String("role_id"),
		field.String("permission"), // "user:write", "branch:*", "*:*"
	}
}

func (RolePermission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("role", Role.Type).Ref("permissions").Field("role_id").Unique().Required(),
	}
}

func (RolePermission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "permission").Unique(),
	}
}
