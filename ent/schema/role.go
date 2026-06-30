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

// Role is a named bundle of permissions a membership (TenantUser) can hold. A
// role with an empty tenant_id is a *system* role shared by all tenants (owner,
// admin, manager, member); a role with a tenant_id is a tenant's custom role.
// Lives in the shared (public) schema. Permissions hang off role_permissions.
type Role struct {
	ent.Schema
}

func (Role) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (Role) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(), // "role_<uuid8>"
		field.String("tenant_id").Optional(),     // "" => system role (all tenants)
		field.String("slug"),                      // owner | admin | manager | member | <custom>
		field.String("name"),
		field.Bool("is_system").Default(false), // system roles cannot be edited/deleted
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

func (Role) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("permissions", RolePermission.Type),
	}
}

func (Role) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "slug").Unique(), // slug unique within a tenant (and within system roles)
	}
}
