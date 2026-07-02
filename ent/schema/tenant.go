package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Tenant struct {
	ent.Schema
}

func (Tenant) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (Tenant) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		// slug is a permanent identifier: it names the tenant's Postgres schema
		// (tenant_<slug>) and is the login key, so it cannot change after creation.
		// Only the display name / plan are editable.
		field.String("slug").Unique().Immutable(),
		field.String("name"),
		field.String("plan").Default("starter"),
		field.String("status").Default("provisioning"),
		field.String("schema_name").Unique().Immutable(),
	}
}

func (Tenant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("tenant_users", TenantUser.Type),
		edge.To("plugin_installs", PluginInstall.Type),
		edge.To("branches", Branch.Type),
	}
}
