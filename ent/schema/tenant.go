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
		field.String("slug").Unique(),
		field.String("name"),
		field.String("plan").Default("starter"),
		field.String("status").Default("provisioning"),
		field.String("schema_name").Unique(),
	}
}

func (Tenant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("tenant_users", TenantUser.Type),
		edge.To("plugin_installs", PluginInstall.Type),
		edge.To("branches", Branch.Type),
	}
}
