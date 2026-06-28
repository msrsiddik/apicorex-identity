package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type PluginInstall struct {
	ent.Schema
}

func (PluginInstall) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (PluginInstall) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("tenant_id"),
		field.String("plugin_name"),
		field.Time("installed_at").Default(time.Now),
		field.Strings("permissions").Optional(),
	}
}

func (PluginInstall) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("plugin_installs").Field("tenant_id").Unique().Required(),
	}
}
