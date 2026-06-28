package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

type PluginMigrationHistory struct {
	ent.Schema
}

func (PluginMigrationHistory) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (PluginMigrationHistory) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("tenant_id"),
		field.String("plugin_name"),
		field.String("version"), // YYYYMMDD_NNN
		field.String("name"),
		field.String("status").Default("applied"), // applied | failed | rolled_back
		field.Time("applied_at").Default(time.Now),
	}
}
