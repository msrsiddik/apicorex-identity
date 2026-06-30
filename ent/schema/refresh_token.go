package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

type RefreshToken struct {
	ent.Schema
}

func (RefreshToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (RefreshToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("user_id").NotEmpty(),
		field.String("tenant_id").NotEmpty(),
		field.String("branch_id").Optional(), // the branch the refreshed token stays scoped to
		field.Time("expires_at"),
		field.Bool("revoked").Default(false),
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}
