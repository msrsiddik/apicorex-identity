package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// UserProfile holds a user's PII (full_name, phone, etc.) inside the per-tenant
// schema (e.g. tenant_acme.user_profiles). The id IS the user_id — a logical FK
// to shared.users.id (no DB-level FK, different schema). Replaces BusinessUser.
//
// The "public" annotation is overridden per tenant at runtime via
// ent.AlternateSchema (same mechanism as the old BusinessUser).
type UserProfile struct {
	ent.Schema
}

func (UserProfile) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"), // overridden at runtime per tenant
	}
}

func (UserProfile) Fields() []ent.Field {
	return []ent.Field{
		// user_id is the primary key (= shared.users.id)
		field.String("id").Unique().Immutable().StorageKey("user_id"),
		field.String("full_name"),
		field.String("phone").Optional(),
		field.String("job_title").Optional(),
		field.String("system_role").Default("customer"),
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}
