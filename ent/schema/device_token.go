package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// DeviceToken is the single opaque credential a device holds after login.
// The raw token (zdt_...) is returned once at login and never stored; only
// its SHA-256 hash lives here. There are no claims — every request resolves
// tenant/branch and the acting user's role/permissions fresh from the DB via
// /internal/introspect. Long-lived: valid until revoked_at is set.
type DeviceToken struct {
	ent.Schema
}

func (DeviceToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Schema("public"),
	}
}

func (DeviceToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("token_hash").Unique().NotEmpty(), // sha256 hex of the raw token
		field.String("user_id").NotEmpty(),             // the owner: whoever logged in on the device
		field.String("tenant_id").NotEmpty(),
		field.String("branch_id").Optional(), // the branch this device is scoped to
		field.String("device_name").Optional().Default(""),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("last_used_at").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
	}
}

func (DeviceToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "tenant_id"),
	}
}
