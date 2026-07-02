package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/msrsiddik/apicorex-identity/ent"
	entuser "github.com/msrsiddik/apicorex-identity/ent/user"
)

// platformAdminEmails is a parsed comma-separated email list (e.g. the
// PLATFORM_ADMIN_EMAILS env var), used only to bootstrap is_platform_admin at
// boot. Runtime authorization always reads the DB column, not this — so every
// identity instance agrees regardless of its own env, and revoking access
// after boot is a DB update (via /platform-admins), not a redeploy.
type platformAdminEmails map[string]bool

// ParsePlatformAdminEmails builds the set from a comma-separated list. Entries
// are trimmed and lowercased; empty entries are ignored.
func ParsePlatformAdminEmails(csv string) platformAdminEmails {
	set := platformAdminEmails{}
	for _, e := range strings.Split(csv, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			set[e] = true
		}
	}
	return set
}

// SyncPlatformAdminsFromEnv grants is_platform_admin to every existing user
// whose email is in emails. Call once at boot after PLATFORM_ADMIN_EMAILS is
// parsed. It only ever adds the flag — it never revokes it, so removing an
// email from the env does nothing; use DELETE /platform-admins for that. Users
// who haven't registered yet are silently skipped (nothing to bootstrap); once
// they register, grant them via the /platform-admins endpoint.
func SyncPlatformAdminsFromEnv(ctx context.Context, entClient *ent.Client, emails platformAdminEmails) (int, error) {
	granted := 0
	for email := range emails {
		n, err := entClient.User.Update().
			Where(entuser.Email(email), entuser.IsPlatformAdmin(false)).
			SetIsPlatformAdmin(true).
			Save(ctx)
		if err != nil {
			return granted, fmt.Errorf("bootstrap platform admin %s: %w", email, err)
		}
		granted += n
	}
	return granted, nil
}
