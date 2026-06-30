package tenant

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/msrsiddik/apicorex-identity/ent/tenant"
)

// nonSlugChars matches any run of characters that are not valid inside a slug
// body (lowercase letters, digits, underscore), used to collapse a name into a
// slug-safe base.
var nonSlugChars = regexp.MustCompile(`[^a-z0-9_]+`)

// GenerateSlugBase derives a slug-shaped string from a free-text name: lowercased,
// non-slug characters collapsed to underscores, trimmed, and padded/truncated to
// satisfy the slug rules (3–32 chars, starts with a letter). It does NOT check
// availability — callers use SlugAvailable / a uniqueness loop for that. Returns
// "" only if name has no usable letters/digits at all.
func GenerateSlugBase(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = nonSlugChars.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")

	// must start with a letter
	for len(s) > 0 && (s[0] < 'a' || s[0] > 'z') {
		s = s[1:]
	}
	if s == "" {
		return ""
	}
	if len(s) > 32 {
		s = strings.Trim(s[:32], "_")
	}
	// pad short slugs (>=3 required) deterministically
	for len(s) < 3 {
		s += "0"
	}
	return s
}

// SlugAvailable reports whether a slug is well-formed AND not already taken.
func (s *Saga) SlugAvailable(ctx context.Context, slug string) (bool, error) {
	if ValidateSlug(slug) != nil {
		return false, nil
	}
	taken, err := s.entClient.Tenant.Query().Where(tenant.Slug(slug)).Exist(ctx)
	if err != nil {
		return false, err
	}
	return !taken, nil
}

// SuggestSlug derives a free, valid slug from a tenant name without registering
// anything — for previewing a slug before submitting the form. Returns
// ErrInvalidSlug if no slug can be derived from name (e.g. name has no letters).
func (s *Saga) SuggestSlug(ctx context.Context, name string) (string, error) {
	return s.resolveSlug(ctx, "", name)
}

// resolveSlug returns a free, valid slug. If requested is non-empty it is used
// as-is (caller validated it). If empty, a slug is generated from name and made
// unique by appending _2, _3, … on collision. Returns ErrInvalidSlug if a slug
// cannot be derived from name.
func (s *Saga) resolveSlug(ctx context.Context, requested, name string) (string, error) {
	if requested != "" {
		return requested, nil
	}
	base := GenerateSlugBase(name)
	if base == "" {
		return "", ErrInvalidSlug
	}
	// keep room for a numeric suffix within the 32-char limit
	candidate := base
	for i := 2; ; i++ {
		ok, err := s.SlugAvailable(ctx, candidate)
		if err != nil {
			return "", err
		}
		if ok {
			return candidate, nil
		}
		suffix := "_" + strconv.Itoa(i)
		trimTo := 32 - len(suffix)
		b := base
		if len(b) > trimTo {
			b = strings.Trim(b[:trimTo], "_")
		}
		candidate = b + suffix
	}
}
