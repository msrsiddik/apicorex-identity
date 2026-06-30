package tenant

import "testing"

func TestGenerateSlugBase(t *testing.T) {
	cases := map[string]string{
		"Acme Corp":          "acme_corp",
		"Acme, Inc.":         "acme_inc",
		"  Hello  World  ":   "hello_world",
		"123 Go":             "go0", // leading non-letters stripped, padded to 3
		"ab":                 "ab0", // padded to 3 chars
		"A":                  "a00", // padded
		"already_valid_slug": "already_valid_slug",
	}
	for in, want := range cases {
		if got := GenerateSlugBase(in); got != want {
			t.Errorf("GenerateSlugBase(%q) = %q, want %q", in, got, want)
		}
	}

	// every non-empty generated base must itself be a valid slug
	for in := range cases {
		if got := GenerateSlugBase(in); got != "" {
			if err := ValidateSlug(got); err != nil {
				t.Errorf("GenerateSlugBase(%q) = %q is not a valid slug: %v", in, got, err)
			}
		}
	}

	// a name with no usable characters yields ""
	if got := GenerateSlugBase("!!! ###"); got != "" {
		t.Errorf("GenerateSlugBase(no letters) = %q, want empty", got)
	}

	// long names are truncated to <=32 and stay valid
	long := GenerateSlugBase("this is a very long company name that exceeds the limit")
	if len(long) > 32 || ValidateSlug(long) != nil {
		t.Errorf("GenerateSlugBase long = %q (%d chars), want valid <=32", long, len(long))
	}
}

func TestValidateSlug(t *testing.T) {
	valid := []string{"acme", "acme_corp", "a1b2", "abc", "tenant_123", "x" + "23456789012345678901234567890_"} // last = 32 chars
	for _, s := range valid {
		if err := ValidateSlug(s); err != nil {
			t.Errorf("ValidateSlug(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"",                                    // empty
		"ab",                                  // too short (2)
		"Acme",                                // uppercase
		"1acme",                               // starts with digit
		"_acme",                               // starts with underscore
		"acme-corp",                           // hyphen
		"acme corp",                           // space
		"acme;drop",                           // SQL-injection-ish
		"thisslugiswaytoolongforanidentifier", // > 32 chars
		"naïve",                               // non-ASCII
	}
	for _, s := range invalid {
		if err := ValidateSlug(s); err == nil {
			t.Errorf("ValidateSlug(%q) = nil, want error", s)
		}
	}
}
