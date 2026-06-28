package tenant

import "testing"

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
