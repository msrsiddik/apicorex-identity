package auth

import "testing"

func TestParsePlatformAdminEmails(t *testing.T) {
	set := ParsePlatformAdminEmails("Alice@Example.com, bob@example.com ,, ")
	if !set["alice@example.com"] {
		t.Error("email should be lowercased")
	}
	if !set["bob@example.com"] {
		t.Error("email should be trimmed")
	}
	if set["carol@example.com"] {
		t.Error("unlisted email should not be present")
	}
	if len(set) != 2 {
		t.Errorf("empty entries should be ignored, got %d entries", len(set))
	}

	if empty := ParsePlatformAdminEmails(""); len(empty) != 0 {
		t.Error("empty config should yield an empty set")
	}
}
