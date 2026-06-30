package rbac

import "testing"

func TestWithBaseline(t *testing.T) {
	// empty role -> just the baseline
	got := WithBaseline(nil)
	if len(got) != len(BaselinePermissions) {
		t.Fatalf("WithBaseline(nil) = %v, want baseline %v", got, BaselinePermissions)
	}

	// role perms merged, baseline not duplicated, role-only perms preserved
	got = WithBaseline([]string{"branch:read", "branch:write", "user:read"})
	want := map[string]bool{"user:read": true, "branch:read": true, "branch:write": true}
	if len(got) != len(want) {
		t.Fatalf("WithBaseline merged = %v, want keys %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}

	// baseline appears first
	got = WithBaseline([]string{"plugin:install"})
	if got[0] != BaselinePermissions[0] {
		t.Errorf("baseline should come first, got %v", got)
	}
}

func TestAllows(t *testing.T) {
	cases := []struct {
		granted  []string
		required string
		want     bool
	}{
		{[]string{"user:read"}, "user:read", true},
		{[]string{"user:read"}, "user:write", false},
		{[]string{"user:*"}, "user:write", true},
		{[]string{"*:*"}, "anything:goes", true},
		{[]string{"branch:read", "branch:write"}, "branch:write", true},
		{[]string{"branch:read"}, "branch:manage", false},
		{[]string{"*:read"}, "branch:read", true},
		{[]string{"*:read"}, "branch:write", false},
		{nil, "user:read", false},
		{[]string{"user:read"}, "", true}, // no permission required
	}
	for _, c := range cases {
		if got := Allows(c.granted, c.required); got != c.want {
			t.Errorf("Allows(%v, %q) = %v, want %v", c.granted, c.required, got, c.want)
		}
	}
}
