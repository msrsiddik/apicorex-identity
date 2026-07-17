package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newTestVerifier builds a verifier whose key cache is pre-seeded with pub under
// kid, and marked fresh, so Verify never hits the network.
func newTestVerifier(clientIDs []string, kid string, pub *rsa.PublicKey) *GoogleVerifier {
	v := NewGoogleVerifier(clientIDs)
	v.keys = map[string]*rsa.PublicKey{kid: pub}
	v.fetchedA = time.Now()
	return v
}

// signToken mints an RS256 JWT with the given claims and kid.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            "https://accounts.google.com",
		"aud":            "client-123",
		"sub":            "google-sub-1",
		"email":          "staff@shop.com",
		"email_verified": true,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Add(-time.Minute).Unix(),
	}
}

func TestGoogleVerify_Valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier([]string{"client-123"}, "kid1", &key.PublicKey)
	raw := signToken(t, key, "kid1", baseClaims())

	got, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if got.Email != "staff@shop.com" || got.Sub != "google-sub-1" {
		t.Errorf("claims = %+v, want staff@shop.com/google-sub-1", got)
	}
}

func TestGoogleVerify_Rejections(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier([]string{"client-123"}, "kid1", &key.PublicKey)

	cases := map[string]func() string{
		"wrong audience": func() string {
			c := baseClaims()
			c["aud"] = "someone-elses-client"
			return signToken(t, key, "kid1", c)
		},
		"wrong issuer": func() string {
			c := baseClaims()
			c["iss"] = "https://evil.example.com"
			return signToken(t, key, "kid1", c)
		},
		"email not verified": func() string {
			c := baseClaims()
			c["email_verified"] = false
			return signToken(t, key, "kid1", c)
		},
		"expired": func() string {
			c := baseClaims()
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			return signToken(t, key, "kid1", c)
		},
		"signed by unknown key": func() string {
			// signed by `other`, but header claims kid1 (whose real key is `key`)
			return signToken(t, other, "kid1", baseClaims())
		},
		"unknown kid": func() string {
			return signToken(t, key, "kid-unknown", baseClaims())
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), mk())
			if !errors.Is(err, ErrGoogleToken) {
				t.Errorf("Verify() error = %v, want ErrGoogleToken", err)
			}
		})
	}
}

func TestGoogleVerify_MultipleClientIDs(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier([]string{"android-id", "web-id", "desktop-id"}, "kid1", &key.PublicKey)
	c := baseClaims()
	c["aud"] = "web-id"
	raw := signToken(t, key, "kid1", c)

	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Errorf("Verify() with matching web-id aud error = %v, want nil", err)
	}
}

func TestGoogleVerify_NilVerifier(t *testing.T) {
	var v *GoogleVerifier
	if _, err := v.Verify(context.Background(), "anything"); !errors.Is(err, ErrGoogleToken) {
		t.Errorf("nil verifier error = %v, want ErrGoogleToken", err)
	}
}

func TestParseGoogleClientIDs(t *testing.T) {
	got := ParseGoogleClientIDs("  a , ,b,c  ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if len(ParseGoogleClientIDs("")) != 0 {
		t.Error("empty string should parse to no ids")
	}
}
