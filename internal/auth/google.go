package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ParseGoogleClientIDs splits a comma-separated GOOGLE_CLIENT_IDS value into a
// trimmed, non-empty list of allowed OAuth client IDs (one per platform).
func ParseGoogleClientIDs(csv string) []string {
	var ids []string
	for _, part := range strings.Split(csv, ",") {
		if id := strings.TrimSpace(part); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// googleCertsURL is Google's JWKS endpoint holding the RSA public keys that sign
// OpenID Connect ID tokens. Keys rotate, so we refetch after the cache expires.
const googleCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// googleIssuers are the two accepted values of the ID token's "iss" claim.
var googleIssuers = map[string]bool{
	"accounts.google.com":         true,
	"https://accounts.google.com": true,
}

// ErrGoogleToken is returned for any failure verifying a Google ID token
// (bad signature, wrong audience, expired, unverified email, …). The handler
// maps it to 401 without leaking which check failed.
var ErrGoogleToken = errors.New("invalid google token")

// GoogleClaims is the subset of the ID token payload we rely on.
type GoogleClaims struct {
	Email         string
	Sub           string
	EmailVerified bool
}

// GoogleVerifier verifies Google-issued OpenID Connect ID tokens: it fetches and
// caches Google's signing keys (JWKS), checks the RS256 signature, and validates
// the issuer, audience (must be one of the configured client IDs), expiry, and
// email_verified. It is safe for concurrent use.
type GoogleVerifier struct {
	clientIDs []string // allowed "aud" values (Android/Web/Desktop client IDs)
	http      *http.Client

	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey // kid -> public key
	fetchedA time.Time                 // when keys were last fetched
	ttl      time.Duration             // how long cached keys stay fresh
}

// NewGoogleVerifier builds a verifier accepting tokens whose "aud" is any of
// clientIDs. Returns nil if clientIDs is empty (Google login stays disabled).
func NewGoogleVerifier(clientIDs []string) *GoogleVerifier {
	if len(clientIDs) == 0 {
		return nil
	}
	return &GoogleVerifier{
		clientIDs: clientIDs,
		http:      &http.Client{Timeout: 5 * time.Second},
		ttl:       time.Hour,
	}
}

// Verify parses and validates a raw Google ID token, returning its verified
// claims. Every failure collapses to ErrGoogleToken so callers can't distinguish
// a forged signature from a wrong audience.
func (v *GoogleVerifier) Verify(ctx context.Context, rawIDToken string) (*GoogleClaims, error) {
	if v == nil {
		return nil, ErrGoogleToken
	}
	// keyFunc resolves the signing key from the token's "kid" header, refetching
	// Google's JWKS on a miss (a key may have rotated in since our last fetch).
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("%w: unexpected alg %q", ErrGoogleToken, t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: missing kid", ErrGoogleToken)
		}
		key, err := v.keyForKid(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	var claims jwt.MapClaims
	// jwt.WithValidMethods enforces RS256 before the key lookup runs, closing the
	// "alg: none" downgrade. Expiry is validated by the parser automatically.
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})).
		ParseWithClaims(rawIDToken, &claims, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGoogleToken, err)
	}

	// issuer
	iss, _ := claims["iss"].(string)
	if !googleIssuers[iss] {
		return nil, fmt.Errorf("%w: bad issuer %q", ErrGoogleToken, iss)
	}
	// audience: must match one of our client IDs. aud may be a string or []string.
	if !v.audienceAllowed(claims["aud"]) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrGoogleToken)
	}

	email, _ := claims["email"].(string)
	sub, _ := claims["sub"].(string)
	if email == "" || sub == "" {
		return nil, fmt.Errorf("%w: missing email/sub", ErrGoogleToken)
	}
	// email_verified arrives as a bool (or occasionally the string "true").
	verified := false
	switch ev := claims["email_verified"].(type) {
	case bool:
		verified = ev
	case string:
		verified = ev == "true"
	}
	if !verified {
		return nil, fmt.Errorf("%w: email not verified", ErrGoogleToken)
	}

	return &GoogleClaims{Email: email, Sub: sub, EmailVerified: true}, nil
}

// audienceAllowed reports whether the token's "aud" claim (string or []string)
// contains one of the configured client IDs.
func (v *GoogleVerifier) audienceAllowed(aud interface{}) bool {
	match := func(a string) bool {
		for _, id := range v.clientIDs {
			if a == id {
				return true
			}
		}
		return false
	}
	switch a := aud.(type) {
	case string:
		return match(a)
	case []interface{}:
		for _, x := range a {
			if s, ok := x.(string); ok && match(s) {
				return true
			}
		}
	case []string:
		for _, s := range a {
			if match(s) {
				return true
			}
		}
	}
	return false
}

// keyForKid returns the cached public key for kid, refetching Google's JWKS when
// the cache is stale or the kid is unknown (a rotation). At most one refetch per
// call, so an unknown kid after a fresh fetch is a hard failure.
func (v *GoogleVerifier) keyForKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	fresh := time.Since(v.fetchedA) < v.ttl
	v.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}
	if err := v.refresh(ctx); err != nil {
		// If a refresh fails but we still hold the key from before, use it rather
		// than reject a valid token over a transient network blip.
		if ok {
			return key, nil
		}
		return nil, err
	}
	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown signing key", ErrGoogleToken)
	}
	return key, nil
}

// jwk is one RSA key in Google's JWKS response.
type jwk struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kty string `json:"kty"`
}

// refresh fetches Google's current JWKS and replaces the cached key set.
func (v *GoogleVerifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleCertsURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGoogleToken, err)
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: fetch certs: %v", ErrGoogleToken, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: certs status %d", ErrGoogleToken, resp.StatusCode)
	}
	var body struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("%w: decode certs: %v", ErrGoogleToken, err)
	}
	keys := make(map[string]*rsa.PublicKey, len(body.Keys))
	for _, k := range body.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := rsaKeyFromJWK(k)
		if err != nil {
			continue // skip a malformed key rather than fail the whole set
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: no usable signing keys", ErrGoogleToken)
	}
	v.mu.Lock()
	v.keys = keys
	v.fetchedA = time.Now()
	v.mu.Unlock()
	return nil
}

// rsaKeyFromJWK reconstructs an RSA public key from a JWK's base64url modulus/exponent.
func rsaKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}
