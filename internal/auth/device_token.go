package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// deviceTokenPrefix marks raw device tokens on the wire so the gateway can
// cheaply reject garbage before hashing.
const deviceTokenPrefix = "zdt_"

// GenerateDeviceToken returns a new raw opaque device token ("zdt_" + 32
// random bytes, base64url). The raw value is shown to the client exactly once;
// only HashToken(raw) is persisted.
func GenerateDeviceToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate device token: %w", err)
	}
	return deviceTokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken returns the sha256 hex digest of a raw device token — the only
// form ever stored or compared.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
