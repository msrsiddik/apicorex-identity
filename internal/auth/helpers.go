package auth

import "github.com/golang-jwt/jwt/v5"

func jwtRegisteredClaims(subject string) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{Subject: subject}
}
