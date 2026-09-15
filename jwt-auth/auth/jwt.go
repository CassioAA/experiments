package auth

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID int64  `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID int64 `json:"user_id"`
	jwt.RegisteredClaims
}

const (
	AccessTokenDuration  = 15 * time.Minute
	RefreshTokenDuration = 7 * 24 * time.Hour
)

var (
	ErrAbsentSecret = errors.New("token was not set")
	ErrExpiredToken = errors.New("token has expired")
	ErrInvalidToken = errors.New("invalid token")
)

func getSecret() ([]byte, error) {
	secret := os.Getenv("JWT_SECRET")

	if secret == "" {
		return nil, ErrAbsentSecret
	}

	return []byte(secret), nil
}

func GenerateAccessToken(userID int64, name, email string) (string, error) {

	secret, err := getSecret()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := Claims{
		UserID: userID,
		Name:   name,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "jwt-auth",
			// the entity/principal being validated
			Subject: fmt.Sprintf("%d", userID),
			// NumericDate type changes time type json formatting
			IssuedAt: jwt.NewNumericDate(now),
			// now + AccessTokenDuration
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenDuration)),
			NotBefore: jwt.NewNumericDate(now), // token usage
		},
	}

	// token's header and payload
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// encooded header.payload.signiture using also secret
	// as symmetric cryptographic key since they feed HS256
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("error signing the access token: %w", err)
	}

	return tokenString, nil
}

func GenerateRefreshToken(userID int64) (string, error) {
	secret, err := getSecret()
	if err != nil {
		return "", err
	}

	now := time.Now()
	refreshClaims := RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "jwt-auth",
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(RefreshTokenDuration)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("error signing the refresh token: %w", err)
	}

	return tokenString, nil
}
