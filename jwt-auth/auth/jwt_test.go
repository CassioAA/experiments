package auth

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGetSecret_Missing(t *testing.T) {
	os.Unsetenv("JWT_SECRET")

	secret, err := getSecret()
	if secret != nil {
		t.Errorf("expected secret to be nil when unset, got %v", secret)
	}
	if !errors.Is(err, ErrAbsentSecret) {
		t.Errorf("expected error %v, got %v", ErrAbsentSecret, err)
	}
}

func TestGetSecret_Present(t *testing.T) {
	// at least 32 chars for HS256
	expectedSecret := "super-secret-key-with-at-least-32-chars"
	// it also runs os.Unsetenv("JWT_SECRET")
	// https://cs.opensource.google/go/go/+/master:src/testing/testing.go;l=1692;drc=cd6dd4ce340d04b30b7e7b7a83abc8b640b6c0d5
	t.Setenv("JWT_SECRET", expectedSecret)

	secret, err := getSecret()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(secret) != expectedSecret {
		t.Errorf("expected secret %q, got %q", expectedSecret, string(secret))
	}
}

// may still are there another edge cases for missing secret
func TestGenerateTokens_MissingSecret(t *testing.T) {
	os.Unsetenv("JWT_SECRET")

	token, err := GenerateAccessToken(1, "test@email.com", "Test User")
	if !errors.Is(err, ErrAbsentSecret) {
		t.Errorf("expected ErrAbsentSecret on access token generation, got %v", err)
	}
	if token != "" {
		t.Errorf("expected empty access token, got %q", token)
	}

	refreshToken, err := GenerateRefreshToken(1)
	if !errors.Is(err, ErrAbsentSecret) {
		t.Errorf("expected ErrAbsentSecret on refresh token generation, got %v", err)
	}
	if refreshToken != "" {
		t.Errorf("expected empty refresh token, got %q", refreshToken)
	}
}

func TestGenerateTokens_Success(t *testing.T) {
	t.Setenv("JWT_SECRET", "super-secret-key-with-at-least-32-chars")

	accessToken, err := GenerateAccessToken(1, "test@email.com", "Test User")
	if err != nil {
		t.Fatalf("unexpected error generating access token: %v", err)
	}
	if accessToken == "" {
		t.Errorf("expected non-empty access token")
	}

	refreshToken, err := GenerateRefreshToken(1)
	if err != nil {
		t.Fatalf("unexpected error generating refresh token: %v", err)
	}
	if refreshToken == "" {
		t.Errorf("expected non-empty refresh token")
	}
}

func TestValidateAccessToken_Success(t *testing.T) {
	t.Setenv("JWT_SECRET", "super-secret-key-with-at-least-32-chars")

	tokenString, err := GenerateAccessToken(42, "Cássio", "cassio@email.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := ValidateAccessToken(tokenString)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if claims.UserID != 42 || claims.Name != "Cássio" || claims.Email != "cassio@email.com" {
		t.Errorf("claims data mismatch: got %+v", claims)
	}
}

func TestValidateAccessToken_InvalidToken(t *testing.T) {
	t.Setenv("JWT_SECRET", "super-secret-key-with-at-least-32-chars")

	_, err := ValidateAccessToken("this.is.a.completely.invalid.token")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	secretKey := []byte("super-secret-key-with-at-least-32-chars")
	t.Setenv("JWT_SECRET", string(secretKey))

	// a token that expired 1 hour ago
	now := time.Now().Add(-1 * time.Hour)
	expiredClaims := Claims{
		UserID: 1,
		Name:   "Expired User",
		Email:  "expired@email.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now),
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString(secretKey)
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}

	_, err = ValidateAccessToken(expiredTokenString)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}
