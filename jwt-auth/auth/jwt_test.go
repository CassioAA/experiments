package auth

import (
	"errors"
	"os"
	"testing"
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
	expectedSecret := "super-secret-key-with-at-least-32-chars"
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
