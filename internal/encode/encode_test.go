package encode

import (
	"testing"
	"time"

	"jwt-parse/internal/sign"
	"jwt-parse/internal/token"
)

func TestBuildAndParse(t *testing.T) {
	secret := []byte("my-secret-key")
	tok, err := NewBuilder().
		Secret(secret).
		Issuer("test-app").
		Subject("user-1").
		ExpiresAt(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	header, claims, _, sigInput, err := token.Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "HS256" {
		t.Errorf("alg = %v", header["alg"])
	}
	if claims["iss"] != "test-app" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub = %v", claims["sub"])
	}

	_, _, rawSig, parseErr := token.CompactDeserialize(tok)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if err := sign.Verify(sigInput, rawSig, sign.HS256, secret); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestBuildWithKid(t *testing.T) {
	tok, _ := NewBuilder().
		Secret([]byte("key")).
		Kid("kid-1").
		Build()
	header, _ := token.Header(tok)
	if header["kid"] != "kid-1" {
		t.Errorf("kid = %v", header["kid"])
	}
}

func TestBuildAlgNone(t *testing.T) {
	tok, err := NewBuilder().
		Alg(sign.None).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" {
		t.Error("expected non-empty token")
	}
}

func TestQuickToken(t *testing.T) {
	tok, err := QuickToken([]byte("secret"), "my-service", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, claims, _, _, _ := token.Parse(tok)
	if claims["iss"] != "my-service" {
		t.Errorf("iss = %v", claims["iss"])
	}
}
