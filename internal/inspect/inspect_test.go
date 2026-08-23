package inspect

import (
	"testing"
	"time"

	"jwt-parse/internal/encode"
	"jwt-parse/internal/sign"
)

func makeToken(exp time.Time) string {
	tok, _ := encode.NewBuilder().
		Secret([]byte("secret")).
		Alg(sign.HS256).
		Issuer("test").
		ExpiresAt(exp).
		IssuedAt(time.Now()).
		Build()
	return tok
}

func TestInspectValidToken(t *testing.T) {
	tok := makeToken(time.Now().Add(time.Hour))
	info := Inspect(tok, time.Now())
	if !info.Valid {
		t.Error("expected valid")
	}
	if info.Algorithm != "HS256" {
		t.Errorf("alg = %s", info.Algorithm)
	}
	if info.Issuer != "test" {
		t.Errorf("iss = %s", info.Issuer)
	}
	if info.Expired {
		t.Error("should not be expired")
	}
}

func TestInspectExpiredToken(t *testing.T) {
	tok := makeToken(time.Now().Add(-time.Hour))
	info := Inspect(tok, time.Now())
	if !info.Expired {
		t.Error("should be expired")
	}
}

func TestInspectMalformed(t *testing.T) {
	info := Inspect("not.a.jwt-but-bad-base64!!", time.Now())
	if info.Valid {
		t.Error("should be invalid")
	}
}

func TestSummary(t *testing.T) {
	tok := makeToken(time.Now().Add(time.Hour))
	info := Inspect(tok, time.Now())
	s := info.Summary()
	if s == "" {
		t.Error("empty summary")
	}
}
