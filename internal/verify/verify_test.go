package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"jwt-parse/internal/keyring"
)

func makeToken(header, claims map[string]any, secret []byte) string {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(hb)
	c := base64.RawURLEncoding.EncodeToString(cb)
	input := h + "." + c
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return input + "." + sig
}

func makeRing(kids map[string][]byte, defaultKid string) *keyring.Ring {
	data := fmt.Sprintf(`{"keys":{`)
	first := true
	for kid, secret := range kids {
		if !first {
			data += ","
		}
		data += fmt.Sprintf(`"%s":"%s"`, kid, base64.StdEncoding.EncodeToString(secret))
		first = false
	}
	data += fmt.Sprintf(`},"default_kid":"%s"}`, defaultKid)
	ring, _ := keyring.Parse([]byte(data))
	return ring
}

func TestVerifyValidToken(t *testing.T) {
	secret := []byte("test-secret-256-bits-long-enough")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{"iss": "auth-svc", "exp": float64(now.Add(time.Hour).Unix())},
		secret,
	)

	v := NewVerifierFromRing(ring, Config{
		ExpectedIssuer: "auth-svc",
		NowFunc:        func() time.Time { return now },
	})

	res, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Kid != "k1" {
		t.Errorf("Kid = %q, want k1", res.Kid)
	}
	if res.Alg != "HS256" {
		t.Errorf("Alg = %q, want HS256", res.Alg)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	secret := []byte("test-secret")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{"exp": float64(now.Add(-time.Hour).Unix())},
		secret,
	)

	v := NewVerifierFromRing(ring, Config{
		NowFunc: func() time.Time { return now },
	})

	_, err := v.Verify(tok)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyUnknownKidRejected(t *testing.T) {
	secret := []byte("test-secret")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "unknown-kid"},
		map[string]any{},
		secret,
	)

	v := NewVerifierFromRing(ring, Config{})
	_, err := v.Verify(tok)
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestVerifyNoKidUsesDefault(t *testing.T) {
	secret := []byte("default-secret")
	ring := makeRing(map[string][]byte{"default": secret}, "default")

	tok := makeToken(
		map[string]any{"alg": "HS256"}, // no kid
		map[string]any{},
		secret,
	)

	v := NewVerifierFromRing(ring, Config{})
	res, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Kid != "" {
		t.Errorf("Kid should be empty (used default)")
	}
}

func TestVerifyNoKidNoDefaultErrors(t *testing.T) {
	secret := []byte("test")
	// ring with no default
	data := fmt.Sprintf(`{"keys":{"k1":"%s"}}`, base64.StdEncoding.EncodeToString(secret))
	ring, _ := keyring.Parse([]byte(data))

	tok := makeToken(
		map[string]any{"alg": "HS256"}, // no kid
		map[string]any{},
		secret,
	)

	v := NewVerifierFromRing(ring, Config{})
	_, err := v.Verify(tok)
	if err == nil {
		t.Fatal("expected ErrNoKid")
	}
}

func TestVerifyAudienceMultiValue(t *testing.T) {
	secret := []byte("aud-test-secret")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{"aud": []any{"svc-a", "svc-b", "svc-c"}, "exp": float64(now.Add(time.Hour).Unix())},
		secret,
	)

	// should match when expected audience is in the array
	v := NewVerifierFromRing(ring, Config{
		ExpectedAudience: "svc-b",
		NowFunc:          func() time.Time { return now },
	})
	_, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify with aud array: %v", err)
	}

	// should fail when expected audience is NOT in the array
	v2 := NewVerifierFromRing(ring, Config{
		ExpectedAudience: "svc-x",
		NowFunc:          func() time.Time { return now },
	})
	_, err = v2.Verify(tok)
	if err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestVerifyNbfBoundary(t *testing.T) {
	secret := []byte("nbf-test")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	nbfTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	expTime := nbfTime.Add(time.Hour)

	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{"nbf": float64(nbfTime.Unix()), "exp": float64(expTime.Unix())},
		secret,
	)

	// exactly at nbf: should pass
	v := NewVerifierFromRing(ring, Config{
		NowFunc: func() time.Time { return nbfTime },
	})
	_, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("at nbf: %v", err)
	}

	// before nbf: should fail
	v2 := NewVerifierFromRing(ring, Config{
		NowFunc: func() time.Time { return nbfTime.Add(-time.Second) },
	})
	_, err = v2.Verify(tok)
	if err == nil {
		t.Fatal("before nbf should fail")
	}
}

func TestVerifyWrongSignature(t *testing.T) {
	secret := []byte("correct-secret")
	wrongSecret := []byte("wrong-secret")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{},
		wrongSecret, // signed with wrong key
	)

	v := NewVerifierFromRing(ring, Config{})
	_, err := v.Verify(tok)
	if err == nil {
		t.Fatal("expected signature error")
	}
}

func TestVerifyRequiredClaims(t *testing.T) {
	secret := []byte("req-test")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{"exp": float64(now.Add(time.Hour).Unix()), "iss": "auth"},
		secret,
	)

	// require "sub" which is missing
	v := NewVerifierFromRing(ring, Config{
		RequiredClaims: []string{"sub"},
		NowFunc:        func() time.Time { return now },
	})
	_, err := v.Verify(tok)
	if err == nil {
		t.Fatal("expected error for missing required claim")
	}
}

func TestVerifyWithSkew(t *testing.T) {
	secret := []byte("skew-test")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	expTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{"exp": float64(expTime.Unix())},
		secret,
	)

	// 5s after exp, but with 10s skew -> should pass
	v := NewVerifierFromRing(ring, Config{
		Skew:    10 * time.Second,
		NowFunc: func() time.Time { return expTime.Add(5 * time.Second) },
	})
	_, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("within skew: %v", err)
	}

	// 15s after exp with 10s skew -> should fail
	v2 := NewVerifierFromRing(ring, Config{
		Skew:    10 * time.Second,
		NowFunc: func() time.Time { return expTime.Add(15 * time.Second) },
	})
	_, err = v2.Verify(tok)
	if err == nil {
		t.Fatal("beyond skew should fail")
	}
}

func TestVerifyMultipleKidsInRing(t *testing.T) {
	s1 := []byte("secret-for-k1")
	s2 := []byte("secret-for-k2")
	s3 := []byte("secret-for-k3")
	ring := makeRing(map[string][]byte{"k1": s1, "k2": s2, "k3": s3}, "k1")

	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	// token signed with k2's secret
	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k2"},
		map[string]any{"exp": float64(now.Add(time.Hour).Unix())},
		s2,
	)

	v := NewVerifierFromRing(ring, Config{
		NowFunc: func() time.Time { return now },
	})
	res, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify with k2: %v", err)
	}
	if res.Kid != "k2" {
		t.Errorf("Kid = %q, want k2", res.Kid)
	}
}

func TestVerifyKeyringFromFile(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("file-based-secret")
	ring := makeRing(map[string][]byte{"fk": secret}, "fk")
	ring.SaveFile(dir + "/keys.json")

	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "fk"},
		map[string]any{"exp": float64(now.Add(time.Hour).Unix())},
		secret,
	)

	v, err := NewVerifier(Config{
		KeyringPath: dir + "/keys.json",
		NowFunc:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, err = v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify from file: %v", err)
	}
}

func TestVerifyMissingAlgHeader(t *testing.T) {
	secret := []byte("test")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	tok := makeToken(
		map[string]any{"kid": "k1"}, // no alg
		map[string]any{},
		secret,
	)

	v := NewVerifierFromRing(ring, Config{})
	_, err := v.Verify(tok)
	if err == nil {
		t.Fatal("missing alg should error")
	}
}

func TestVerifyIssuerMismatch(t *testing.T) {
	secret := []byte("iss-test")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{"iss": "wrong-issuer"},
		secret,
	)

	v := NewVerifierFromRing(ring, Config{ExpectedIssuer: "correct-issuer"})
	_, err := v.Verify(tok)
	if err == nil {
		t.Fatal("issuer mismatch should error")
	}
}

func TestVerifySubjectMatch(t *testing.T) {
	secret := []byte("sub-test")
	ring := makeRing(map[string][]byte{"k1": secret}, "k1")

	tok := makeToken(
		map[string]any{"alg": "HS256", "kid": "k1"},
		map[string]any{"sub": "user-42"},
		secret,
	)

	v := NewVerifierFromRing(ring, Config{ExpectedSubject: "user-42"})
	_, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("subject match: %v", err)
	}
}
