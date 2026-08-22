package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

func hmacSig(input string, secret []byte, h func() hash.Hash) []byte {
	mac := hmac.New(h, secret)
	mac.Write([]byte(input))
	return mac.Sum(nil)
}

func TestVerifyHS256(t *testing.T) {
	input := "header.payload"
	secret := []byte("key")
	sig := hmacSig(input, secret, sha256.New)
	if err := Verify(input, sig, HS256, secret); err != nil {
		t.Errorf("expected valid, got %v", err)
	}
}

func TestVerifyHS512(t *testing.T) {
	input := "header.payload"
	secret := []byte("key")
	sig := hmacSig(input, secret, sha512.New)
	if err := Verify(input, sig, HS512, secret); err != nil {
		t.Errorf("expected valid, got %v", err)
	}
}

func TestVerifyMismatch(t *testing.T) {
	input := "header.payload"
	sig := hmacSig(input, []byte("key"), sha256.New)
	if err := Verify(input, sig, HS256, []byte("wrong")); err != ErrSignatureMismatch {
		t.Errorf("err = %v, want ErrSignatureMismatch", err)
	}
}

func TestVerifyNoneEmpty(t *testing.T) {
	if err := Verify("x", nil, None, nil); err != nil {
		t.Errorf("none empty should be valid, got %v", err)
	}
}

func TestVerifyNoneWithSig(t *testing.T) {
	if err := Verify("x", []byte("sig"), None, nil); err != ErrInsecureNone {
		t.Errorf("err = %v, want ErrInsecureNone", err)
	}
}

func TestVerifyUnsupportedAlg(t *testing.T) {
	if err := Verify("x", nil, Alg("RS256"), nil); err != ErrUnsupportedAlg {
		t.Errorf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	input := "test.payload"
	secret := []byte("round-trip-secret")
	for _, alg := range []Alg{HS256, HS384, HS512} {
		sig, err := Sign(input, alg, secret)
		if err != nil {
			t.Fatalf("Sign(%s): %v", alg, err)
		}
		if err := Verify(input, sig, alg, secret); err != nil {
			t.Errorf("Verify(%s): %v", alg, err)
		}
	}
}

func TestSignNone(t *testing.T) {
	sig, err := Sign("test", None, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sig != nil {
		t.Errorf("none sig = %v, want nil", sig)
	}
}

func TestSignUnsupported(t *testing.T) {
	_, err := Sign("x", Alg("RS256"), nil)
	if err != ErrUnsupportedAlg {
		t.Errorf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestIsSupported(t *testing.T) {
	if !IsSupported(HS256) {
		t.Error("HS256 should be supported")
	}
	if IsSupported(Alg("RS256")) {
		t.Error("RS256 should not be supported")
	}
}

func TestAlgFromString(t *testing.T) {
	if AlgFromString("HS256") != HS256 {
		t.Error("HS256 string")
	}
	if AlgFromString("unknown") != "" {
		t.Error("unknown should return empty")
	}
}

func TestVerifyHS384(t *testing.T) {
	input := "data"
	secret := []byte("s384")
	sig := hmacSig(input, secret, sha512.New384)
	if err := Verify(input, sig, HS384, secret); err != nil {
		t.Errorf("HS384 verify: %v", err)
	}
}
