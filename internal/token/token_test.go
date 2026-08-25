package token

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func seg(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestParseOK(t *testing.T) {
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	payload := map[string]any{"sub": "123", "exp": 9999999999.0}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	tok := seg(hb) + "." + seg(pb) + "." + seg([]byte("sig"))
	h, c, sig, input, err := Parse(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h["alg"] != "HS256" {
		t.Errorf("header alg = %v", h["alg"])
	}
	if c["sub"] != "123" {
		t.Errorf("claims sub = %v", c["sub"])
	}
	if string(sig) != "sig" {
		t.Errorf("sig = %q", sig)
	}
	if got, want := input, seg(hb)+"."+seg(pb); got != want {
		t.Errorf("input = %q want %q", got, want)
	}
}

func TestParseTooFewSegments(t *testing.T) {
	if _, _, _, _, err := Parse("a.b"); err != ErrMalformed {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

func TestParseBadBase64(t *testing.T) {
	if _, _, _, _, err := Parse("!!!.!!!.!!!"); err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestParsePreservesNestedSlice(t *testing.T) {
	payload := map[string]any{"roles": []any{"a", "b"}}
	pb, _ := json.Marshal(payload)
	tok := seg([]byte(`{"alg":"none"}`)) + "." + seg(pb) + "." + seg(nil)
	_, c, _, _, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	roles, ok := c["roles"].([]any)
	if !ok || len(roles) != 2 {
		t.Errorf("roles = %v", c["roles"])
	}
}

func TestBuildAndParseRoundTrip(t *testing.T) {
	header := map[string]any{"alg": "HS256", "kid": "test-key"}
	claims := map[string]any{"sub": "user-1", "aud": []any{"svc-a", "svc-b"}}
	sig := []byte("fake-signature-bytes")

	tok, err := Build(header, claims, sig)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	h, c, gotSig, _, err := Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h["kid"] != "test-key" {
		t.Errorf("kid = %v", h["kid"])
	}
	if c["sub"] != "user-1" {
		t.Errorf("sub = %v", c["sub"])
	}
	if string(gotSig) != string(sig) {
		t.Errorf("sig mismatch")
	}
}

func TestHeaderExtract(t *testing.T) {
	hb, _ := json.Marshal(map[string]any{"alg": "HS512", "kid": "k1"})
	tok := seg(hb) + "." + seg([]byte(`{}`)) + "." + seg(nil)

	h, err := Header(tok)
	if err != nil {
		t.Fatal(err)
	}
	if h["alg"] != "HS512" {
		t.Errorf("alg = %v", h["alg"])
	}
}

func TestSigningInput(t *testing.T) {
	tok := "aaa.bbb.ccc"
	input, err := SigningInput(tok)
	if err != nil {
		t.Fatal(err)
	}
	if input != "aaa.bbb" {
		t.Errorf("input = %q, want aaa.bbb", input)
	}
}

func TestSigningInputMalformed(t *testing.T) {
	_, err := SigningInput("nodots")
	if err != ErrMalformed {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

func TestBuildNilSig(t *testing.T) {
	tok, err := Build(map[string]any{"alg": "none"}, map[string]any{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 0 {
		t.Errorf("sig = %v, want empty", sig)
	}
}

func TestParseEmptyString(t *testing.T) {
	_, _, _, _, err := Parse("")
	if err != ErrMalformed {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}
