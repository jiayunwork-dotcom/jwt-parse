package header

import "testing"

func TestParseBasic(t *testing.T) {
	raw := map[string]any{"alg": "HS256", "typ": "JWT", "kid": "key1"}
	h := Parse(raw)
	if h.Alg != "HS256" || h.Typ != "JWT" || h.Kid != "key1" {
		t.Errorf("parsed = %+v", h)
	}
}

func TestPolicyRejectNone(t *testing.T) {
	pol := DefaultPolicy()
	h := &Parsed{Alg: "none"}
	if err := pol.Validate(h); err == nil {
		t.Error("expected none rejection")
	}
}

func TestPolicyAllowHS256(t *testing.T) {
	pol := DefaultPolicy()
	h := &Parsed{Alg: "HS256"}
	if err := pol.Validate(h); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPolicyRejectUnknownAlg(t *testing.T) {
	pol := DefaultPolicy()
	h := &Parsed{Alg: "RS256"}
	if err := pol.Validate(h); err == nil {
		t.Error("expected unknown alg rejection")
	}
}

func TestIsSymmetric(t *testing.T) {
	if !IsSymmetric("HS256") {
		t.Error("HS256 should be symmetric")
	}
	if IsSymmetric("RS256") {
		t.Error("RS256 should not be symmetric")
	}
}
