package claims

import (
	"errors"
	"testing"
	"time"
)

func TestValidateExpired(t *testing.T) {
	c := map[string]any{"exp": float64(1000)}
	if err := (Validator{}).Validate(c, time.Unix(2000, 0)); err != ErrExpired {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestValidateFutureOK(t *testing.T) {
	c := map[string]any{"exp": float64(9999999999)}
	if err := (Validator{}).Validate(c, time.Unix(1000, 0)); err != nil {
		t.Errorf("expected valid, got %v", err)
	}
}

func TestValidateIssuerMismatch(t *testing.T) {
	c := map[string]any{"iss": "A"}
	if err := (Validator{Issuer: "B"}).Validate(c, time.Now()); err != ErrIssuerMismatch {
		t.Errorf("err = %v, want ErrIssuerMismatch", err)
	}
}

func TestValidateIssuerOK(t *testing.T) {
	c := map[string]any{"iss": "A"}
	if err := (Validator{Issuer: "A"}).Validate(c, time.Now()); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestValidateAudienceSlice(t *testing.T) {
	c := map[string]any{"aud": []any{"x", "y"}}
	if err := (Validator{Audience: "y"}).Validate(c, time.Now()); err != nil {
		t.Errorf("expected match in slice, got %v", err)
	}
	if err := (Validator{Audience: "z"}).Validate(c, time.Now()); err != ErrAudienceMismatch {
		t.Errorf("err = %v, want ErrAudienceMismatch", err)
	}
}

func TestValidateMissingRequired(t *testing.T) {
	c := map[string]any{}
	if err := (Validator{Require: []string{"sub"}}).Validate(c, time.Now()); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("err = %v, want ErrMissingClaim", err)
	}
}

func TestValidateNBF(t *testing.T) {
	c := map[string]any{"nbf": float64(5000)}
	if err := (Validator{}).Validate(c, time.Unix(1000, 0)); err != ErrNotBefore {
		t.Errorf("err = %v, want ErrNotBefore", err)
	}
}

func TestValidateNBFBoundary(t *testing.T) {
	nbf := int64(5000)
	c := map[string]any{"nbf": float64(nbf)}
	if err := (Validator{}).Validate(c, time.Unix(nbf, 0)); err != nil {
		t.Errorf("at nbf: %v", err)
	}
	if err := (Validator{}).Validate(c, time.Unix(nbf-1, 0)); err != ErrNotBefore {
		t.Errorf("before nbf: %v, want ErrNotBefore", err)
	}
}

func TestValidateExpAndNbfCoexist(t *testing.T) {
	now := time.Unix(3000, 0)
	c := map[string]any{"nbf": float64(2000), "exp": float64(4000)}
	if err := (Validator{}).Validate(c, now); err != nil {
		t.Errorf("valid window: %v", err)
	}
	if err := (Validator{}).Validate(c, time.Unix(1000, 0)); err != ErrNotBefore {
		t.Errorf("before nbf: %v", err)
	}
	if err := (Validator{}).Validate(c, time.Unix(5000, 0)); err != ErrExpired {
		t.Errorf("after exp: %v", err)
	}
}

func TestValidateSkew(t *testing.T) {
	exp := int64(1000)
	c := map[string]any{"exp": float64(exp)}
	v := Validator{Skew: 10 * time.Second}
	if err := v.Validate(c, time.Unix(exp+5, 0)); err != nil {
		t.Errorf("within skew: %v", err)
	}
	if err := v.Validate(c, time.Unix(exp+15, 0)); err != ErrExpired {
		t.Errorf("beyond skew: %v, want ErrExpired", err)
	}
}

func TestValidateAudienceString(t *testing.T) {
	c := map[string]any{"aud": "single-audience"}
	if err := (Validator{Audience: "single-audience"}).Validate(c, time.Now()); err != nil {
		t.Errorf("string aud match: %v", err)
	}
	if err := (Validator{Audience: "other"}).Validate(c, time.Now()); err != ErrAudienceMismatch {
		t.Errorf("string aud mismatch: %v", err)
	}
}

func TestValidateSubject(t *testing.T) {
	c := map[string]any{"sub": "user-123"}
	if err := (Validator{Subject: "user-123"}).Validate(c, time.Now()); err != nil {
		t.Errorf("sub match: %v", err)
	}
	if err := (Validator{Subject: "other"}).Validate(c, time.Now()); err != ErrSubjectMismatch {
		t.Errorf("sub mismatch: %v", err)
	}
}

func TestValidateIat(t *testing.T) {
	c := map[string]any{"iat": float64(9999999999)}
	if err := (Validator{}).Validate(c, time.Unix(1000, 0)); err != ErrIssuedInFuture {
		t.Errorf("future iat: %v", err)
	}
}

func TestValidateNoClaimsOK(t *testing.T) {
	c := map[string]any{}
	if err := (Validator{}).Validate(c, time.Now()); err != nil {
		t.Errorf("empty claims: %v", err)
	}
}

func TestValidateMultipleRequired(t *testing.T) {
	c := map[string]any{"iss": "x"}
	v := Validator{Require: []string{"iss", "sub"}}
	err := v.Validate(c, time.Now())
	if !errors.Is(err, ErrMissingClaim) {
		t.Errorf("missing sub: %v", err)
	}
	c["sub"] = "y"
	if err := v.Validate(c, time.Now()); err != nil {
		t.Errorf("all present: %v", err)
	}
}
