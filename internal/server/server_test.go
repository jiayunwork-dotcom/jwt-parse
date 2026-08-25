package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	mux := New(Config{Addr: ":8080"})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestSignAndVerify(t *testing.T) {
	mux := New(Config{Addr: ":8080"})

	signPayload := signRequest{
		Claims: map[string]any{"sub": "user1", "iss": "test"},
		Secret: "mysecret",
		Alg:    "HS256",
	}
	body, _ := json.Marshal(signPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var signResp signResponse
	json.Unmarshal(rec.Body.Bytes(), &signResp)
	if signResp.Token == "" {
		t.Fatal("expected non-empty token")
	}

	verifyPayload := verifyRequest{Token: signResp.Token, Secret: "mysecret"}
	body, _ = json.Marshal(verifyPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var verResp verifyResponse
	json.Unmarshal(rec.Body.Bytes(), &verResp)
	if !verResp.Valid {
		t.Errorf("expected valid=true, got error: %s", verResp.Error)
	}
}

func TestVerifyEndpoint_BadSecret(t *testing.T) {
	mux := New(Config{Addr: ":8080"})

	signPayload := signRequest{Claims: map[string]any{"sub": "u"}, Secret: "secret1", Alg: "HS256"}
	body, _ := json.Marshal(signPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var signResp signResponse
	json.Unmarshal(rec.Body.Bytes(), &signResp)

	verifyPayload := verifyRequest{Token: signResp.Token, Secret: "wrong"}
	body, _ = json.Marshal(verifyPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var verResp verifyResponse
	json.Unmarshal(rec.Body.Bytes(), &verResp)
	if verResp.Valid {
		t.Error("expected valid=false with wrong secret")
	}
}

func TestInspectEndpoint(t *testing.T) {
	mux := New(Config{Addr: ":8080"})

	signPayload := signRequest{Claims: map[string]any{"sub": "alice"}, Secret: "s", Alg: "HS256"}
	body, _ := json.Marshal(signPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var signResp signResponse
	json.Unmarshal(rec.Body.Bytes(), &signResp)

	inspPayload := inspectRequest{Token: signResp.Token}
	body, _ = json.Marshal(inspPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/inspect", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var inspResp inspectResponse
	json.Unmarshal(rec.Body.Bytes(), &inspResp)
	if inspResp.Header["alg"] != "HS256" {
		t.Errorf("expected alg=HS256, got %v", inspResp.Header["alg"])
	}
	if inspResp.Claims["sub"] != "alice" {
		t.Errorf("expected sub=alice, got %v", inspResp.Claims["sub"])
	}
}

func TestInspectEndpoint_Empty(t *testing.T) {
	mux := New(Config{Addr: ":8080"})
	body := []byte(`{"token":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/inspect", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestSignEndpoint_NoSecret(t *testing.T) {
	mux := New(Config{Addr: ":8080"})
	body := []byte(`{"claims":{"sub":"x"},"secret":"","alg":"HS256"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	mux := New(Config{Addr: ":8080"})
	endpoints := []string{"/api/inspect", "/api/verify", "/api/sign"}
	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", ep, rec.Code)
		}
	}
}
