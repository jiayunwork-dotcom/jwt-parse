package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"jwt-parse/internal/claims"
	"jwt-parse/internal/sign"
	"jwt-parse/internal/token"
)

type Config struct {
	Addr string
}

func New(cfg Config) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/inspect", handleInspect)
	mux.HandleFunc("/api/verify", handleVerify)
	mux.HandleFunc("/api/sign", handleSign)
	return mux
}

func ListenAndServe(cfg Config) error {
	mux := New(cfg)
	return http.ListenAndServe(cfg.Addr, mux)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type inspectRequest struct {
	Token string `json:"token"`
}

type inspectResponse struct {
	Header map[string]any `json:"header"`
	Claims map[string]any `json:"claims"`
}

func handleInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req inspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Token == "" {
		httpError(w, http.StatusBadRequest, "token is empty")
		return
	}
	h, c, _, _, err := token.Parse(req.Token)
	if err != nil {
		httpError(w, http.StatusBadRequest, "parse error: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, inspectResponse{Header: h, Claims: c})
}

type verifyRequest struct {
	Token    string `json:"token"`
	Secret   string `json:"secret"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	Subject  string `json:"subject"`
}

type verifyResponse struct {
	Valid  bool           `json:"valid"`
	Header map[string]any `json:"header,omitempty"`
	Claims map[string]any `json:"claims,omitempty"`
	Error  string         `json:"error,omitempty"`
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Token == "" {
		httpError(w, http.StatusBadRequest, "token is empty")
		return
	}
	h, c, sig, input, err := token.Parse(req.Token)
	if err != nil {
		writeJSON(w, http.StatusOK, verifyResponse{Valid: false, Error: "parse: " + err.Error()})
		return
	}
	algStr, _ := h["alg"].(string)
	if err := sign.Verify(input, sig, sign.Alg(algStr), []byte(req.Secret)); err != nil {
		writeJSON(w, http.StatusOK, verifyResponse{Valid: false, Error: "signature: " + err.Error()})
		return
	}
	v := claims.Validator{Issuer: req.Issuer, Audience: req.Audience, Subject: req.Subject}
	if err := v.Validate(c, time.Now()); err != nil {
		writeJSON(w, http.StatusOK, verifyResponse{Valid: false, Header: h, Claims: c, Error: "claims: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: true, Header: h, Claims: c})
}

type signRequest struct {
	Header map[string]any `json:"header"`
	Claims map[string]any `json:"claims"`
	Secret string         `json:"secret"`
	Alg    string         `json:"alg"`
}

type signResponse struct {
	Token string `json:"token"`
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Secret == "" {
		httpError(w, http.StatusBadRequest, "secret is empty")
		return
	}
	alg := sign.Alg(req.Alg)
	if alg == "" {
		alg = sign.Alg("HS256")
	}
	if !sign.IsSupported(alg) {
		httpError(w, http.StatusBadRequest, "unsupported algorithm: "+req.Alg)
		return
	}
	if req.Header == nil {
		req.Header = map[string]any{}
	}
	req.Header["alg"] = string(alg)
	req.Header["typ"] = "JWT"
	if req.Claims == nil {
		req.Claims = map[string]any{}
	}

	hdrJSON, _ := json.Marshal(req.Header)
	clmJSON, _ := json.Marshal(req.Claims)
	hdrEnc := base64URLEncode(hdrJSON)
	clmEnc := base64URLEncode(clmJSON)
	input := hdrEnc + "." + clmEnc

	sig, err := sign.Sign(input, alg, []byte(req.Secret))
	if err != nil {
		httpError(w, http.StatusBadRequest, "sign error: "+err.Error())
		return
	}
	tok, err := token.Build(req.Header, req.Claims, sig)
	if err != nil {
		httpError(w, http.StatusBadRequest, "build error: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, signResponse{Token: tok})
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func ParsePort(addr string) int {
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return 0
	}
	p, _ := strconv.Atoi(parts[len(parts)-1])
	return p
}

func FormatAddr(addr string) string {
	port := ParsePort(addr)
	if port == 0 {
		return addr
	}
	return fmt.Sprintf("http://0.0.0.0:%d", port)
}
