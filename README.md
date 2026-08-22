# jwt-parse

JWT (JSON Web Token) parsing, verification, and lifecycle management tool (CLI).

Supports HMAC signing (HS256/HS384/HS512), multi-key keyring with kid resolution, claims validation with clock injection, key rotation with grace period, token revocation (JTI blacklist), policy engine, token refresh, and audit logging.

## Architecture

```
token (parse/build/compact) → sign (HMAC + derive)
      ↓
header (parse + policy) → verify (integrated pipeline)
      ↓
claims (validate + custom registry)
      ↓
keyring (load/resolve/generate/rotate)
      ↓
rotation (dual-key verification window)
revoke (JTI blacklist + persist)
policy (algorithm/claims/issuer restrictions)
inspect (diagnostic analysis)
encode (builder-pattern token creation)
refresh (token renewal with lineage tracking)
audit (verification event logging)
clock (injectable time source)
```

Packages:

| Package | Role |
|---------|------|
| `internal/token` | JWT structure parsing, compact serialization, segment extraction |
| `internal/sign` | HMAC signing/verification (HS256/384/512), key derivation (HKDF-SHA256) |
| `internal/claims` | Standard claims validation (exp/nbf/iat/iss/aud/sub), custom validator registry |
| `internal/header` | JOSE header parsing, algorithm policy enforcement, security checks |
| `internal/keyring` | Multi-key HMAC keyring (JSON persistence), key generation, kid resolution |
| `internal/verify` | Integrated verification pipeline (parse→key→sign→claims) |
| `internal/rotation` | Key rotation with grace period (dual-key acceptance during window) |
| `internal/revoke` | JTI-based revocation list with expiry and persistence |
| `internal/policy` | Verification policy engine (algorithm/claims/issuer/audience/age restrictions) |
| `internal/inspect` | Diagnostic token analysis without verification |
| `internal/encode` | Builder-pattern JWT creation with fluent API |
| `internal/refresh` | Token renewal with TTL, refresh count tracking, claim preservation |
| `internal/audit` | Verification event logger (JSON-lines file + in-memory) |
| `internal/clock` | Injectable time source for deterministic testing |

## Usage

```bash
# Inspect a token (no verification)
jwt-parse inspect <token>

# Verify a token with a secret
jwt-parse verify <token> -secret mykey -iss my-service -aud my-app
```

## Security Invariants

- Unknown kid NEVER falls back to default key silently
- `alg:none` with non-empty signature is always rejected
- HMAC uses constant-time comparison (hmac.Equal)
- Key rotation: both old and new keys accepted during window, only new key signs

## Build & Test

```bash
export GOTOOLCHAIN=local CGO_ENABLED=0
go build ./...
go test ./...
```

## License

MIT
