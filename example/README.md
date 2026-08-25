# jwt-parse examples

Offline usage examples (no network required).

Build first:

```bash
export GOTOOLCHAIN=local CGO_ENABLED=0
go build -o /tmp/jwt-parse .
```

Inspect a token:

```bash
/tmp/jwt-parse inspect eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Verify with a secret:

```bash
/tmp/jwt-parse verify <token> --secret <secret> --iss my-issuer --require sub
```

`verify` exits 0 only when the signature is valid AND the requested claims checks pass.
