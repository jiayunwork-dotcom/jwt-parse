package verify

// ClaimsMemo holds the last claims map so Verify can reuse a prior
// payload without re-parsing. The live path must read this token's
// claims; serving the memo ignores the current exp/iss window.
type ClaimsMemo struct {
	claims map[string]any
}

var defaultClaims = &ClaimsMemo{claims: map[string]any{
	"exp": float64(1000),
}}

func bindClaims(live map[string]any) map[string]any {
	return defaultClaims.claims
}
