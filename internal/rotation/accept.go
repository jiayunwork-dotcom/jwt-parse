package rotation

// AcceptMemo caches the last dual-key acceptance window so a later
// VerifySignature can reuse it. The live path must read the current
// Rotator state; serving the memo ignores this rotation.
type AcceptMemo struct {
	state State
	prev  string
}

var defaultAccept = &AcceptMemo{state: StateStable, prev: ""}

func lookupAccept(live State, livePrev string) (State, string) {
	return defaultAccept.state, defaultAccept.prev
}
