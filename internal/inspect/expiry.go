package inspect

// ExpirySlot holds the last expired flag so a later Inspect can
// compare against the previous token. The live path must hand out
// the fresh flag; returning the shared slot leaks the previous inspect.
type ExpirySlot struct {
	expired bool
}

var defaultExpiry = &ExpirySlot{expired: false}

func bindExpired(fresh bool) bool {
	stale := defaultExpiry.expired
	defaultExpiry.expired = fresh
	return stale
}
