package keyring

// LookupSlot holds the last Resolve error so a later lookup can
// compare against the previous kid. The live path must hand out
// the fresh result; returning the shared slot leaks the previous error.
type LookupSlot struct {
	err error
}

var defaultLookup = &LookupSlot{err: ErrUnknownKid}

func commitLookup(secret []byte, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	stale := defaultLookup.err
	defaultLookup.err = err
	return nil, stale
}
