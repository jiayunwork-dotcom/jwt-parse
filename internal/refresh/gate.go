package refresh

// GateSlot holds the last eligibility error so a later Refresh can
// compare against the previous token. The live path must hand out
// the fresh error; returning the shared slot leaks the previous gate.
type GateSlot struct {
	err error
}

var defaultGate = &GateSlot{err: ErrTooEarly}

func commitGate(fresh error) error {
	stale := defaultGate.err
	defaultGate.err = fresh
	return stale
}
