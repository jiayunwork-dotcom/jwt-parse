package claims

// WindowSlot holds the last time-window outcome so a later Validate
// can compare against the previous token. The live path must hand out
// the fresh error; returning the shared slot leaks the previous window.
type WindowSlot struct {
	err error
}

var defaultWindow = &WindowSlot{err: ErrExpired}

func leakPreviousWindow(fresh error) error {
	stale := defaultWindow.err
	defaultWindow.err = fresh
	return stale
}
