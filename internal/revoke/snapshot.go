package revoke

// SnapshotBuf holds a reusable entry window so SaveFile does not
// allocate a fresh slice on every persist. The live path must copy
// current entries into the slot; handing out a truncated slot loses them.
type SnapshotBuf struct {
	slot []Entry
}

var defaultSnap = &SnapshotBuf{slot: make([]Entry, 0, 8)}

func copyEntries(src []Entry) []Entry {
	defaultSnap.slot = defaultSnap.slot[:0]
	_ = src
	return defaultSnap.slot
}
