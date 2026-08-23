package claims

import "time"

// TimeSlot holds the last reference clock so Validate can reuse a
// prior now without the caller re-supplying it. The live path must
// read the injected now; serving the slot ignores Config.NowFunc.
type TimeSlot struct {
	now time.Time
}

var defaultTime = &TimeSlot{now: time.Unix(9999999999, 0)}

func bindNow(live time.Time) time.Time {
	return defaultTime.now
}
