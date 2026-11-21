package dht

import "time"

// health detects a sudden rise in failures from routing contacts, the
// signature of a network partition. Absolute failure rates are a poor signal:
// a DHT always has dead contacts, and when a 25%-diaspora community is cut off
// the rate may only rise to 30–50%. So it compares a fast moving average with
// a slow baseline. Only previously responsive contacts count; referrals are
// often stale and would drown the signal.
type health struct {
	fast, slow float64
	samples    int
	suspected  bool
	since      time.Time
}

const (
	healthMinSamples  = 32
	healthEnterRise   = 0.15
	healthEnterFloor  = 0.2
	healthExitMargin  = 0.05
	healthMinDuration = 10 * time.Minute
)

func (h *health) record(fail bool) {
	x := 0.0
	if fail {
		x = 1
	}
	if h.samples == 0 {
		h.fast, h.slow = x, x
	}
	h.fast += (x - h.fast) / 16
	h.slow += (x - h.slow) / 256
	h.samples++
}

func (h *health) eval(now time.Time) (changed bool) {
	switch {
	case !h.suspected && h.samples >= healthMinSamples && h.fast > healthEnterFloor && h.fast-h.slow > healthEnterRise:
		h.suspected, h.since = true, now
		return true
	case h.suspected && now.Sub(h.since) >= healthMinDuration && h.fast < h.slow+healthExitMargin:
		h.suspected = false
		return true
	}
	return false
}
