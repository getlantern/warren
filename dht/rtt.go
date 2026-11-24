package dht

import "time"

// minShortTimeout is the floor of the adaptive short timeout: below it,
// ordinary jitter would mark answering nodes slow.
const minShortTimeout = 250 * time.Millisecond

// rttEstimator smooths the round trip of answered queries, as TCP does
// (RFC 6298), so a lookup can tell a slow node from a dead one by this
// network's timing rather than a fixed second.
type rttEstimator struct {
	srtt, rttvar time.Duration
	samples      int
}

func (r *rttEstimator) sample(d time.Duration) {
	if d <= 0 {
		return
	}
	if r.samples == 0 {
		r.srtt, r.rttvar = d, d/2
	} else {
		dev := r.srtt - d
		if dev < 0 {
			dev = -dev
		}
		r.rttvar += (dev - r.rttvar) / 4
		r.srtt += (d - r.srtt) / 8
	}
	r.samples++
}

// shortTimeout is how long a query may go unanswered before the lookup
// stops counting it as active and sends another: the smoothed round trip
// plus four deviations, between minShortTimeout and ceiling. Until a few
// replies have been timed, it is ceiling.
func (r *rttEstimator) shortTimeout(ceiling time.Duration) time.Duration {
	if r.samples < 4 {
		return ceiling
	}
	return min(max(r.srtt+4*r.rttvar, minShortTimeout), ceiling)
}
