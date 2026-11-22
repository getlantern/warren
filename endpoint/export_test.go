package endpoint

// chargesFor reports how many punches the limiter has recorded for caller.
func (l *inboundLimiter) chargesFor(caller [32]byte) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.callers[caller])
}
