//go:build race

package bencode

// raceEnabled skips wall-clock bounds, which the race detector slows.
const raceEnabled = true
