//go:build race

package roster

// raceEnabled skips wall-clock bounds, which the race detector slows by an
// order of magnitude.
const raceEnabled = true
