//go:build !unix

package endpoint

// openFileLimit is a conservative guess where the platform has no
// RLIMIT_NOFILE.
func openFileLimit() int { return 1024 }
