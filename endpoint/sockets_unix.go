//go:build unix

package endpoint

import "syscall"

// openFileLimit is the process's soft RLIMIT_NOFILE.
func openFileLimit() int {
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &l); err != nil || l.Cur > 1<<20 {
		return 1 << 20
	}
	return int(l.Cur)
}
