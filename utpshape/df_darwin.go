package utpshape

import (
	"net"

	"golang.org/x/sys/unix"
)

func setDontFragment(c *net.UDPConn) bool {
	rc, err := c.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	if err := rc.Control(func(fd uintptr) {
		v4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		v6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
		ok = v4 == nil || v6 == nil
	}); err != nil {
		return false
	}
	return ok
}
