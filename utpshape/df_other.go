//go:build !darwin && !linux

package utpshape

import "net"

func setDontFragment(*net.UDPConn) bool { return false }
