//go:build linux && (arm || 386)

package awg

import "unsafe"

type iovec struct {
	Base *byte
	Len  uint32
}

type msghdr struct {
	Name       *byte
	Namelen    uint32
	Iov        *iovec
	Iovlen     uint32
	Control    *byte
	Controllen uint32
	Flags      int32
}

type mmsghdr struct {
	Hdr msghdr
	Len uint32
}

type cmsghdr struct {
	Len   uint32
	Level int32
	Type  int32
}

const (
	mmsghdrSize = unsafe.Sizeof(mmsghdr{})
	cmsgAlign   = 4
)

func setIovecLen(iov *iovec, n uint64)       { iov.Len = uint32(n) }
func setIovlen(hdr *msghdr, n uint64)        { hdr.Iovlen = uint32(n) }
func setControllen(hdr *msghdr, n uint64)    { hdr.Controllen = uint32(n) }
func getControllen(hdr *msghdr) int          { return int(hdr.Controllen) }
func setCmsghdrLen(cmsg *cmsghdr, n int)     { cmsg.Len = uint32(n) }
