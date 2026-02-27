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

const mmsghdrSize = unsafe.Sizeof(mmsghdr{})

func setIovecLen(iov *iovec, n uint64) { iov.Len = uint32(n) }
func setIovlen(hdr *msghdr, n uint64)  { hdr.Iovlen = uint32(n) }
