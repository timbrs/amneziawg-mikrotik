//go:build linux && (amd64 || arm64)

package awg

import "unsafe"

type iovec struct {
	Base *byte
	Len  uint64
}

type msghdr struct {
	Name       *byte
	Namelen    uint32
	_          [4]byte // padding
	Iov        *iovec
	Iovlen     uint64
	Control    *byte
	Controllen uint64
	Flags      int32
	_          [4]byte // padding
}

type mmsghdr struct {
	Hdr msghdr
	Len uint32
	_   [4]byte // padding
}

type cmsghdr struct {
	Len   uint64
	Level int32
	Type  int32
}

const (
	mmsghdrSize = unsafe.Sizeof(mmsghdr{})
	cmsgAlign   = 8
)

func setIovecLen(iov *iovec, n uint64)       { iov.Len = n }
func setIovlen(hdr *msghdr, n uint64)        { hdr.Iovlen = n }
func setControllen(hdr *msghdr, n uint64)    { hdr.Controllen = n }
func getControllen(hdr *msghdr) int          { return int(hdr.Controllen) }
func setCmsghdrLen(cmsg *cmsghdr, n int)     { cmsg.Len = uint64(n) }
