package awg

import "encoding/binary"

// BLAKE2s (RFC 7693) for WireGuard MAC1 recomputation.
// Only BLAKE2s-256 (unkeyed) and BLAKE2s-128 (keyed MAC) are implemented.

var blake2sIV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var blake2sSigma = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func rotr32(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

func blake2sG(v *[16]uint32, a, b, c, d int, x, y uint32) {
	v[a] += v[b] + x
	v[d] = rotr32(v[d]^v[a], 16)
	v[c] += v[d]
	v[b] = rotr32(v[b]^v[c], 12)
	v[a] += v[b] + y
	v[d] = rotr32(v[d]^v[a], 8)
	v[c] += v[d]
	v[b] = rotr32(v[b]^v[c], 7)
}

func blake2sCompress(h *[8]uint32, block []byte, t0, t1 uint32, last bool) {
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[i*4:])
	}

	v := [16]uint32{
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
		blake2sIV[0], blake2sIV[1], blake2sIV[2], blake2sIV[3],
		t0 ^ blake2sIV[4], t1 ^ blake2sIV[5], blake2sIV[6], blake2sIV[7],
	}
	if last {
		v[14] ^= 0xFFFFFFFF
	}

	for i := 0; i < 10; i++ {
		s := &blake2sSigma[i]
		blake2sG(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		blake2sG(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		blake2sG(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		blake2sG(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		blake2sG(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		blake2sG(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		blake2sG(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		blake2sG(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}

type blake2sState struct {
	h      [8]uint32
	t0, t1 uint32
	buf    [64]byte
	bufLen int
	nn     int
}

func blake2sInit(nn int, key []byte) blake2sState {
	var s blake2sState
	s.nn = nn
	s.h = blake2sIV
	kk := len(key)
	s.h[0] ^= 0x01010000 | uint32(kk)<<8 | uint32(nn)

	if kk > 0 {
		copy(s.buf[:], key)
		s.bufLen = 64
	}

	return s
}

func (s *blake2sState) update(data []byte) {
	if len(data) == 0 {
		return
	}

	left := s.bufLen
	fill := 64 - left

	if len(data) > fill {
		copy(s.buf[left:], data[:fill])
		s.t0 += 64
		if s.t0 < 64 {
			s.t1++
		}
		blake2sCompress(&s.h, s.buf[:], s.t0, s.t1, false)
		data = data[fill:]
		s.bufLen = 0

		for len(data) > 64 {
			s.t0 += 64
			if s.t0 < 64 {
				s.t1++
			}
			blake2sCompress(&s.h, data[:64], s.t0, s.t1, false)
			data = data[64:]
		}
	}

	copy(s.buf[s.bufLen:], data)
	s.bufLen += len(data)
}

func (s *blake2sState) sum() [32]byte {
	n := uint32(s.bufLen)
	s.t0 += n
	if s.t0 < n {
		s.t1++
	}
	for i := s.bufLen; i < 64; i++ {
		s.buf[i] = 0
	}
	blake2sCompress(&s.h, s.buf[:], s.t0, s.t1, true)

	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], s.h[i])
	}
	return out
}

// blake2s256 computes unkeyed BLAKE2s with 32-byte output.
func blake2s256(data []byte) [32]byte {
	s := blake2sInit(32, nil)
	s.update(data)
	return s.sum()
}

// blake2s128MAC computes keyed BLAKE2s with 16-byte output.
func blake2s128MAC(key [32]byte, data []byte) [16]byte {
	s := blake2sInit(16, key[:])
	s.update(data)
	full := s.sum()
	var out [16]byte
	copy(out[:], full[:16])
	return out
}

// computeMAC1Key derives mac1key = BLAKE2s-256("mac1----" || serverPub).
func computeMAC1Key(serverPub [32]byte) [32]byte {
	var input [40]byte
	copy(input[:8], "mac1----")
	copy(input[8:], serverPub[:])
	return blake2s256(input[:])
}

// recomputeMAC1 recalculates mac1 in a handshake init packet.
// buf must be at least 132 bytes. MAC1 is at bytes [116:132], covers [0:116].
func recomputeMAC1(buf []byte, mac1key [32]byte) {
	mac1 := blake2s128MAC(mac1key, buf[:116])
	copy(buf[116:132], mac1[:])
}

// recomputeMAC1Response recalculates mac1 in a handshake response packet.
// buf must be at least 76 bytes. MAC1 is at bytes [60:76], covers [0:60].
func recomputeMAC1Response(buf []byte, mac1key [32]byte) {
	mac1 := blake2s128MAC(mac1key, buf[:60])
	copy(buf[60:76], mac1[:])
}
