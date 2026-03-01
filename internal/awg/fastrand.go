package awg

import (
	"encoding/binary"
	"math/rand/v2"
)

// fastRand is a simple xorshift64 PRNG for hot-path random generation.
// ~3-5x faster than math/rand/v2 (ChaCha8) for non-cryptographic use.
// NOT thread-safe — use from a single goroutine only.
type fastRand struct {
	s uint64
}

// newFastRand creates a fastRand seeded from math/rand/v2.
func newFastRand() fastRand {
	s := rand.Uint64()
	if s == 0 {
		s = 1 // xorshift64 must not be zero
	}
	return fastRand{s: s}
}

// Uint64 returns the next pseudo-random uint64.
func (r *fastRand) Uint64() uint64 {
	r.s ^= r.s << 13
	r.s ^= r.s >> 7
	r.s ^= r.s << 17
	return r.s
}

// IntN returns a pseudo-random int in [0, n).
func (r *fastRand) IntN(n int) int {
	return int(r.Uint64() % uint64(n))
}

// Fill fills b with pseudo-random bytes using xorshift64.
func (r *fastRand) Fill(b []byte) {
	for i := 0; i+8 <= len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:i+8], r.Uint64())
	}
	tail := len(b) & 7
	if tail > 0 {
		v := r.Uint64()
		off := len(b) - tail
		for j := 0; j < tail; j++ {
			b[off+j] = byte(v >> (j * 8))
		}
	}
}
