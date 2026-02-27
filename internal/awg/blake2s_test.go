package awg

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/blake2s"
)

func TestBLAKE2s256Empty(t *testing.T) {
	got := blake2s256(nil)

	ref, _ := blake2s.New256(nil)
	var want [32]byte
	copy(want[:], ref.Sum(nil))

	if got != want {
		t.Fatalf("BLAKE2s-256 empty:\n  got  %x\n  want %x", got, want)
	}
}

func TestBLAKE2s256ABC(t *testing.T) {
	got := blake2s256([]byte("abc"))

	ref, _ := blake2s.New256(nil)
	ref.Write([]byte("abc"))
	var want [32]byte
	copy(want[:], ref.Sum(nil))

	if got != want {
		t.Fatalf("BLAKE2s-256 abc:\n  got  %x\n  want %x", got, want)
	}
}

func TestBLAKE2s256LongInput(t *testing.T) {
	// Test with input larger than one block (64 bytes).
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}

	got := blake2s256(data)

	ref, _ := blake2s.New256(nil)
	ref.Write(data)
	var want [32]byte
	copy(want[:], ref.Sum(nil))

	if got != want {
		t.Fatalf("BLAKE2s-256 long:\n  got  %x\n  want %x", got, want)
	}
}

func TestBLAKE2s256ExactBlock(t *testing.T) {
	// Exactly 64 bytes = 1 block.
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}

	got := blake2s256(data)

	ref, _ := blake2s.New256(nil)
	ref.Write(data)
	var want [32]byte
	copy(want[:], ref.Sum(nil))

	if got != want {
		t.Fatalf("BLAKE2s-256 exact block:\n  got  %x\n  want %x", got, want)
	}
}

func TestBLAKE2s256TwoBlocks(t *testing.T) {
	// Exactly 128 bytes = 2 blocks.
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}

	got := blake2s256(data)

	ref, _ := blake2s.New256(nil)
	ref.Write(data)
	var want [32]byte
	copy(want[:], ref.Sum(nil))

	if got != want {
		t.Fatalf("BLAKE2s-256 two blocks:\n  got  %x\n  want %x", got, want)
	}
}

func TestBLAKE2s128Keyed(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	data := []byte("test data for keyed blake2s")

	got := blake2s128MAC(key, data)

	ref, _ := blake2s.New128(key[:])
	ref.Write(data)
	want := ref.Sum(nil)

	for i := 0; i < 16; i++ {
		if got[i] != want[i] {
			t.Fatalf("BLAKE2s-128 keyed:\n  got  %x\n  want %x", got, want[:16])
		}
	}
}

func TestBLAKE2s128KeyedEmpty(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 0x80)
	}

	got := blake2s128MAC(key, nil)

	ref, _ := blake2s.New128(key[:])
	want := ref.Sum(nil)

	for i := 0; i < 16; i++ {
		if got[i] != want[i] {
			t.Fatalf("BLAKE2s-128 keyed empty:\n  got  %x\n  want %x", got, want[:16])
		}
	}
}

func TestBLAKE2s128KeyedLong(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	data := make([]byte, 300)
	for i := range data {
		data[i] = byte(i)
	}

	got := blake2s128MAC(key, data)

	ref, _ := blake2s.New128(key[:])
	ref.Write(data)
	want := ref.Sum(nil)

	for i := 0; i < 16; i++ {
		if got[i] != want[i] {
			t.Fatalf("BLAKE2s-128 keyed long:\n  got  %x\n  want %x", got, want[:16])
		}
	}
}

func TestComputeMAC1Key(t *testing.T) {
	var serverPub [32]byte
	for i := range serverPub {
		serverPub[i] = byte(i + 1)
	}

	got := computeMAC1Key(serverPub)

	// Manual computation: BLAKE2s-256("mac1----" || serverPub)
	var input [40]byte
	copy(input[:8], "mac1----")
	copy(input[8:], serverPub[:])
	ref, _ := blake2s.New256(nil)
	ref.Write(input[:])
	var want [32]byte
	copy(want[:], ref.Sum(nil))

	if got != want {
		t.Fatalf("computeMAC1Key:\n  got  %x\n  want %x", got, want)
	}
}

func TestRecomputeMAC1(t *testing.T) {
	// Create a fake handshake init packet with H1 type.
	var serverPub [32]byte
	for i := range serverPub {
		serverPub[i] = byte(i + 0x10)
	}

	h1 := uint32(1234567890)
	mac1key := computeMAC1Key(serverPub)

	buf := make([]byte, WgHandshakeInitSize)
	binary.LittleEndian.PutUint32(buf[:4], h1)
	for i := 4; i < 116; i++ {
		buf[i] = byte(i)
	}

	recomputeMAC1(buf, mac1key)

	// Verify: mac1 at [116:132] = BLAKE2s-128-keyed(mac1key, buf[0:116])
	ref, _ := blake2s.New128(mac1key[:])
	ref.Write(buf[:116])
	want := ref.Sum(nil)

	for i := 0; i < 16; i++ {
		if buf[116+i] != want[i] {
			t.Fatalf("recomputeMAC1: byte %d mismatch\n  got  %x\n  want %x", i, buf[116:132], want[:16])
		}
	}
}

func TestBLAKE2s256IncrementalUpdate(t *testing.T) {
	// Verify that multiple update calls produce the same result as a single call.
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}

	// Single update.
	s1 := blake2sInit(32, nil)
	s1.update(data)
	got1 := s1.sum()

	// Multiple updates: 10 + 50 + 140.
	s2 := blake2sInit(32, nil)
	s2.update(data[:10])
	s2.update(data[10:60])
	s2.update(data[60:])
	got2 := s2.sum()

	if got1 != got2 {
		t.Fatalf("incremental update mismatch:\n  single %x\n  multi  %x", got1, got2)
	}

	// Verify against reference.
	ref, _ := blake2s.New256(nil)
	ref.Write(data)
	var want [32]byte
	copy(want[:], ref.Sum(nil))

	if got1 != want {
		t.Fatalf("incremental vs reference:\n  got  %x\n  want %x", got1, want)
	}
}
