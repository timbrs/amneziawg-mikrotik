package awg

import (
	"encoding/binary"
	"math/rand/v2"
)

// randFill fills b with pseudo-random bytes using math/rand/v2.
func randFill(b []byte) {
	for i := 0; i+8 <= len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:i+8], rand.Uint64())
	}
	// Handle remaining bytes.
	tail := len(b) & 7
	if tail > 0 {
		v := rand.Uint64()
		off := len(b) - tail
		for j := 0; j < tail; j++ {
			b[off+j] = byte(v >> (j * 8))
		}
	}
}

// Standard WireGuard message types (little-endian uint32 in first 4 bytes).
const (
	wgHandshakeInit     uint32 = 1
	wgHandshakeResponse uint32 = 2
	wgCookieReply       uint32 = 3
	wgTransportData     uint32 = 4
)

// Standard WireGuard packet sizes.
const (
	WgHandshakeInitSize     = 148
	WgHandshakeResponseSize = 92
	WgCookieReplySize       = 64
	WgTransportMinSize      = 32
)

// HRange represents a uint32 range [Min, Max] for v2 H-parameters.
type HRange struct {
	Min, Max uint32
}

// Pick returns a random value in [Min, Max]. Returns Min if Min == Max.
func (r HRange) Pick() uint32 {
	if r.Min == r.Max {
		return r.Min
	}
	return r.Min + uint32(rand.IntN(int(r.Max-r.Min+1)))
}

// Contains returns true if v is in [Min, Max].
func (r HRange) Contains(v uint32) bool {
	return v >= r.Min && v <= r.Max
}

// Config holds AmneziaWG obfuscation parameters.
type Config struct {
	Jc   int    // junk packet count before handshake init
	Jmin int    // min junk packet size
	Jmax int    // max junk packet size
	S1   int    // padding bytes prepended to handshake init
	S2   int    // padding bytes prepended to handshake response
	S3   int    // padding bytes prepended to cookie reply (v2, default 0)
	S4   int    // padding bytes prepended to transport data (v2, default 0)
	H1   HRange // replacement type for handshake init
	H2   HRange // replacement type for handshake response
	H3   HRange // replacement type for cookie reply
	H4   HRange // replacement type for transport data

	CPS [5]*CPSTemplate // I1-I5 CPS templates (v2, nil = not configured)

	ServerPub     [32]byte // AWG server public key (for outbound MAC1 recomputation)
	ClientPub     [32]byte // WG client public key (for inbound MAC1 recomputation)
	mac1keyServer [32]byte // precomputed BLAKE2s-256("mac1----" || ServerPub)
	mac1keyClient [32]byte // precomputed BLAKE2s-256("mac1----" || ClientPub)

	h4Fixed     uint32 // H4.Min for point-range configs (avoids Pick())
	h4NoOp      bool   // true when H4={4,4} and S4==0 (identity transform, zero work)
	initTotal   int    // S1 + WgHandshakeInitSize (expected total size of padded init)
	respTotal   int    // S2 + WgHandshakeResponseSize (expected total size of padded response)
	cookieTotal int    // S3 + WgCookieReplySize (expected total size of padded cookie)

	Timeout  int // inactivity timeout seconds, default 180
	LogLevel int // 0=none, 1=error, 2=info
}

// Log levels.
const (
	LevelNone  = 0
	LevelError = 1
	LevelInfo  = 2
	LevelDebug = 3
)

// ComputeMAC1Keys derives MAC1 keys from ServerPub and ClientPub.
func (c *Config) ComputeMAC1Keys() {
	c.mac1keyServer = computeMAC1Key(c.ServerPub)
	c.mac1keyClient = computeMAC1Key(c.ClientPub)
}

// ComputeFastPath precomputes fast-path flags for hot-path optimizations.
// Must be called after setting H4, S4 and all S1-S4 values.
func (c *Config) ComputeFastPath() {
	c.h4Fixed = c.H4.Min
	c.h4NoOp = c.H4.Min == wgTransportData && c.H4.Max == wgTransportData && c.S4 == 0
	c.initTotal = c.S1 + WgHandshakeInitSize
	c.respTotal = c.S2 + WgHandshakeResponseSize
	c.cookieTotal = c.S3 + WgCookieReplySize
}

// TransformOutbound transforms an outbound WireGuard packet into AmneziaWG format.
// It returns the transformed packet and whether junk packets should be sent before it.
// buf is the full buffer, dataOff is the offset where packet data starts, n is the data length.
// For zero-alloc S4 padding, the caller should allocate buf with S4 extra bytes at the start
// and read data into buf[S4:]. When S4>0 and dataOff>=S4, padding uses the headroom in buf.
func TransformOutbound(buf []byte, dataOff, n int, cfg *Config) (out []byte, sendJunk bool) {
	if n < 4 {
		return buf[dataOff : dataOff+n], false
	}

	data := buf[dataOff : dataOff+n]
	msgType := binary.LittleEndian.Uint32(data[:4])

	switch {
	case msgType == wgHandshakeInit && n == WgHandshakeInitSize:
		// Replace type and recompute MAC1.
		binary.LittleEndian.PutUint32(data[:4], cfg.H1.Pick())
		if cfg.ServerPub != ([32]byte{}) {
			recomputeMAC1(data, cfg.mac1keyServer)
		}
		if cfg.S1 > 0 {
			out = make([]byte, cfg.S1+n)
			randFill(out[:cfg.S1])
			copy(out[cfg.S1:], data)
		} else {
			out = data
		}
		return out, cfg.Jc > 0

	case msgType == wgHandshakeResponse && n == WgHandshakeResponseSize:
		// Replace type and prepend S2 padding bytes.
		binary.LittleEndian.PutUint32(data[:4], cfg.H2.Pick())
		if cfg.S2 > 0 {
			out = make([]byte, cfg.S2+n)
			randFill(out[:cfg.S2])
			copy(out[cfg.S2:], data)
		} else {
			out = data
		}
		return out, false

	case msgType == wgCookieReply && n == WgCookieReplySize:
		binary.LittleEndian.PutUint32(data[:4], cfg.H3.Pick())
		if cfg.S3 > 0 {
			out = make([]byte, cfg.S3+n)
			randFill(out[:cfg.S3])
			copy(out[cfg.S3:], data)
		} else {
			out = data
		}
		return out, false

	case msgType == wgTransportData && n >= WgTransportMinSize:
		if cfg.h4NoOp {
			return data, false
		}
		if cfg.H4.Min == cfg.H4.Max {
			binary.LittleEndian.PutUint32(data[:4], cfg.h4Fixed)
		} else {
			binary.LittleEndian.PutUint32(data[:4], cfg.H4.Pick())
		}
		if cfg.S4 > 0 && dataOff >= cfg.S4 {
			// Zero-alloc: use headroom before dataOff.
			randFill(buf[dataOff-cfg.S4 : dataOff])
			return buf[dataOff-cfg.S4 : dataOff+n], false
		} else if cfg.S4 > 0 {
			out = make([]byte, cfg.S4+n)
			randFill(out[:cfg.S4])
			copy(out[cfg.S4:], data)
			return out, false
		}
		return data, false

	default:
		// Unknown packet, pass through unchanged.
		return data, false
	}
}

// TransformInbound transforms an inbound AmneziaWG packet back to standard WireGuard format.
// Returns the transformed packet and whether it is valid (junk packets return valid=false).
// Uses size-based dispatch: handshake packets have fixed total sizes and are checked first,
// transport data is checked last to avoid false positives from random padding bytes.
func TransformInbound(buf []byte, n int, cfg *Config) (out []byte, valid bool) {
	if n < 4 {
		return nil, false
	}

	// Fast path: identity transform (H4={4,4}, S4=0) — no work needed.
	if cfg.h4NoOp {
		if binary.LittleEndian.Uint32(buf[:4]) == wgTransportData && n >= WgTransportMinSize {
			return buf[:n], true
		}
	}

	// Size-based dispatch: handshake packets have fixed total sizes (S+payload).
	// Check handshake types FIRST, transport data LAST to avoid priority inversion
	// where random padding bytes fall into a wide H4 range.

	if n == cfg.initTotal {
		h := binary.LittleEndian.Uint32(buf[cfg.S1 : cfg.S1+4])
		if cfg.H1.Contains(h) {
			binary.LittleEndian.PutUint32(buf[cfg.S1:cfg.S1+4], wgHandshakeInit)
			return buf[cfg.S1:n], true
		}
	}

	if n == cfg.respTotal {
		h := binary.LittleEndian.Uint32(buf[cfg.S2 : cfg.S2+4])
		if cfg.H2.Contains(h) {
			binary.LittleEndian.PutUint32(buf[cfg.S2:cfg.S2+4], wgHandshakeResponse)
			if cfg.ClientPub != ([32]byte{}) {
				recomputeMAC1Response(buf[cfg.S2:cfg.S2+WgHandshakeResponseSize], cfg.mac1keyClient)
			}
			return buf[cfg.S2:n], true
		}
	}

	if n == cfg.cookieTotal {
		h := binary.LittleEndian.Uint32(buf[cfg.S3 : cfg.S3+4])
		if cfg.H3.Contains(h) {
			binary.LittleEndian.PutUint32(buf[cfg.S3:cfg.S3+4], wgCookieReply)
			return buf[cfg.S3:n], true
		}
	}

	// Transport data: variable size, checked last to avoid priority inversion.
	if n >= cfg.S4+WgTransportMinSize {
		h := binary.LittleEndian.Uint32(buf[cfg.S4 : cfg.S4+4])
		if cfg.H4.Contains(h) {
			binary.LittleEndian.PutUint32(buf[cfg.S4:cfg.S4+4], wgTransportData)
			return buf[cfg.S4:n], true
		}
	}

	return nil, false
}

// GenerateJunkPackets creates Jc junk packets with random sizes in [Jmin, Jmax].
// Uses 2 allocations instead of Jc+1: one shared data buffer + one slice header.
func GenerateJunkPackets(cfg *Config) [][]byte {
	if cfg.Jc <= 0 || cfg.Jmax <= 0 {
		return nil
	}

	jmin := cfg.Jmin
	if jmin <= 0 {
		jmin = 1
	}
	jmax := cfg.Jmax
	if jmax < jmin {
		jmax = jmin
	}

	// Single data buffer for all junk (upper bound: Jc * Jmax).
	data := make([]byte, cfg.Jc*jmax)
	randFill(data)

	packets := make([][]byte, cfg.Jc)
	off := 0
	for i := range packets {
		size := jmin
		if jmax > jmin {
			size = jmin + rand.IntN(jmax-jmin+1)
		}
		packets[i] = data[off : off+size]
		off += size
	}
	return packets
}
