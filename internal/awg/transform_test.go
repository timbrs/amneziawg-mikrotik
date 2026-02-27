package awg

import (
	"encoding/binary"
	"testing"
)

func testConfig() *Config {
	cfg := &Config{
		Jc:   3,
		Jmin: 30,
		Jmax: 500,
		S1:   20,
		S2:   20,
		H1:   HRange{Min: 1234567890, Max: 1234567890},
		H2:   HRange{Min: 1234567891, Max: 1234567891},
		H3:   HRange{Min: 1234567892, Max: 1234567892},
		H4:   HRange{Min: 1234567893, Max: 1234567893},
	}
	cfg.ComputeFastPath()
	return cfg
}

func makePacket(msgType uint32, size int) []byte {
	buf := make([]byte, size)
	binary.LittleEndian.PutUint32(buf[:4], msgType)
	// Fill rest with deterministic data.
	for i := 4; i < size; i++ {
		buf[i] = byte(i)
	}
	return buf
}

func TestTransformOutboundHandshakeInit(t *testing.T) {
	cfg := testConfig()
	original := makePacket(wgHandshakeInit, WgHandshakeInitSize)
	payload := make([]byte, WgHandshakeInitSize)
	copy(payload, original)

	out, sendJunk := TransformOutbound(payload, 0, WgHandshakeInitSize, cfg)

	if !sendJunk {
		t.Fatal("expected sendJunk=true for handshake init")
	}
	if len(out) != cfg.S1+WgHandshakeInitSize {
		t.Fatalf("expected len %d, got %d", cfg.S1+WgHandshakeInitSize, len(out))
	}
	// Check type at S1 offset.
	gotType := binary.LittleEndian.Uint32(out[cfg.S1 : cfg.S1+4])
	if !cfg.H1.Contains(gotType) {
		t.Fatalf("expected type in H1 range [%d,%d], got %d", cfg.H1.Min, cfg.H1.Max, gotType)
	}
	// Check payload preserved after type.
	for i := 4; i < WgHandshakeInitSize; i++ {
		if out[cfg.S1+i] != original[i] {
			t.Fatalf("payload byte %d mismatch: expected %d, got %d", i, original[i], out[cfg.S1+i])
		}
	}
}

func TestTransformOutboundHandshakeResponse(t *testing.T) {
	cfg := testConfig()
	original := makePacket(wgHandshakeResponse, WgHandshakeResponseSize)
	payload := make([]byte, WgHandshakeResponseSize)
	copy(payload, original)

	out, sendJunk := TransformOutbound(payload, 0, WgHandshakeResponseSize, cfg)

	if sendJunk {
		t.Fatal("expected sendJunk=false for handshake response")
	}
	if len(out) != cfg.S2+WgHandshakeResponseSize {
		t.Fatalf("expected len %d, got %d", cfg.S2+WgHandshakeResponseSize, len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[cfg.S2 : cfg.S2+4])
	if !cfg.H2.Contains(gotType) {
		t.Fatalf("expected type in H2 range [%d,%d], got %d", cfg.H2.Min, cfg.H2.Max, gotType)
	}
}

func TestTransformOutboundCookieReply(t *testing.T) {
	cfg := testConfig()
	payload := makePacket(wgCookieReply, WgCookieReplySize)

	out, sendJunk := TransformOutbound(payload, 0, WgCookieReplySize, cfg)

	if sendJunk {
		t.Fatal("expected sendJunk=false for cookie reply")
	}
	if len(out) != WgCookieReplySize {
		t.Fatalf("expected len %d, got %d", WgCookieReplySize, len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if !cfg.H3.Contains(gotType) {
		t.Fatalf("expected type in H3 range [%d,%d], got %d", cfg.H3.Min, cfg.H3.Max, gotType)
	}
}

func TestTransformOutboundTransportData(t *testing.T) {
	cfg := testConfig()
	payload := makePacket(wgTransportData, 100)

	out, sendJunk := TransformOutbound(payload, 0, 100, cfg)

	if sendJunk {
		t.Fatal("expected sendJunk=false for transport data")
	}
	if len(out) != 100 {
		t.Fatalf("expected len 100, got %d", len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if !cfg.H4.Contains(gotType) {
		t.Fatalf("expected type in H4 range [%d,%d], got %d", cfg.H4.Min, cfg.H4.Max, gotType)
	}
}

func TestTransformInboundHandshakeInit(t *testing.T) {
	cfg := testConfig()
	// Build an AWG handshake init: S1 random bytes + H1 type + payload.
	inner := makePacket(cfg.H1.Min, WgHandshakeInitSize)
	buf := make([]byte, cfg.S1+WgHandshakeInitSize)
	copy(buf[cfg.S1:], inner)

	out, valid := TransformInbound(buf, len(buf), cfg)
	if !valid {
		t.Fatal("expected valid=true")
	}
	if len(out) != WgHandshakeInitSize {
		t.Fatalf("expected len %d, got %d", WgHandshakeInitSize, len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if gotType != wgHandshakeInit {
		t.Fatalf("expected type %d, got %d", wgHandshakeInit, gotType)
	}
}

func TestTransformInboundHandshakeResponse(t *testing.T) {
	cfg := testConfig()
	inner := makePacket(cfg.H2.Min, WgHandshakeResponseSize)
	buf := make([]byte, cfg.S2+WgHandshakeResponseSize)
	copy(buf[cfg.S2:], inner)

	out, valid := TransformInbound(buf, len(buf), cfg)
	if !valid {
		t.Fatal("expected valid=true")
	}
	if len(out) != WgHandshakeResponseSize {
		t.Fatalf("expected len %d, got %d", WgHandshakeResponseSize, len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if gotType != wgHandshakeResponse {
		t.Fatalf("expected type %d, got %d", wgHandshakeResponse, gotType)
	}
}

func TestTransformInboundCookieReply(t *testing.T) {
	cfg := testConfig()
	buf := makePacket(cfg.H3.Min, WgCookieReplySize)

	out, valid := TransformInbound(buf, len(buf), cfg)
	if !valid {
		t.Fatal("expected valid=true")
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if gotType != wgCookieReply {
		t.Fatalf("expected type %d, got %d", wgCookieReply, gotType)
	}
}

func TestTransformInboundTransportData(t *testing.T) {
	cfg := testConfig()
	buf := makePacket(cfg.H4.Min, 100)

	out, valid := TransformInbound(buf, len(buf), cfg)
	if !valid {
		t.Fatal("expected valid=true")
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if gotType != wgTransportData {
		t.Fatalf("expected type %d, got %d", wgTransportData, gotType)
	}
}

func TestRoundtripHandshakeInit(t *testing.T) {
	cfg := testConfig()
	original := makePacket(wgHandshakeInit, WgHandshakeInitSize)
	saved := make([]byte, WgHandshakeInitSize)
	copy(saved, original)

	out, _ := TransformOutbound(original, 0, WgHandshakeInitSize, cfg)
	result, valid := TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("roundtrip: inbound returned invalid")
	}
	if len(result) != WgHandshakeInitSize {
		t.Fatalf("roundtrip: expected len %d, got %d", WgHandshakeInitSize, len(result))
	}
	// Type should be restored.
	gotType := binary.LittleEndian.Uint32(result[:4])
	if gotType != wgHandshakeInit {
		t.Fatalf("roundtrip: expected type %d, got %d", wgHandshakeInit, gotType)
	}
	// Payload after type should be preserved.
	for i := 4; i < WgHandshakeInitSize; i++ {
		if result[i] != saved[i] {
			t.Fatalf("roundtrip: byte %d mismatch", i)
		}
	}
}

func TestRoundtripHandshakeResponse(t *testing.T) {
	cfg := testConfig()
	original := makePacket(wgHandshakeResponse, WgHandshakeResponseSize)
	saved := make([]byte, WgHandshakeResponseSize)
	copy(saved, original)

	out, _ := TransformOutbound(original, 0, WgHandshakeResponseSize, cfg)
	result, valid := TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("roundtrip: inbound returned invalid")
	}
	gotType := binary.LittleEndian.Uint32(result[:4])
	if gotType != wgHandshakeResponse {
		t.Fatalf("roundtrip: expected type %d, got %d", wgHandshakeResponse, gotType)
	}
	for i := 4; i < WgHandshakeResponseSize; i++ {
		if result[i] != saved[i] {
			t.Fatalf("roundtrip: byte %d mismatch", i)
		}
	}
}

func TestRoundtripCookieReply(t *testing.T) {
	cfg := testConfig()
	original := makePacket(wgCookieReply, WgCookieReplySize)
	saved := make([]byte, WgCookieReplySize)
	copy(saved, original)

	out, _ := TransformOutbound(original, 0, WgCookieReplySize, cfg)
	result, valid := TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("roundtrip: inbound returned invalid")
	}
	gotType := binary.LittleEndian.Uint32(result[:4])
	if gotType != wgCookieReply {
		t.Fatalf("roundtrip: expected type %d, got %d", wgCookieReply, gotType)
	}
}

func TestRoundtripTransportData(t *testing.T) {
	cfg := testConfig()
	original := makePacket(wgTransportData, 200)
	saved := make([]byte, 200)
	copy(saved, original)

	out, _ := TransformOutbound(original, 0, 200, cfg)
	result, valid := TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("roundtrip: inbound returned invalid")
	}
	gotType := binary.LittleEndian.Uint32(result[:4])
	if gotType != wgTransportData {
		t.Fatalf("roundtrip: expected type %d, got %d", wgTransportData, gotType)
	}
	for i := 4; i < 200; i++ {
		if result[i] != saved[i] {
			t.Fatalf("roundtrip: byte %d mismatch", i)
		}
	}
}

func TestGenerateJunkPackets(t *testing.T) {
	cfg := testConfig()
	packets := GenerateJunkPackets(cfg)

	if len(packets) != cfg.Jc {
		t.Fatalf("expected %d junk packets, got %d", cfg.Jc, len(packets))
	}
	for i, pkt := range packets {
		if len(pkt) < cfg.Jmin || len(pkt) > cfg.Jmax {
			t.Fatalf("junk packet %d: size %d not in [%d, %d]", i, len(pkt), cfg.Jmin, cfg.Jmax)
		}
	}
}

func TestGenerateJunkPacketsZeroJc(t *testing.T) {
	cfg := testConfig()
	cfg.Jc = 0
	packets := GenerateJunkPackets(cfg)
	if packets != nil {
		t.Fatalf("expected nil for Jc=0, got %d packets", len(packets))
	}
}

func TestInboundDropsUnknown(t *testing.T) {
	cfg := testConfig()
	// Packet with unknown type.
	buf := makePacket(99999, 100)
	_, valid := TransformInbound(buf, len(buf), cfg)
	if valid {
		t.Fatal("expected valid=false for unknown packet type")
	}
}

func TestInboundDropsTooShort(t *testing.T) {
	cfg := testConfig()
	buf := []byte{1, 2, 3}
	_, valid := TransformInbound(buf, len(buf), cfg)
	if valid {
		t.Fatal("expected valid=false for too-short packet")
	}
}

func TestNoPaddingS1Zero(t *testing.T) {
	cfg := testConfig()
	cfg.S1 = 0
	cfg.ComputeFastPath()
	original := makePacket(wgHandshakeInit, WgHandshakeInitSize)
	saved := make([]byte, WgHandshakeInitSize)
	copy(saved, original)

	out, sendJunk := TransformOutbound(original, 0, WgHandshakeInitSize, cfg)
	if !sendJunk {
		t.Fatal("expected sendJunk=true even with S1=0")
	}
	if len(out) != WgHandshakeInitSize {
		t.Fatalf("expected len %d with S1=0, got %d", WgHandshakeInitSize, len(out))
	}

	// Roundtrip.
	result, valid := TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("roundtrip with S1=0: invalid")
	}
	gotType := binary.LittleEndian.Uint32(result[:4])
	if gotType != wgHandshakeInit {
		t.Fatalf("roundtrip with S1=0: expected type %d, got %d", wgHandshakeInit, gotType)
	}
}

func TestNoPaddingS2Zero(t *testing.T) {
	cfg := testConfig()
	cfg.S2 = 0
	cfg.ComputeFastPath()
	original := makePacket(wgHandshakeResponse, WgHandshakeResponseSize)
	saved := make([]byte, WgHandshakeResponseSize)
	copy(saved, original)

	out, _ := TransformOutbound(original, 0, WgHandshakeResponseSize, cfg)
	if len(out) != WgHandshakeResponseSize {
		t.Fatalf("expected len %d with S2=0, got %d", WgHandshakeResponseSize, len(out))
	}

	result, valid := TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("roundtrip with S2=0: invalid")
	}
	gotType := binary.LittleEndian.Uint32(result[:4])
	if gotType != wgHandshakeResponse {
		t.Fatalf("roundtrip with S2=0: expected type %d, got %d", wgHandshakeResponse, gotType)
	}
}

func TestOutboundTooShort(t *testing.T) {
	cfg := testConfig()
	buf := []byte{1, 2}
	out, sendJunk := TransformOutbound(buf, 0, 2, cfg)
	if sendJunk {
		t.Fatal("expected sendJunk=false for too-short packet")
	}
	if len(out) != 2 {
		t.Fatalf("expected passthrough for too-short packet")
	}
}

// ============================================================
// v2-specific tests
// ============================================================

func TestHRangePick(t *testing.T) {
	// Point range: always returns Min.
	r := HRange{Min: 42, Max: 42}
	for i := 0; i < 100; i++ {
		if v := r.Pick(); v != 42 {
			t.Fatalf("point range Pick: expected 42, got %d", v)
		}
	}
	// Range: should return values in [100, 200].
	r2 := HRange{Min: 100, Max: 200}
	for i := 0; i < 100; i++ {
		v := r2.Pick()
		if v < 100 || v > 200 {
			t.Fatalf("range Pick: %d not in [100, 200]", v)
		}
	}
}

func TestHRangeContains(t *testing.T) {
	r := HRange{Min: 10, Max: 20}
	if !r.Contains(10) {
		t.Fatal("expected Contains(10)=true")
	}
	if !r.Contains(15) {
		t.Fatal("expected Contains(15)=true")
	}
	if !r.Contains(20) {
		t.Fatal("expected Contains(20)=true")
	}
	if r.Contains(9) {
		t.Fatal("expected Contains(9)=false")
	}
	if r.Contains(21) {
		t.Fatal("expected Contains(21)=false")
	}
}

func TestOutboundCookieWithS3(t *testing.T) {
	cfg := testConfig()
	cfg.S3 = 49
	cfg.ComputeFastPath()
	payload := makePacket(wgCookieReply, WgCookieReplySize)

	out, sendJunk := TransformOutbound(payload, 0, WgCookieReplySize, cfg)
	if sendJunk {
		t.Fatal("expected sendJunk=false for cookie reply")
	}
	if len(out) != cfg.S3+WgCookieReplySize {
		t.Fatalf("expected len %d, got %d", cfg.S3+WgCookieReplySize, len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[cfg.S3 : cfg.S3+4])
	if !cfg.H3.Contains(gotType) {
		t.Fatalf("expected H3 type, got %d", gotType)
	}
}

func TestOutboundTransportWithS4(t *testing.T) {
	cfg := testConfig()
	cfg.S4 = 17
	cfg.ComputeFastPath()
	payload := makePacket(wgTransportData, 100)

	out, sendJunk := TransformOutbound(payload, 0, 100, cfg)
	if sendJunk {
		t.Fatal("expected sendJunk=false for transport data")
	}
	if len(out) != cfg.S4+100 {
		t.Fatalf("expected len %d, got %d", cfg.S4+100, len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[cfg.S4 : cfg.S4+4])
	if !cfg.H4.Contains(gotType) {
		t.Fatalf("expected H4 type, got %d", gotType)
	}
}

func TestInboundScanningWithS3(t *testing.T) {
	cfg := testConfig()
	cfg.S3 = 49
	cfg.ComputeFastPath()
	// Build AWG cookie reply with S3 padding.
	inner := makePacket(cfg.H3.Min, WgCookieReplySize)
	buf := make([]byte, cfg.S3+WgCookieReplySize)
	randFill(buf[:cfg.S3])
	copy(buf[cfg.S3:], inner)

	out, valid := TransformInbound(buf, len(buf), cfg)
	if !valid {
		t.Fatal("expected valid=true for cookie with S3 padding")
	}
	if len(out) != WgCookieReplySize {
		t.Fatalf("expected len %d, got %d", WgCookieReplySize, len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if gotType != wgCookieReply {
		t.Fatalf("expected type %d, got %d", wgCookieReply, gotType)
	}
}

func TestInboundScanningWithS4(t *testing.T) {
	cfg := testConfig()
	cfg.S4 = 17
	cfg.ComputeFastPath()
	// Build AWG transport with S4 padding.
	inner := makePacket(cfg.H4.Min, 100)
	buf := make([]byte, cfg.S4+100)
	randFill(buf[:cfg.S4])
	copy(buf[cfg.S4:], inner)

	out, valid := TransformInbound(buf, len(buf), cfg)
	if !valid {
		t.Fatal("expected valid=true for transport with S4 padding")
	}
	if len(out) != 100 {
		t.Fatalf("expected len 100, got %d", len(out))
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if gotType != wgTransportData {
		t.Fatalf("expected type %d, got %d", wgTransportData, gotType)
	}
}

func TestInboundHRange(t *testing.T) {
	cfg := testConfig()
	cfg.H4 = HRange{Min: 1000, Max: 2000}
	cfg.ComputeFastPath()
	// Use a value inside the range.
	buf := makePacket(1500, 100)

	out, valid := TransformInbound(buf, len(buf), cfg)
	if !valid {
		t.Fatal("expected valid=true for value in H4 range")
	}
	gotType := binary.LittleEndian.Uint32(out[:4])
	if gotType != wgTransportData {
		t.Fatalf("expected type %d, got %d", wgTransportData, gotType)
	}
}

func TestInboundHRangeReject(t *testing.T) {
	cfg := testConfig()
	cfg.H4 = HRange{Min: 1000, Max: 2000}
	cfg.ComputeFastPath()
	// Use a value outside the range.
	buf := makePacket(999, 100)

	_, valid := TransformInbound(buf, len(buf), cfg)
	if valid {
		t.Fatal("expected valid=false for value outside H4 range")
	}
}

func TestRoundtripV2(t *testing.T) {
	cfg := testConfig()
	cfg.S3 = 49
	cfg.S4 = 17
	cfg.H1 = HRange{Min: 100000, Max: 200000}
	cfg.H2 = HRange{Min: 300000, Max: 400000}
	cfg.H3 = HRange{Min: 500000, Max: 600000}
	cfg.H4 = HRange{Min: 700000, Max: 800000}
	cfg.ComputeFastPath()

	// Roundtrip handshake init.
	initPkt := makePacket(wgHandshakeInit, WgHandshakeInitSize)
	savedInit := make([]byte, WgHandshakeInitSize)
	copy(savedInit, initPkt)

	out, _ := TransformOutbound(initPkt, 0, WgHandshakeInitSize, cfg)
	result, valid := TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("v2 roundtrip init: invalid")
	}
	if binary.LittleEndian.Uint32(result[:4]) != wgHandshakeInit {
		t.Fatal("v2 roundtrip init: type not restored")
	}

	// Roundtrip cookie reply with S3.
	cookiePkt := makePacket(wgCookieReply, WgCookieReplySize)
	out, _ = TransformOutbound(cookiePkt, 0, WgCookieReplySize, cfg)
	if len(out) != cfg.S3+WgCookieReplySize {
		t.Fatalf("v2 cookie outbound: expected %d, got %d", cfg.S3+WgCookieReplySize, len(out))
	}
	result, valid = TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("v2 roundtrip cookie: invalid")
	}
	if binary.LittleEndian.Uint32(result[:4]) != wgCookieReply {
		t.Fatal("v2 roundtrip cookie: type not restored")
	}

	// Roundtrip transport with S4.
	transportPkt := makePacket(wgTransportData, 200)
	savedTransport := make([]byte, 200)
	copy(savedTransport, transportPkt)

	out, _ = TransformOutbound(transportPkt, 0, 200, cfg)
	if len(out) != cfg.S4+200 {
		t.Fatalf("v2 transport outbound: expected %d, got %d", cfg.S4+200, len(out))
	}
	result, valid = TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("v2 roundtrip transport: invalid")
	}
	if binary.LittleEndian.Uint32(result[:4]) != wgTransportData {
		t.Fatal("v2 roundtrip transport: type not restored")
	}
	for i := 4; i < 200; i++ {
		if result[i] != savedTransport[i] {
			t.Fatalf("v2 roundtrip transport: byte %d mismatch", i)
		}
	}
}

func TestV1Backward(t *testing.T) {
	// Verify v1 config (point ranges, S3=S4=0) still works identically.
	cfg := &Config{
		Jc:   2,
		Jmin: 10,
		Jmax: 50,
		S1:   46,
		S2:   122,
		S3:   0,
		S4:   0,
		H1:   HRange{Min: 1033089720, Max: 1033089720},
		H2:   HRange{Min: 1336452505, Max: 1336452505},
		H3:   HRange{Min: 1858775673, Max: 1858775673},
		H4:   HRange{Min: 332219739, Max: 332219739},
	}
	cfg.ComputeFastPath()

	// Handshake init roundtrip.
	initPkt := makePacket(wgHandshakeInit, WgHandshakeInitSize)
	out, sendJunk := TransformOutbound(initPkt, 0, WgHandshakeInitSize, cfg)
	if !sendJunk {
		t.Fatal("v1 backward: expected sendJunk=true")
	}
	if len(out) != cfg.S1+WgHandshakeInitSize {
		t.Fatalf("v1 backward: expected len %d, got %d", cfg.S1+WgHandshakeInitSize, len(out))
	}
	result, valid := TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("v1 backward: inbound invalid")
	}
	if binary.LittleEndian.Uint32(result[:4]) != wgHandshakeInit {
		t.Fatal("v1 backward: type not restored")
	}

	// Transport data: no padding with S4=0.
	transportPkt := makePacket(wgTransportData, 100)
	out, _ = TransformOutbound(transportPkt, 0, 100, cfg)
	if len(out) != 100 {
		t.Fatalf("v1 backward: transport expected 100, got %d", len(out))
	}
	result, valid = TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("v1 backward: transport inbound invalid")
	}
	if binary.LittleEndian.Uint32(result[:4]) != wgTransportData {
		t.Fatal("v1 backward: transport type not restored")
	}

	// Cookie: no padding with S3=0.
	cookiePkt := makePacket(wgCookieReply, WgCookieReplySize)
	out, _ = TransformOutbound(cookiePkt, 0, WgCookieReplySize, cfg)
	if len(out) != WgCookieReplySize {
		t.Fatalf("v1 backward: cookie expected %d, got %d", WgCookieReplySize, len(out))
	}
	result, valid = TransformInbound(out, len(out), cfg)
	if !valid {
		t.Fatal("v1 backward: cookie inbound invalid")
	}
	if binary.LittleEndian.Uint32(result[:4]) != wgCookieReply {
		t.Fatal("v1 backward: cookie type not restored")
	}
}

func BenchmarkTransformOutboundTransport(b *testing.B) {
	cfg := testConfig()
	buf := make([]byte, 1200)
	binary.LittleEndian.PutUint32(buf[:4], wgTransportData)
	for i := 4; i < 1200; i++ {
		buf[i] = byte(i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint32(buf[:4], wgTransportData)
		TransformOutbound(buf, 0, 1200, cfg)
	}
}

func BenchmarkTransformOutboundTransportS4(b *testing.B) {
	cfg := testConfig()
	cfg.S4 = 17
	cfg.ComputeFastPath()
	prefix := cfg.S4
	buf := make([]byte, prefix+1200)
	binary.LittleEndian.PutUint32(buf[prefix:prefix+4], wgTransportData)
	for i := 4; i < 1200; i++ {
		buf[prefix+i] = byte(i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint32(buf[prefix:prefix+4], wgTransportData)
		TransformOutbound(buf, prefix, 1200, cfg)
	}
}

func BenchmarkTransformInboundTransport(b *testing.B) {
	cfg := testConfig()
	buf := make([]byte, 1200)
	binary.LittleEndian.PutUint32(buf[:4], cfg.H4.Min)
	for i := 4; i < 1200; i++ {
		buf[i] = byte(i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint32(buf[:4], cfg.H4.Min)
		TransformInbound(buf, 1200, cfg)
	}
}

func TestInboundV2RangeFalsePositive(t *testing.T) {
	// Regression test: wide H4 range must NOT cause handshake packets
	// to be misidentified as transport data due to random padding bytes
	// falling into the H4 range at offset 0.
	cfg := &Config{
		Jc:   2,
		Jmin: 10,
		Jmax: 50,
		S1:   46,
		S2:   62,
		S3:   30,
		S4:   17,
		H1:   HRange{Min: 100000, Max: 200000},
		H2:   HRange{Min: 300000, Max: 400000},
		H3:   HRange{Min: 500000, Max: 600000},
		// Wide H4 range: covers ~25% of uint32 space.
		H4: HRange{Min: 0, Max: 1073741823},
	}
	cfg.ComputeFastPath()

	// Helper: poison first 4 bytes of padding with a value inside H4 range.
	poisonPadding := func(buf []byte) {
		binary.LittleEndian.PutUint32(buf[:4], cfg.H4.Min+12345)
	}

	// 1. Padded handshake response: S2+92 bytes, padding poisoned with H4 value.
	t.Run("handshake_response", func(t *testing.T) {
		inner := makePacket(cfg.H2.Min, WgHandshakeResponseSize)
		buf := make([]byte, cfg.S2+WgHandshakeResponseSize)
		poisonPadding(buf)
		copy(buf[cfg.S2:], inner)

		out, valid := TransformInbound(buf, len(buf), cfg)
		if !valid {
			t.Fatal("expected valid=true for handshake response")
		}
		if len(out) != WgHandshakeResponseSize {
			t.Fatalf("expected len %d, got %d", WgHandshakeResponseSize, len(out))
		}
		gotType := binary.LittleEndian.Uint32(out[:4])
		if gotType != wgHandshakeResponse {
			t.Fatalf("expected type %d (handshake response), got %d", wgHandshakeResponse, gotType)
		}
	})

	// 2. Padded handshake init: S1+148 bytes, padding poisoned.
	t.Run("handshake_init", func(t *testing.T) {
		inner := makePacket(cfg.H1.Min, WgHandshakeInitSize)
		buf := make([]byte, cfg.S1+WgHandshakeInitSize)
		poisonPadding(buf)
		copy(buf[cfg.S1:], inner)

		out, valid := TransformInbound(buf, len(buf), cfg)
		if !valid {
			t.Fatal("expected valid=true for handshake init")
		}
		if len(out) != WgHandshakeInitSize {
			t.Fatalf("expected len %d, got %d", WgHandshakeInitSize, len(out))
		}
		gotType := binary.LittleEndian.Uint32(out[:4])
		if gotType != wgHandshakeInit {
			t.Fatalf("expected type %d (handshake init), got %d", wgHandshakeInit, gotType)
		}
	})

	// 3. Padded cookie reply: S3+64 bytes, padding poisoned.
	t.Run("cookie_reply", func(t *testing.T) {
		inner := makePacket(cfg.H3.Min, WgCookieReplySize)
		buf := make([]byte, cfg.S3+WgCookieReplySize)
		poisonPadding(buf)
		copy(buf[cfg.S3:], inner)

		out, valid := TransformInbound(buf, len(buf), cfg)
		if !valid {
			t.Fatal("expected valid=true for cookie reply")
		}
		if len(out) != WgCookieReplySize {
			t.Fatalf("expected len %d, got %d", WgCookieReplySize, len(out))
		}
		gotType := binary.LittleEndian.Uint32(out[:4])
		if gotType != wgCookieReply {
			t.Fatalf("expected type %d (cookie reply), got %d", wgCookieReply, gotType)
		}
	})

	// 4. Padded transport data: S4+payload bytes, H4 type at offset S4.
	t.Run("transport_data", func(t *testing.T) {
		payloadSize := 200
		inner := makePacket(cfg.H4.Min+999, payloadSize)
		buf := make([]byte, cfg.S4+payloadSize)
		randFill(buf[:cfg.S4])
		copy(buf[cfg.S4:], inner)

		out, valid := TransformInbound(buf, len(buf), cfg)
		if !valid {
			t.Fatal("expected valid=true for transport data")
		}
		if len(out) != payloadSize {
			t.Fatalf("expected len %d, got %d", payloadSize, len(out))
		}
		gotType := binary.LittleEndian.Uint32(out[:4])
		if gotType != wgTransportData {
			t.Fatalf("expected type %d (transport data), got %d", wgTransportData, gotType)
		}
	})

	// 5. Junk packet: size doesn't match any handshake total or transport minimum.
	t.Run("junk_packet", func(t *testing.T) {
		junkSize := 17
		buf := make([]byte, junkSize)
		randFill(buf)
		_, valid := TransformInbound(buf, len(buf), cfg)
		if valid {
			t.Fatal("expected valid=false for junk packet")
		}
	})
}

func BenchmarkGenerateJunkPackets(b *testing.B) {
	cfg := testConfig()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		GenerateJunkPackets(cfg)
	}
}
