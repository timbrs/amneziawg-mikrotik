package awg

import (
	"encoding/binary"
	"testing"
)

func TestParseCPSStaticBytes(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<b 0x0844>")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(tmpl.segments))
	}
	seg := tmpl.segments[0]
	if seg.kind != cpsStatic {
		t.Fatalf("expected kind 'b', got %c", seg.kind)
	}
	if len(seg.data) != 2 || seg.data[0] != 0x08 || seg.data[1] != 0x44 {
		t.Fatalf("expected [0x08 0x44], got %v", seg.data)
	}
}

func TestParseCPSRandom(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<r 16>")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(tmpl.segments))
	}
	seg := tmpl.segments[0]
	if seg.kind != cpsRandom {
		t.Fatalf("expected kind 'r', got %c", seg.kind)
	}
	if seg.size != 16 {
		t.Fatalf("expected size 16, got %d", seg.size)
	}
}

func TestParseCPSTimestamp(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<t>")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(tmpl.segments))
	}
	if tmpl.segments[0].kind != cpsTimestamp {
		t.Fatalf("expected kind 't', got %c", tmpl.segments[0].kind)
	}
}

func TestParseCPSCounter(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<c>")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(tmpl.segments))
	}
	if tmpl.segments[0].kind != cpsCounter {
		t.Fatalf("expected kind 'c', got %c", tmpl.segments[0].kind)
	}
}

func TestParseCPSRandomChars(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<rc 12>")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(tmpl.segments))
	}
	seg := tmpl.segments[0]
	if seg.kind != cpsRandomChars {
		t.Fatalf("expected kind cpsRandomChars, got %c", seg.kind)
	}
	if seg.size != 12 {
		t.Fatalf("expected size 12, got %d", seg.size)
	}
}

func TestParseCPSRandomDigits(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<rd 8>")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(tmpl.segments))
	}
	seg := tmpl.segments[0]
	if seg.kind != cpsRandomDigits {
		t.Fatalf("expected kind cpsRandomDigits, got %c", seg.kind)
	}
	if seg.size != 8 {
		t.Fatalf("expected size 8, got %d", seg.size)
	}
}

func TestGenerateRandomChars(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<rc 20>")
	if err != nil {
		t.Fatal(err)
	}
	pkt := tmpl.Generate(0)
	if len(pkt) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(pkt))
	}
	for i, b := range pkt {
		if !isAlphanumeric(b) {
			t.Fatalf("byte %d: 0x%x is not alphanumeric", i, b)
		}
	}
}

func TestGenerateRandomDigits(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<rd 10>")
	if err != nil {
		t.Fatal(err)
	}
	pkt := tmpl.Generate(0)
	if len(pkt) != 10 {
		t.Fatalf("expected 10 bytes, got %d", len(pkt))
	}
	for i, b := range pkt {
		if b < '0' || b > '9' {
			t.Fatalf("byte %d: 0x%x is not a digit", i, b)
		}
	}
}

func isAlphanumeric(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func TestParseCPSMixedWithRcRd(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<b 0xDEAD> <rc 8> <t> <rd 4>")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.segments) != 4 {
		t.Fatalf("expected 4 segments, got %d", len(tmpl.segments))
	}
	kinds := []byte{cpsStatic, cpsRandomChars, cpsTimestamp, cpsRandomDigits}
	for i, seg := range tmpl.segments {
		if seg.kind != kinds[i] {
			t.Fatalf("segment %d: expected kind %c, got %c", i, kinds[i], seg.kind)
		}
	}
	pkt := tmpl.Generate(0)
	// 2 (static) + 8 (rc) + 4 (timestamp) + 4 (rd) = 18
	if len(pkt) != 18 {
		t.Fatalf("expected 18 bytes, got %d", len(pkt))
	}
	if pkt[0] != 0xDE || pkt[1] != 0xAD {
		t.Fatalf("static bytes mismatch")
	}
	for i := 2; i < 10; i++ {
		if !isAlphanumeric(pkt[i]) {
			t.Fatalf("rc byte %d: 0x%x is not alphanumeric", i, pkt[i])
		}
	}
	for i := 14; i < 18; i++ {
		if pkt[i] < '0' || pkt[i] > '9' {
			t.Fatalf("rd byte %d: 0x%x is not a digit", i, pkt[i])
		}
	}
}

func TestParseCPSRcRdInvalid(t *testing.T) {
	cases := []string{
		"<rc>",     // no size
		"<rc abc>", // non-numeric
		"<rc 0>",   // zero
		"<rc -1>",  // negative
		"<rd>",     // no size
		"<rd abc>", // non-numeric
		"<rd 0>",   // zero
		"<rd -1>",  // negative
	}
	for _, tc := range cases {
		_, err := ParseCPSTemplate(tc)
		if err == nil {
			t.Fatalf("expected error for %q, got nil", tc)
		}
	}
}

func TestParseCPSMultiSegment(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<b 0xAABB> <r 8> <t> <c>")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.segments) != 4 {
		t.Fatalf("expected 4 segments, got %d", len(tmpl.segments))
	}
	kinds := []byte{cpsStatic, cpsRandom, cpsTimestamp, cpsCounter}
	for i, seg := range tmpl.segments {
		if seg.kind != kinds[i] {
			t.Fatalf("segment %d: expected kind %c, got %c", i, kinds[i], seg.kind)
		}
	}
}

func TestParseCPSEmpty(t *testing.T) {
	_, err := ParseCPSTemplate("")
	if err == nil {
		t.Fatal("expected error for empty template")
	}
}

func TestParseCPSInvalid(t *testing.T) {
	cases := []string{
		"no tags here",
		"<b>",      // no hex data
		"<b 0x>",   // empty hex
		"<b 0xGG>", // invalid hex
		"<b 0x1>",  // odd-length hex
		"<r>",      // no size
		"<r abc>",  // non-numeric size
		"<r -5>",   // negative size
		"<r 0>",    // zero size
		"<x>",      // unknown kind
		"<b 0xFF",  // unclosed tag
	}
	for _, tc := range cases {
		_, err := ParseCPSTemplate(tc)
		if err == nil {
			t.Fatalf("expected error for %q, got nil", tc)
		}
	}
}

func TestGenerateCPS(t *testing.T) {
	tmpl, err := ParseCPSTemplate("<b 0xDEAD> <r 4> <c>")
	if err != nil {
		t.Fatal(err)
	}
	pkt := tmpl.Generate(42)
	// Expected: 2 bytes static + 4 bytes random + 4 bytes counter = 10
	if len(pkt) != 10 {
		t.Fatalf("expected 10 bytes, got %d", len(pkt))
	}
	if pkt[0] != 0xDE || pkt[1] != 0xAD {
		t.Fatalf("static bytes mismatch: %x %x", pkt[0], pkt[1])
	}
	counter := binary.LittleEndian.Uint32(pkt[6:10])
	if counter != 42 {
		t.Fatalf("expected counter 42, got %d", counter)
	}
}

func TestGenerateCPSPackets(t *testing.T) {
	t1, _ := ParseCPSTemplate("<b 0xFF>")
	t3, _ := ParseCPSTemplate("<c>")
	var templates [5]*CPSTemplate
	templates[0] = t1
	templates[2] = t3

	var counter uint32
	packets := GenerateCPSPackets(templates, &counter)

	if len(packets) != 2 {
		t.Fatalf("expected 2 packets (I1 + I3), got %d", len(packets))
	}
	if counter != 2 {
		t.Fatalf("expected counter 2, got %d", counter)
	}
	// First packet: I1 -> counter was 0
	if len(packets[0]) != 1 || packets[0][0] != 0xFF {
		t.Fatalf("I1 packet mismatch")
	}
	// Second packet: I3 -> counter was 1
	c := binary.LittleEndian.Uint32(packets[1])
	if c != 1 {
		t.Fatalf("I3 counter: expected 1, got %d", c)
	}
}

func TestDecodeHex(t *testing.T) {
	cases := []struct {
		input string
		want  []byte
	}{
		{"", nil},
		{"00", []byte{0}},
		{"FF", []byte{0xFF}},
		{"ff", []byte{0xFF}},
		{"0123456789abcdef", []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}},
	}
	for _, tc := range cases {
		got, err := decodeHex(tc.input)
		if err != nil {
			t.Fatalf("decodeHex(%q): %v", tc.input, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("decodeHex(%q): len %d, want %d", tc.input, len(got), len(tc.want))
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("decodeHex(%q): byte %d: %x, want %x", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestDecodeHexErrors(t *testing.T) {
	cases := []string{
		"1",  // odd length
		"GG", // invalid chars
		"0G", // second char invalid
	}
	for _, tc := range cases {
		_, err := decodeHex(tc)
		if err == nil {
			t.Fatalf("decodeHex(%q): expected error", tc)
		}
	}
}
