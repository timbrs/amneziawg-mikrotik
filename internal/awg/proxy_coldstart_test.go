package awg

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestProxyDropsTransportBeforeHandshake verifies that on a cold start (or
// after reconnect), the proxy drops transport data packets until a handshake
// init has been forwarded. This forces MikroTik WG to quickly detect the
// dead peer and initiate a new handshake instead of sending stale transport
// data from a previous session.
func TestProxyDropsTransportBeforeHandshake(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	_, proxyAddr, stopProxy := startProxyWithHandle(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Phase 1: Send transport data WITHOUT prior handshake (cold start).
	// The proxy should drop it silently.
	transportPkt := makeWGPacket(wgTransportData, 100)
	for i := 0; i < 3; i++ {
		clientConn.Write(transportPkt)
	}

	// Give proxy time to process.
	time.Sleep(100 * time.Millisecond)

	// Verify: nothing arrived at mock server.
	pkts := readPackets(mockServer, 500*time.Millisecond, 10)
	if len(pkts) > 0 {
		t.Fatalf("expected 0 packets at server before handshake, got %d", len(pkts))
	}

	// Phase 2: Send handshake init — this should go through.
	initPkt := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	clientConn.Write(initPkt)

	// Expect Jc junk + 1 handshake init.
	expectedTotal := cfg.Jc + 1
	hsPkts := readPackets(mockServer, 3*time.Second, expectedTotal+2)
	if len(hsPkts) < expectedTotal {
		t.Fatalf("expected at least %d packets (junk+init), got %d", expectedTotal, len(hsPkts))
	}

	// Verify last packet is the handshake init with H1 type.
	hsInit := hsPkts[cfg.Jc]
	expectedSize := cfg.S1 + WgHandshakeInitSize
	if len(hsInit) != expectedSize {
		t.Fatalf("handshake init: expected %d bytes, got %d", expectedSize, len(hsInit))
	}
	gotType := binary.LittleEndian.Uint32(hsInit[cfg.S1 : cfg.S1+4])
	if !cfg.H1.Contains(gotType) {
		t.Fatalf("handshake init type: expected H1, got %d", gotType)
	}

	// Phase 3: Now transport data should go through.
	transportPkt2 := makeWGPacket(wgTransportData, 80)
	savedPayload := make([]byte, 80)
	copy(savedPayload, transportPkt2)
	clientConn.Write(transportPkt2)

	tPkts := readPackets(mockServer, 3*time.Second, 1)
	if len(tPkts) < 1 {
		t.Fatal("transport data should arrive after handshake init")
	}
	if len(tPkts[0]) != 80 {
		t.Fatalf("transport: expected 80 bytes, got %d", len(tPkts[0]))
	}
	if !cfg.H4.Contains(binary.LittleEndian.Uint32(tPkts[0][:4])) {
		t.Fatal("transport: H4 type mismatch")
	}
	for i := 4; i < 80; i++ {
		if tPkts[0][i] != savedPayload[i] {
			t.Fatalf("transport byte %d mismatch", i)
		}
	}

	t.Log("transport correctly dropped before handshake, forwarded after")
}

// TestProxyDropsTransportAfterReconnect verifies that after a reconnect,
// the handshakeDone flag is reset and transport data is dropped until a
// new handshake init is sent.
func TestProxyDropsTransportAfterReconnect(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxy, proxyAddr, stopProxy := startProxyWithHandle(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Establish session — handshakeDone becomes true.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Verify transport works.
	pkt := makeWGPacket(wgTransportData, 64)
	clientConn.Write(pkt)
	pkts := readPackets(mockServer, 3*time.Second, 1)
	if len(pkts) < 1 {
		t.Fatal("transport should work after handshake")
	}

	// Force reconnect — handshakeDone should reset.
	forceReconnect(t, proxy)

	// Send transport without handshake — should be dropped.
	transportPkt := makeWGPacket(wgTransportData, 100)
	for i := 0; i < 3; i++ {
		clientConn.Write(transportPkt)
	}
	time.Sleep(100 * time.Millisecond)

	droppedPkts := readPackets(mockServer, 500*time.Millisecond, 10)
	if len(droppedPkts) > 0 {
		t.Fatalf("expected 0 packets after reconnect without handshake, got %d", len(droppedPkts))
	}

	// Re-establish session — handshakeDone becomes true again.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Transport should work again.
	pkt2 := makeWGPacket(wgTransportData, 64)
	clientConn.Write(pkt2)
	pkts2 := readPackets(mockServer, 3*time.Second, 1)
	if len(pkts2) < 1 {
		t.Fatal("transport should work after re-handshake")
	}

	t.Log("handshakeDone correctly reset on reconnect")
}

// TestProxyRekeySkipsJunk verifies that when handshakeDone is true (rekey),
// junk and CPS packets are NOT sent — only the transformed handshake init.
// This prevents burst congestion during WireGuard rekey.
func TestProxyRekeySkipsJunk(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	_, proxyAddr, stopProxy := startProxyWithHandle(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Phase 1: Initial handshake — should send Jc junk + 1 init.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Phase 2: Rekey handshake — handshakeDone is true, should send only 1 packet (no junk).
	rekeyPacket := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	if _, err := clientConn.Write(rekeyPacket); err != nil {
		t.Fatal("write rekey: ", err)
	}

	rekeyPkts := readPackets(mockServer, 2*time.Second, cfg.Jc+5)
	if len(rekeyPkts) != 1 {
		t.Fatalf("rekey: expected exactly 1 packet (no junk), got %d", len(rekeyPkts))
	}

	pkt := rekeyPkts[0]
	expectedSize := cfg.S1 + WgHandshakeInitSize
	if len(pkt) != expectedSize {
		t.Fatalf("rekey packet: expected %d bytes, got %d", expectedSize, len(pkt))
	}
	gotType := binary.LittleEndian.Uint32(pkt[cfg.S1 : cfg.S1+4])
	if !cfg.H1.Contains(gotType) {
		t.Fatalf("rekey packet type: expected H1, got %d", gotType)
	}

	t.Log("rekey correctly skips junk, sends only transformed handshake init")
}
