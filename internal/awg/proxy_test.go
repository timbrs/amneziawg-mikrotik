package awg

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// proxyTestConfig returns a synthetic config for proxy tests.
func proxyTestConfig() *Config {
	cfg := &Config{
		Jc:       4,
		Jmin:     10,
		Jmax:     50,
		S1:       46,
		S2:       122,
		H1:       HRange{Min: 100, Max: 100},
		H2:       HRange{Min: 200, Max: 200},
		H3:       HRange{Min: 300, Max: 300},
		H4:       HRange{Min: 400, Max: 400},
		Timeout:  180,
		LogLevel: LevelInfo,
	}
	cfg.ComputeFastPath()
	return cfg
}

// makeWGPacket creates a WireGuard packet with the given type and size.
// Bytes 4..size are filled with deterministic data (index mod 256).
func makeWGPacket(msgType uint32, size int) []byte {
	buf := make([]byte, size)
	binary.LittleEndian.PutUint32(buf[:4], msgType)
	for i := 4; i < size; i++ {
		buf[i] = byte(i)
	}
	return buf
}

// startMockServer starts a UDP listener on localhost with a random port.
// Returns the connection and the address it listens on.
func startMockServer(t *testing.T) *net.UDPConn {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("resolve mock server addr: ", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal("listen mock server: ", err)
	}
	return conn
}

// startProxy starts the proxy in a background goroutine. Returns the proxy's
// listen address and a stop function.
func startProxy(t *testing.T, cfg *Config, remoteAddr *net.UDPAddr) (*net.UDPAddr, func()) {
	t.Helper()

	listenAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("resolve listen addr: ", err)
	}

	// We need to discover the actual port the proxy binds to.
	// The proxy calls ListenUDP internally, so we pre-bind to find a port,
	// then close and let the proxy use it.
	tmpConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		t.Fatal("tmp listen: ", err)
	}
	actualAddr := tmpConn.LocalAddr().(*net.UDPAddr)
	proxyAddr := &net.UDPAddr{IP: actualAddr.IP, Port: actualAddr.Port}
	tmpConn.Close()

	// Give the OS a moment to release the port.
	time.Sleep(10 * time.Millisecond)

	proxy := NewProxy(cfg, proxyAddr, remoteAddr)
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		proxy.Run(stop)
	}()

	// Wait a bit for the proxy to start listening.
	time.Sleep(50 * time.Millisecond)

	cleanup := func() {
		close(stop)
		<-done
	}

	return proxyAddr, cleanup
}

// readPackets reads up to maxPackets from a UDP connection with a deadline.
// Returns all packets received before the deadline.
func readPackets(conn *net.UDPConn, deadline time.Duration, maxPackets int) [][]byte {
	var packets [][]byte
	conn.SetReadDeadline(time.Now().Add(deadline))
	for i := 0; i < maxPackets; i++ {
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		packets = append(packets, pkt)
	}
	return packets
}

func TestProxyForwardsHandshakeInit(t *testing.T) {
	cfg := proxyTestConfig()

	// Start mock AWG server.
	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	t.Logf("mock server listening on %s", mockAddr.String())

	// Start proxy.
	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	t.Logf("proxy listening on %s", proxyAddr.String())

	// Create client and send a WG handshake init.
	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial proxy: ", err)
	}
	defer clientConn.Close()

	initPacket := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	savedPayload := make([]byte, WgHandshakeInitSize)
	copy(savedPayload, initPacket)

	_, err = clientConn.Write(initPacket)
	if err != nil {
		t.Fatal("write to proxy: ", err)
	}

	// Read packets from mock server: expect Jc=4 junk + 1 handshake init = 5 packets.
	expectedTotal := cfg.Jc + 1
	packets := readPackets(mockServer, 3*time.Second, expectedTotal+5) // read a few extra to detect overcounting

	t.Logf("received %d packets at mock server (expected %d)", len(packets), expectedTotal)

	if len(packets) < expectedTotal {
		t.Fatalf("expected at least %d packets, got %d", expectedTotal, len(packets))
	}

	// First Jc packets should be junk (size between Jmin and Jmax).
	for i := 0; i < cfg.Jc; i++ {
		pkt := packets[i]
		if len(pkt) < cfg.Jmin || len(pkt) > cfg.Jmax {
			t.Fatalf("junk packet %d: size %d not in [%d, %d]", i, len(pkt), cfg.Jmin, cfg.Jmax)
		}
		t.Logf("junk packet %d: %d bytes (valid range %d-%d)", i, len(pkt), cfg.Jmin, cfg.Jmax)
	}

	// Last packet should be the transformed handshake init.
	hsInit := packets[cfg.Jc]
	expectedSize := cfg.S1 + WgHandshakeInitSize
	if len(hsInit) != expectedSize {
		t.Fatalf("handshake init: expected %d bytes (S1=%d + %d), got %d",
			expectedSize, cfg.S1, WgHandshakeInitSize, len(hsInit))
	}
	t.Logf("handshake init packet: %d bytes (expected %d)", len(hsInit), expectedSize)

	// Check H1 type at offset S1.
	gotType := binary.LittleEndian.Uint32(hsInit[cfg.S1 : cfg.S1+4])
	if !cfg.H1.Contains(gotType) {
		t.Fatalf("handshake init type: expected H1=%d, got %d", cfg.H1.Min, gotType)
	}
	t.Logf("H1 type at offset S1=%d: %d (correct)", cfg.S1, gotType)

	// Verify payload after type field is preserved (bytes 4-148 of original).
	for i := 4; i < WgHandshakeInitSize; i++ {
		if hsInit[cfg.S1+i] != savedPayload[i] {
			t.Fatalf("payload byte %d mismatch: expected 0x%02x, got 0x%02x",
				i, savedPayload[i], hsInit[cfg.S1+i])
		}
	}
	t.Logf("payload bytes 4-%d preserved correctly", WgHandshakeInitSize-1)

	// Verify no extra packets beyond expected.
	if len(packets) > expectedTotal {
		t.Logf("WARNING: received %d extra unexpected packets", len(packets)-expectedTotal)
	}
}

func TestProxyForwardsHandshakeResponse(t *testing.T) {
	cfg := proxyTestConfig()

	// Start mock AWG server.
	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	t.Logf("mock server listening on %s", mockAddr.String())

	// Start proxy.
	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	t.Logf("proxy listening on %s", proxyAddr.String())

	// Create client.
	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial proxy: ", err)
	}
	defer clientConn.Close()

	// Step 1: Send a handshake init to establish client address in proxy.
	initPacket := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	_, err = clientConn.Write(initPacket)
	if err != nil {
		t.Fatal("write init to proxy: ", err)
	}

	// Drain the junk + init packets at the mock server.
	_ = readPackets(mockServer, 2*time.Second, cfg.Jc+1)
	t.Logf("drained initial handshake packets from mock server")

	// Step 2: From mock server, send back a transformed handshake response.
	// Build AWG handshake response: S2 padding + H2 type + 92 bytes total inner.
	innerResponse := make([]byte, WgHandshakeResponseSize)
	binary.LittleEndian.PutUint32(innerResponse[:4], cfg.H2.Min)
	for i := 4; i < WgHandshakeResponseSize; i++ {
		innerResponse[i] = byte(i + 100) // distinct payload
	}
	savedInnerPayload := make([]byte, WgHandshakeResponseSize)
	copy(savedInnerPayload, innerResponse)

	awgResponse := make([]byte, cfg.S2+WgHandshakeResponseSize)
	randFill(awgResponse[:cfg.S2]) // random padding
	copy(awgResponse[cfg.S2:], innerResponse)

	// We need to find where the proxy's remote connection comes from,
	// so we can send the response back to it. The mock server received packets
	// from the proxy -- we need to read the source address.
	// Re-send init and capture the source address this time.
	initPacket2 := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	_, err = clientConn.Write(initPacket2)
	if err != nil {
		t.Fatal("write init2 to proxy: ", err)
	}

	// Read from mock server to capture proxy's source address.
	buf := make([]byte, 1500)
	mockServer.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, proxyRemoteAddr, err := mockServer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal("read from mock to get proxy addr: ", err)
	}
	// Drain remaining junk/init packets.
	for i := 0; i < cfg.Jc+1; i++ {
		mockServer.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		mockServer.ReadFromUDP(buf)
	}

	t.Logf("proxy remote address: %s", proxyRemoteAddr.String())

	// Send the AWG response from mock server to proxy's remote address.
	_, err = mockServer.WriteToUDP(awgResponse, proxyRemoteAddr)
	if err != nil {
		t.Fatal("write response from mock: ", err)
	}
	t.Logf("sent AWG handshake response (%d bytes) to proxy", len(awgResponse))

	// Step 3: Read the response at the client.
	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, 1500)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatal("read response at client: ", err)
	}

	t.Logf("client received response: %d bytes", n)

	// Verify: should be a standard WG handshake response (type=2, 92 bytes).
	if n != WgHandshakeResponseSize {
		t.Fatalf("expected %d bytes, got %d", WgHandshakeResponseSize, n)
	}

	gotType := binary.LittleEndian.Uint32(respBuf[:4])
	if gotType != wgHandshakeResponse {
		t.Fatalf("expected WG type %d, got %d", wgHandshakeResponse, gotType)
	}
	t.Logf("response type: %d (WG handshake response, correct)", gotType)

	// Verify payload is preserved (bytes 4-92).
	for i := 4; i < WgHandshakeResponseSize; i++ {
		if respBuf[i] != savedInnerPayload[i] {
			t.Fatalf("response payload byte %d mismatch: expected 0x%02x, got 0x%02x",
				i, savedInnerPayload[i], respBuf[i])
		}
	}
	t.Logf("response payload bytes 4-%d preserved correctly", WgHandshakeResponseSize-1)
}

func TestProxyForwardsTransportData(t *testing.T) {
	cfg := proxyTestConfig()

	// Start mock AWG server.
	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	t.Logf("mock server listening on %s", mockAddr.String())

	// Start proxy.
	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	t.Logf("proxy listening on %s", proxyAddr.String())

	// Create client.
	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial proxy: ", err)
	}
	defer clientConn.Close()

	// Step 1: Send a handshake init first to establish the client in the proxy.
	initPacket := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	_, err = clientConn.Write(initPacket)
	if err != nil {
		t.Fatal("write init: ", err)
	}

	// Drain packets at mock server.
	_ = readPackets(mockServer, 2*time.Second, cfg.Jc+1)

	// Step 2: Send a WG transport data packet (type=4, 100 bytes).
	transportPacket := makeWGPacket(wgTransportData, 100)
	savedPayload := make([]byte, 100)
	copy(savedPayload, transportPacket)

	_, err = clientConn.Write(transportPacket)
	if err != nil {
		t.Fatal("write transport: ", err)
	}

	// Read from mock server.
	packets := readPackets(mockServer, 3*time.Second, 5)

	if len(packets) < 1 {
		t.Fatal("expected at least 1 packet at mock server for transport data")
	}

	t.Logf("received %d packets at mock server for transport data", len(packets))

	// Transport data should arrive with same size, H4 type (no padding, no junk).
	pkt := packets[0]
	if len(pkt) != 100 {
		t.Fatalf("transport packet: expected 100 bytes, got %d", len(pkt))
	}

	gotType := binary.LittleEndian.Uint32(pkt[:4])
	if !cfg.H4.Contains(gotType) {
		t.Fatalf("transport packet: expected H4=%d, got %d", cfg.H4.Min, gotType)
	}
	t.Logf("transport packet type: H4=%d (correct)", gotType)

	// Verify payload preserved (bytes 4-100).
	for i := 4; i < 100; i++ {
		if pkt[i] != savedPayload[i] {
			t.Fatalf("transport payload byte %d mismatch: expected 0x%02x, got 0x%02x",
				i, savedPayload[i], pkt[i])
		}
	}
	t.Logf("transport payload bytes 4-99 preserved correctly")

	// Verify no junk packets were sent (transport data should not trigger junk).
	if len(packets) > 1 {
		t.Fatalf("transport data should NOT trigger junk packets, but got %d extra packets", len(packets)-1)
	}
}
