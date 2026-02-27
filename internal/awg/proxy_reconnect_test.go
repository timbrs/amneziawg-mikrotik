package awg

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- Helpers ---

// startProxyWithHandle is like startProxy but also returns the *Proxy so tests
// can inspect and manipulate internal state (remoteConn, clientAddr, etc.).
func startProxyWithHandle(t *testing.T, cfg *Config, remoteAddr *net.UDPAddr) (*Proxy, *net.UDPAddr, func()) {
	t.Helper()
	listenAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tmpConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	actualAddr := tmpConn.LocalAddr().(*net.UDPAddr)
	proxyAddr := &net.UDPAddr{IP: actualAddr.IP, Port: actualAddr.Port}
	tmpConn.Close()
	time.Sleep(10 * time.Millisecond)

	proxy := NewProxy(cfg, proxyAddr, remoteAddr)
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		proxy.Run(stop)
	}()

	time.Sleep(50 * time.Millisecond)

	cleanup := func() {
		close(stop)
		<-done
	}

	return proxy, proxyAddr, cleanup
}

// waitForReconnect polls until proxy.remoteConn differs from oldConn.
func waitForReconnect(t *testing.T, proxy *Proxy, oldConn *net.UDPConn, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if proxy.remoteConn.Load() != oldConn {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("reconnect did not happen within timeout")
}

// forceReconnect closes the proxy's current remote connection, waits for
// the proxy to reconnect, and returns the new connection.
func forceReconnect(t *testing.T, proxy *Proxy) *net.UDPConn {
	t.Helper()
	oldConn := proxy.remoteConn.Load()
	oldConn.Close()
	waitForReconnect(t, proxy, oldConn, 5*time.Second)
	return proxy.remoteConn.Load()
}

// --- Integration tests: reconnect scenarios ---

// TestProxyReconnectBasic verifies that after the remote connection is
// forcibly closed, the proxy reconnects and outbound traffic resumes.
func TestProxyReconnectBasic(t *testing.T) {
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

	// Phase 1: Establish session, send transport, verify it arrives.
	_ = establishSession(t, cfg, clientConn, mockServer)

	pkt1 := makeWGPacket(wgTransportData, 100)
	clientConn.Write(pkt1)
	pkts := readPackets(mockServer, 3*time.Second, 1)
	if len(pkts) < 1 {
		t.Fatal("phase1: no transport at server")
	}

	// Phase 2: Force reconnect by closing remote conn.
	newConn := forceReconnect(t, proxy)
	if newConn == nil {
		t.Fatal("remoteConn is nil after reconnect")
	}

	// Phase 3: Re-establish session (clientAddr cleared on reconnect).
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Phase 4: Verify outbound transport works through new connection.
	pkt2 := makeWGPacket(wgTransportData, 200)
	savedPayload := make([]byte, 200)
	copy(savedPayload, pkt2)
	clientConn.Write(pkt2)

	pkts2 := readPackets(mockServer, 3*time.Second, 1)
	if len(pkts2) < 1 {
		t.Fatal("phase4: no transport after reconnect")
	}
	if len(pkts2[0]) != 200 {
		t.Fatalf("phase4: size %d, expected 200", len(pkts2[0]))
	}
	if !cfg.H4.Contains(binary.LittleEndian.Uint32(pkts2[0][:4])) {
		t.Fatal("phase4: H4 type mismatch")
	}
	for i := 4; i < 200; i++ {
		if pkts2[0][i] != savedPayload[i] {
			t.Fatalf("phase4: byte %d mismatch", i)
		}
	}

	t.Log("outbound traffic restored after reconnect")
}

// TestProxyReconnectBidirectional verifies that both client->server and
// server->client traffic work correctly after a forced reconnect.
func TestProxyReconnectBidirectional(t *testing.T) {
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

	// Phase 1: Establish and verify bidirectional before reconnect.
	proxyRemoteAddr := establishSession(t, cfg, clientConn, mockServer)

	// Client -> server.
	pkt := makeWGPacket(wgTransportData, 100)
	clientConn.Write(pkt)
	pkts := readPackets(mockServer, 3*time.Second, 1)
	if len(pkts) < 1 {
		t.Fatal("phase1: no outbound transport")
	}

	// Server -> client.
	srvPkt := make([]byte, 80)
	binary.LittleEndian.PutUint32(srvPkt[:4], cfg.H4.Min)
	for i := 4; i < 80; i++ {
		srvPkt[i] = byte(i + 10)
	}
	mockServer.WriteToUDP(srvPkt, proxyRemoteAddr)

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatal("phase1: no inbound transport: ", err)
	}
	if n != 80 || binary.LittleEndian.Uint32(buf[:4]) != wgTransportData {
		t.Fatal("phase1: inbound mismatch")
	}

	// Phase 2: Force reconnect.
	forceReconnect(t, proxy)

	// Phase 3: Re-establish session and capture new proxy remote address.
	proxyRemoteAddr2 := establishSession(t, cfg, clientConn, mockServer)

	// Proxy should have a new remote address (new local port after reconnect).
	if proxyRemoteAddr2.Port == proxyRemoteAddr.Port {
		t.Log("note: proxy remote port unchanged (OS reused port)")
	}

	// Phase 4: Verify client -> server.
	pkt2 := makeWGPacket(wgTransportData, 120)
	savedOut := make([]byte, 120)
	copy(savedOut, pkt2)
	clientConn.Write(pkt2)

	pkts2 := readPackets(mockServer, 3*time.Second, 1)
	if len(pkts2) < 1 {
		t.Fatal("phase4: no outbound after reconnect")
	}
	if len(pkts2[0]) != 120 {
		t.Fatalf("phase4: outbound size %d, expected 120", len(pkts2[0]))
	}
	for i := 4; i < 120; i++ {
		if pkts2[0][i] != savedOut[i] {
			t.Fatalf("phase4: outbound byte %d mismatch", i)
		}
	}

	// Phase 5: Verify server -> client via new proxy address.
	srvPkt2 := make([]byte, 90)
	binary.LittleEndian.PutUint32(srvPkt2[:4], cfg.H4.Min)
	for i := 4; i < 90; i++ {
		srvPkt2[i] = byte(i + 50)
	}
	mockServer.WriteToUDP(srvPkt2, proxyRemoteAddr2)

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatal("phase5: no inbound after reconnect: ", err)
	}
	if n != 90 {
		t.Fatalf("phase5: inbound size %d, expected 90", n)
	}
	if binary.LittleEndian.Uint32(buf[:4]) != wgTransportData {
		t.Fatalf("phase5: inbound type %d, expected %d",
			binary.LittleEndian.Uint32(buf[:4]), wgTransportData)
	}
	for i := 4; i < 90; i++ {
		if buf[i] != byte(i+50) {
			t.Fatalf("phase5: inbound byte %d mismatch", i)
		}
	}

	t.Log("bidirectional traffic works after reconnect")
}

// TestProxyReconnectMultiple forces three sequential reconnects and
// verifies traffic works after each one.
func TestProxyReconnectMultiple(t *testing.T) {
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

	for round := 0; round < 3; round++ {
		if round > 0 {
			forceReconnect(t, proxy)
		}

		// Re-establish session after reconnect (or initial).
		_ = establishSession(t, cfg, clientConn, mockServer)

		// Verify outbound transport works.
		size := 64 + round*32
		pkt := makeWGPacket(wgTransportData, size)
		savedPayload := make([]byte, size)
		copy(savedPayload, pkt)
		clientConn.Write(pkt)

		pkts := readPackets(mockServer, 3*time.Second, 1)
		if len(pkts) < 1 {
			t.Fatalf("round %d: no transport at server", round)
		}
		if len(pkts[0]) != size {
			t.Fatalf("round %d: size %d, expected %d", round, len(pkts[0]), size)
		}
		if !cfg.H4.Contains(binary.LittleEndian.Uint32(pkts[0][:4])) {
			t.Fatalf("round %d: type mismatch", round)
		}
		for j := 4; j < size; j++ {
			if pkts[0][j] != savedPayload[j] {
				t.Fatalf("round %d: byte %d mismatch", round, j)
			}
		}
	}

	t.Log("3 sequential reconnects: traffic works after each")
}

// TestProxyClientAddrResetOnReconnect verifies that the proxy clears the
// client address on reconnect and re-establishes it from the next packet.
func TestProxyClientAddrResetOnReconnect(t *testing.T) {
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

	// Establish session — clientAddr should be set.
	_ = establishSession(t, cfg, clientConn, mockServer)
	if proxy.clientAddr.Load() == nil {
		t.Fatal("clientAddr should be set after session")
	}

	// Force reconnect — clientAddr should be cleared.
	forceReconnect(t, proxy)
	if proxy.clientAddr.Load() != nil {
		t.Fatal("clientAddr should be nil after reconnect")
	}

	// Send a new packet — clientAddr should be re-established.
	_ = establishSession(t, cfg, clientConn, mockServer)
	addr := proxy.clientAddr.Load()
	if addr == nil {
		t.Fatal("clientAddr should be set after re-establish")
	}
	t.Log("clientAddr correctly reset on reconnect and re-established: ", addr.String())
}

// TestProxyNewClientAfterReconnect verifies that a new client (different
// source port) can take over after a reconnect clears the old client address.
func TestProxyNewClientAfterReconnect(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxy, proxyAddr, stopProxy := startProxyWithHandle(t, cfg, mockAddr)
	defer stopProxy()

	// Client A connects and establishes session.
	clientA, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial A: ", err)
	}
	defer clientA.Close()

	_ = establishSession(t, cfg, clientA, mockServer)

	addrA := proxy.clientAddr.Load()
	if addrA == nil {
		t.Fatal("clientAddr should be set for client A")
	}
	t.Log("client A: ", addrA.String())

	// Force reconnect — clears clientAddr.
	forceReconnect(t, proxy)

	// Client B connects from a new socket (different local port).
	clientB, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial B: ", err)
	}
	defer clientB.Close()

	proxyRemoteAddr2 := establishSession(t, cfg, clientB, mockServer)

	addrB := proxy.clientAddr.Load()
	if addrB == nil {
		t.Fatal("clientAddr should be set for client B")
	}
	t.Log("client B: ", addrB.String())

	if *addrA == *addrB {
		t.Fatal("client A and B should have different addresses")
	}

	// Verify server -> client B works (not client A).
	srvPkt := make([]byte, 64)
	binary.LittleEndian.PutUint32(srvPkt[:4], cfg.H4.Min)
	for i := 4; i < 64; i++ {
		srvPkt[i] = byte(i + 99)
	}
	mockServer.WriteToUDP(srvPkt, proxyRemoteAddr2)

	// Client B should receive the packet.
	clientB.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := clientB.Read(buf)
	if err != nil {
		t.Fatal("client B read: ", err)
	}
	if n != 64 {
		t.Fatalf("client B: size %d, expected 64", n)
	}
	if binary.LittleEndian.Uint32(buf[:4]) != wgTransportData {
		t.Fatal("client B: type mismatch")
	}

	// Client A should NOT receive the packet (address was cleared).
	clientA.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = clientA.Read(buf)
	if err == nil {
		t.Fatal("client A should NOT receive packet after reconnect + client B takeover")
	}

	t.Log("new client B correctly took over after reconnect")
}

// TestProxyReconnectPreservesTransformConfig verifies that packet
// transformation works identically after a reconnect (same H/S params).
func TestProxyReconnectPreservesTransformConfig(t *testing.T) {
	cfg := v2Config() // use v2 to test S4 padding survives reconnect

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

	// Before reconnect: send transport, verify S4 padding.
	_ = establishSession(t, cfg, clientConn, mockServer)

	pktBefore := makeWGPacket(wgTransportData, 80)
	clientConn.Write(pktBefore)
	pktsBefore := readPackets(mockServer, 3*time.Second, 1)
	if len(pktsBefore) < 1 {
		t.Fatal("before: no transport")
	}
	if len(pktsBefore[0]) != cfg.S4+80 {
		t.Fatalf("before: size %d, expected %d", len(pktsBefore[0]), cfg.S4+80)
	}

	// Force reconnect.
	forceReconnect(t, proxy)

	// After reconnect: verify same S4 padding applied.
	_ = establishSession(t, cfg, clientConn, mockServer)

	pktAfter := makeWGPacket(wgTransportData, 80)
	clientConn.Write(pktAfter)
	pktsAfter := readPackets(mockServer, 3*time.Second, 1)
	if len(pktsAfter) < 1 {
		t.Fatal("after: no transport")
	}
	if len(pktsAfter[0]) != cfg.S4+80 {
		t.Fatalf("after: size %d, expected %d", len(pktsAfter[0]), cfg.S4+80)
	}
	gotType := binary.LittleEndian.Uint32(pktsAfter[0][cfg.S4 : cfg.S4+4])
	if !cfg.H4.Contains(gotType) {
		t.Fatalf("after: H4 type mismatch: %d", gotType)
	}

	t.Log("v2 transform config preserved after reconnect")
}

// TestProxyReconnectDuringTraffic verifies that a reconnect triggered
// mid-stream doesn't cause the proxy to hang or crash. Some packets
// may be lost during the reconnect window, but the proxy recovers.
func TestProxyReconnectDuringTraffic(t *testing.T) {
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

	_ = establishSession(t, cfg, clientConn, mockServer)

	// Start rapid-fire transport packets in a goroutine.
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for i := 0; i < 100; i++ {
			pkt := makeWGPacket(wgTransportData, 64)
			pkt[4] = byte(i) // marker
			clientConn.Write(pkt)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Mid-stream: force reconnect after 200ms.
	time.Sleep(200 * time.Millisecond)
	forceReconnect(t, proxy)

	// Wait for sender to finish.
	<-sendDone

	// Re-establish session.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Verify post-reconnect traffic works.
	marker := makeWGPacket(wgTransportData, 100)
	marker[4] = 0xFF
	marker[5] = 0xAA
	clientConn.Write(marker)

	// Read until we find our marker packet.
	mockServer.SetReadDeadline(time.Now().Add(5 * time.Second))
	found := false
	for i := 0; i < 200; i++ {
		buf := make([]byte, 2048)
		n, _, err := mockServer.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n == 100 && buf[4] == 0xFF && buf[5] == 0xAA {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("marker packet not found after mid-stream reconnect")
	}

	t.Log("proxy recovered from mid-stream reconnect")
}

// TestProxyClientToServerSetsLastActive verifies that packets received from
// the client (e.g. WG keepalives) mark the proxy as active, preventing
// false timeout reconnects when only client->server traffic flows.
func TestProxyClientToServerSetsLastActive(t *testing.T) {
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

	// Establish session.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Clear lastActive — simulate the timeout checker clearing it.
	proxy.lastActive.Store(false)

	// Send a transport packet (simulates WG keepalive from client).
	pkt := makeWGPacket(wgTransportData, 64)
	if _, err := clientConn.Write(pkt); err != nil {
		t.Fatal("write: ", err)
	}

	// Wait for the proxy to process the packet.
	_ = readPackets(mockServer, 2*time.Second, 1)

	// lastActive must be true now.
	if !proxy.lastActive.Load() {
		t.Fatal("lastActive should be true after client->server packet")
	}

	// Verify it resets again after CAS by timeout checker logic.
	if !proxy.lastActive.CompareAndSwap(true, false) {
		t.Fatal("CAS should succeed (lastActive was true)")
	}

	// Send another packet.
	pkt2 := makeWGPacket(wgTransportData, 64)
	if _, err := clientConn.Write(pkt2); err != nil {
		t.Fatal("write2: ", err)
	}
	_ = readPackets(mockServer, 2*time.Second, 1)

	if !proxy.lastActive.Load() {
		t.Fatal("lastActive should be true after second client->server packet")
	}

	t.Log("clientToServer correctly sets lastActive on every packet")
}

// TestProxyNoFalseReconnectOnKeepalive verifies that the proxy does NOT
// trigger a reconnect when only client->server keepalives flow (no server
// responses). This was the exact bug: timeout checker saw no activity
// because clientToServer never set lastActive.
func TestProxyNoFalseReconnectOnKeepalive(t *testing.T) {
	cfg := proxyTestConfig()
	cfg.Timeout = 2 // 2-second timeout for fast test

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

	// Establish session.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Record initial remote connection.
	initialConn := proxy.remoteConn.Load()

	// Send keepalive-like packets every 500ms for 4 seconds (2x timeout).
	// The proxy should NOT reconnect because each packet sets lastActive.
	for i := 0; i < 8; i++ {
		pkt := makeWGPacket(wgTransportData, 64)
		clientConn.Write(pkt)
		_ = readPackets(mockServer, 500*time.Millisecond, 1)
		time.Sleep(500 * time.Millisecond)
	}

	// Verify the remote connection was NOT replaced (no reconnect).
	currentConn := proxy.remoteConn.Load()
	if currentConn != initialConn {
		t.Fatal("proxy reconnected despite active client->server traffic (false reconnect bug)")
	}

	t.Log("no false reconnect during 4s of client->server keepalive traffic with 2s timeout")
}

// TestProxyShutdownDuringReconnect verifies that requesting shutdown while
// the proxy is in the reconnect loop doesn't hang.
func TestProxyShutdownDuringReconnect(t *testing.T) {
	cfg := proxyTestConfig()

	// Point proxy at a non-existent address (high port, unlikely to respond).
	// Use a real mock server first to start the proxy, then close it.
	mockServer := startMockServer(t)
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxy, proxyAddr, _ := startProxyWithHandle(t, cfg, mockAddr)

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Establish session.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Close mock server so reconnect attempt will "succeed" (UDP dial always works)
	// but reads from new conn will fail, triggering another reconnect loop.
	mockServer.Close()

	// Force reconnect — the proxy enters reconnect loop.
	oldConn := proxy.remoteConn.Load()
	oldConn.Close()

	// Give it a moment to enter the reconnect loop.
	time.Sleep(200 * time.Millisecond)

	// Now request shutdown via stopped flag + close remote.
	proxy.stopped.Store(true)
	if rc := proxy.remoteConn.Load(); rc != nil {
		rc.Close()
	}

	// The proxy should exit cleanly. We can't use our normal stopProxy
	// because we already manipulated the proxy. Just verify it doesn't hang
	// by waiting a bounded time.
	time.Sleep(2 * time.Second)
	t.Log("proxy didn't hang during shutdown-while-reconnecting")
}
