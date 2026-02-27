package awg

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"
)

// --- Helpers ---

type simpleErr string

func (e simpleErr) Error() string { return string(e) }

// readPacketsWithAddr reads up to maxPackets from conn, returning packets and
// the source address of the first received packet.
func readPacketsWithAddr(conn *net.UDPConn, deadline time.Duration, maxPackets int) ([][]byte, *net.UDPAddr) {
	var packets [][]byte
	var firstAddr *net.UDPAddr
	conn.SetReadDeadline(time.Now().Add(deadline))
	for i := 0; i < maxPackets; i++ {
		buf := make([]byte, 2048)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		packets = append(packets, pkt)
		if firstAddr == nil {
			firstAddr = addr
		}
	}
	return packets, firstAddr
}

// establishSession sends a WG handshake init through the proxy, drains the
// junk+init at the mock server, and returns the proxy's remote address.
func establishSession(t *testing.T, cfg *Config, clientConn *net.UDPConn, mockServer *net.UDPConn) *net.UDPAddr {
	t.Helper()
	initPacket := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	if _, err := clientConn.Write(initPacket); err != nil {
		t.Fatal("establish: write init: ", err)
	}
	_, proxyAddr := readPacketsWithAddr(mockServer, 3*time.Second, cfg.Jc+2)
	if proxyAddr == nil {
		t.Fatal("establish: no packets from proxy at mock server")
	}
	return proxyAddr
}

// v2Config creates a Config with v2 features (S3/S4 padding).
func v2Config() *Config {
	cfg := &Config{
		Jc:       2,
		Jmin:     10,
		Jmax:     30,
		S1:       20,
		S2:       20,
		S3:       15,
		S4:       25,
		H1:       HRange{Min: 100000001, Max: 100000001},
		H2:       HRange{Min: 100000002, Max: 100000002},
		H3:       HRange{Min: 100000003, Max: 100000003},
		H4:       HRange{Min: 100000004, Max: 100000004},
		Timeout:  180,
		LogLevel: LevelInfo,
	}
	cfg.ComputeFastPath()
	return cfg
}

// --- Unit tests for isClosedErr (Bug #5 fix) ---

func TestIsClosedErrEBADF(t *testing.T) {
	if !isClosedErr(syscall.EBADF) {
		t.Error("expected true for EBADF")
	}
}

func TestIsClosedErrNetClosed(t *testing.T) {
	if !isClosedErr(net.ErrClosed) {
		t.Error("expected true for net.ErrClosed")
	}
}

func TestIsClosedErrWrappedString(t *testing.T) {
	if !isClosedErr(simpleErr("read udp: use of closed network connection")) {
		t.Error("expected true for wrapped 'use of closed' string")
	}
}

func TestIsClosedErrOtherErrno(t *testing.T) {
	if isClosedErr(syscall.ECONNREFUSED) {
		t.Error("expected false for ECONNREFUSED")
	}
}

func TestIsClosedErrGeneric(t *testing.T) {
	if isClosedErr(simpleErr("connection refused")) {
		t.Error("expected false for generic error")
	}
}

// --- Integration tests ---

// TestProxyBidirectionalFlow simulates a complete VPN session:
// handshake init -> response -> transport in both directions.
func TestProxyBidirectionalFlow(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Phase 1: Handshake init (client -> proxy -> server).
	initPayload := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	savedInit := make([]byte, WgHandshakeInitSize)
	copy(savedInit, initPayload)

	if _, err := clientConn.Write(initPayload); err != nil {
		t.Fatal("write init: ", err)
	}

	serverPkts, proxyRemoteAddr := readPacketsWithAddr(mockServer, 3*time.Second, cfg.Jc+2)
	if len(serverPkts) < cfg.Jc+1 {
		t.Fatalf("phase1: expected >= %d packets, got %d", cfg.Jc+1, len(serverPkts))
	}

	// Verify init transformed correctly.
	hsInit := serverPkts[cfg.Jc]
	if len(hsInit) != cfg.S1+WgHandshakeInitSize {
		t.Fatalf("phase1: init size %d, expected %d", len(hsInit), cfg.S1+WgHandshakeInitSize)
	}
	initType := binary.LittleEndian.Uint32(hsInit[cfg.S1 : cfg.S1+4])
	if !cfg.H1.Contains(initType) {
		t.Fatalf("phase1: type %d, expected H1=%d", initType, cfg.H1.Min)
	}
	for i := 4; i < WgHandshakeInitSize; i++ {
		if hsInit[cfg.S1+i] != savedInit[i] {
			t.Fatalf("phase1: init byte %d mismatch", i)
		}
	}

	// Phase 2: Handshake response (server -> proxy -> client).
	innerResp := make([]byte, WgHandshakeResponseSize)
	binary.LittleEndian.PutUint32(innerResp[:4], cfg.H2.Min)
	for i := 4; i < WgHandshakeResponseSize; i++ {
		innerResp[i] = byte(i + 50)
	}
	savedResp := make([]byte, WgHandshakeResponseSize)
	copy(savedResp, innerResp)

	awgResp := make([]byte, cfg.S2+WgHandshakeResponseSize)
	randFill(awgResp[:cfg.S2])
	copy(awgResp[cfg.S2:], innerResp)

	if _, err := mockServer.WriteToUDP(awgResp, proxyRemoteAddr); err != nil {
		t.Fatal("write response: ", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, 1500)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatal("read response: ", err)
	}
	if n != WgHandshakeResponseSize {
		t.Fatalf("phase2: size %d, expected %d", n, WgHandshakeResponseSize)
	}
	if binary.LittleEndian.Uint32(respBuf[:4]) != wgHandshakeResponse {
		t.Fatalf("phase2: type %d, expected %d", binary.LittleEndian.Uint32(respBuf[:4]), wgHandshakeResponse)
	}
	for i := 4; i < WgHandshakeResponseSize; i++ {
		if respBuf[i] != savedResp[i] {
			t.Fatalf("phase2: byte %d mismatch", i)
		}
	}

	// Phase 3: Transport data (client -> proxy -> server).
	transportOut := makeWGPacket(wgTransportData, 200)
	savedTransport := make([]byte, 200)
	copy(savedTransport, transportOut)

	if _, err := clientConn.Write(transportOut); err != nil {
		t.Fatal("write transport: ", err)
	}

	srvPkts2 := readPackets(mockServer, 3*time.Second, 3)
	if len(srvPkts2) < 1 {
		t.Fatal("phase3: no transport packet at server")
	}
	tPkt := srvPkts2[0]
	if len(tPkt) != 200 {
		t.Fatalf("phase3: size %d, expected 200", len(tPkt))
	}
	if !cfg.H4.Contains(binary.LittleEndian.Uint32(tPkt[:4])) {
		t.Fatalf("phase3: type mismatch")
	}
	for i := 4; i < 200; i++ {
		if tPkt[i] != savedTransport[i] {
			t.Fatalf("phase3: byte %d mismatch", i)
		}
	}

	// Phase 4: Transport data (server -> proxy -> client).
	transportIn := make([]byte, 150)
	binary.LittleEndian.PutUint32(transportIn[:4], cfg.H4.Min)
	for i := 4; i < 150; i++ {
		transportIn[i] = byte(i + 77)
	}

	if _, err := mockServer.WriteToUDP(transportIn, proxyRemoteAddr); err != nil {
		t.Fatal("write transport from server: ", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	tBuf := make([]byte, 1500)
	n, err = clientConn.Read(tBuf)
	if err != nil {
		t.Fatal("read transport at client: ", err)
	}
	if n != 150 {
		t.Fatalf("phase4: size %d, expected 150", n)
	}
	if binary.LittleEndian.Uint32(tBuf[:4]) != wgTransportData {
		t.Fatalf("phase4: type %d, expected %d", binary.LittleEndian.Uint32(tBuf[:4]), wgTransportData)
	}
	for i := 4; i < 150; i++ {
		if tBuf[i] != byte(i+77) {
			t.Fatalf("phase4: byte %d mismatch", i)
		}
	}

	t.Log("all 4 phases passed: init, response, transport out, transport in")
}

// TestProxyTransportEchoRoundtrip verifies transport data survives a full
// roundtrip through the proxy via an echo mock server.
func TestProxyTransportEchoRoundtrip(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	// Echo goroutine: reads and writes back every packet.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := mockServer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mockServer.WriteToUDP(buf[:n], addr)
		}
	}()

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Establish session (init + junk get echoed, we drain them).
	initPacket := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	clientConn.Write(initPacket)
	time.Sleep(300 * time.Millisecond)
	clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	drainBuf := make([]byte, 2048)
	for {
		if _, err := clientConn.Read(drainBuf); err != nil {
			break
		}
	}

	// Send 5 transport packets of varying sizes, each should be echoed back.
	for i := 0; i < 5; i++ {
		size := 64 + i*32 // 64, 96, 128, 160, 192
		original := makeWGPacket(wgTransportData, size)
		savedPayload := make([]byte, size)
		copy(savedPayload, original)

		if _, err := clientConn.Write(original); err != nil {
			t.Fatalf("write transport %d: %v", i, err)
		}

		clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		respBuf := make([]byte, 2048)
		n, err := clientConn.Read(respBuf)
		if err != nil {
			t.Fatalf("read echo %d: %v", i, err)
		}

		if n != size {
			t.Fatalf("echo %d: size %d, expected %d", i, n, size)
		}

		gotType := binary.LittleEndian.Uint32(respBuf[:4])
		if gotType != wgTransportData {
			t.Fatalf("echo %d: type %d, expected %d", i, gotType, wgTransportData)
		}

		for j := 4; j < size; j++ {
			if respBuf[j] != savedPayload[j] {
				t.Fatalf("echo %d: byte %d mismatch: got 0x%02x, want 0x%02x",
					i, j, respBuf[j], savedPayload[j])
			}
		}
	}

	t.Log("5 transport echo roundtrips passed with payload integrity")
}

// TestProxyMultipleTransportPackets sends many transport packets rapidly
// and verifies all arrive at the mock server with correct data.
func TestProxyMultipleTransportPackets(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Establish session.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Send N transport packets rapidly.
	const numPackets = 50
	sent := make([][]byte, numPackets)
	for i := 0; i < numPackets; i++ {
		size := 64 + (i%10)*16 // 64..208
		pkt := make([]byte, size)
		binary.LittleEndian.PutUint32(pkt[:4], wgTransportData)
		// Mark each packet with its index for identification.
		if size > 5 {
			pkt[4] = byte(i)
			pkt[5] = byte(i >> 8)
		}
		for j := 6; j < size; j++ {
			pkt[j] = byte(j ^ i)
		}
		sent[i] = pkt

		if _, err := clientConn.Write(pkt); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}

	// Read all packets at mock server.
	received := readPackets(mockServer, 5*time.Second, numPackets)

	if len(received) < numPackets {
		t.Fatalf("received %d/%d packets", len(received), numPackets)
	}

	// Verify each: correct size, H4 type, payload preserved.
	for i := 0; i < numPackets; i++ {
		pkt := received[i]
		expectedSize := len(sent[i])
		if len(pkt) != expectedSize {
			t.Fatalf("packet %d: size %d, expected %d", i, len(pkt), expectedSize)
		}

		gotType := binary.LittleEndian.Uint32(pkt[:4])
		if !cfg.H4.Contains(gotType) {
			t.Fatalf("packet %d: type %d, expected H4", i, gotType)
		}

		for j := 4; j < expectedSize; j++ {
			if pkt[j] != sent[i][j] {
				t.Fatalf("packet %d: byte %d mismatch", i, j)
			}
		}
	}

	t.Logf("all %d transport packets forwarded correctly", numPackets)
}

// TestProxyDropsJunkInbound verifies that junk packets sent from the server
// side are not forwarded to the client.
func TestProxyDropsJunkInbound(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	proxyRemoteAddr := establishSession(t, cfg, clientConn, mockServer)

	// Send 10 junk packets from mock server with a type that won't match
	// any H range in the config.
	for i := 0; i < 10; i++ {
		junk := make([]byte, 30+i*5)
		randFill(junk)
		binary.LittleEndian.PutUint32(junk[:4], 0xDEADBEEF)
		mockServer.WriteToUDP(junk, proxyRemoteAddr)
	}

	// Wait for packets to potentially arrive at client.
	time.Sleep(500 * time.Millisecond)

	// Client should not receive any packets.
	clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	n, err := clientConn.Read(buf)
	if err == nil {
		t.Fatalf("client received %d bytes from junk, expected nothing", n)
	}

	t.Log("all 10 junk packets correctly dropped by proxy")
}

// TestProxyCookieReplyForwarding verifies cookie reply packets (type=3)
// are correctly transformed inbound and forwarded to the client.
func TestProxyCookieReplyForwarding(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	proxyRemoteAddr := establishSession(t, cfg, clientConn, mockServer)

	// Build AWG cookie reply: H3 type, 64 bytes (S3=0 in v1, no padding).
	cookie := make([]byte, WgCookieReplySize)
	binary.LittleEndian.PutUint32(cookie[:4], cfg.H3.Min)
	for i := 4; i < WgCookieReplySize; i++ {
		cookie[i] = byte(i + 200)
	}
	savedCookie := make([]byte, WgCookieReplySize)
	copy(savedCookie, cookie)

	if _, err := mockServer.WriteToUDP(cookie, proxyRemoteAddr); err != nil {
		t.Fatal("write cookie: ", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatal("read cookie: ", err)
	}

	if n != WgCookieReplySize {
		t.Fatalf("cookie size %d, expected %d", n, WgCookieReplySize)
	}
	if binary.LittleEndian.Uint32(buf[:4]) != wgCookieReply {
		t.Fatalf("cookie type %d, expected %d", binary.LittleEndian.Uint32(buf[:4]), wgCookieReply)
	}
	for i := 4; i < WgCookieReplySize; i++ {
		if buf[i] != savedCookie[i] {
			t.Fatalf("cookie byte %d mismatch", i)
		}
	}

	t.Log("cookie reply forwarded correctly")
}

// TestProxyOutboundCookieReply verifies outbound cookie reply (type=3)
// is transformed with H3 type replacement.
func TestProxyOutboundCookieReply(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Establish session first.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Send a WG cookie reply from client (type=3, 64 bytes).
	cookie := makeWGPacket(wgCookieReply, WgCookieReplySize)
	savedCookie := make([]byte, WgCookieReplySize)
	copy(savedCookie, cookie)

	if _, err := clientConn.Write(cookie); err != nil {
		t.Fatal("write cookie: ", err)
	}

	// Server should receive with H3 type (no padding, S3=0 in v1).
	packets := readPackets(mockServer, 3*time.Second, 3)
	if len(packets) < 1 {
		t.Fatal("no cookie packet at server")
	}

	pkt := packets[0]
	if len(pkt) != WgCookieReplySize {
		t.Fatalf("cookie size %d, expected %d", len(pkt), WgCookieReplySize)
	}
	gotType := binary.LittleEndian.Uint32(pkt[:4])
	if !cfg.H3.Contains(gotType) {
		t.Fatalf("cookie type %d, expected H3=%d", gotType, cfg.H3.Min)
	}
	for i := 4; i < WgCookieReplySize; i++ {
		if pkt[i] != savedCookie[i] {
			t.Fatalf("cookie byte %d mismatch", i)
		}
	}

	t.Log("outbound cookie reply transformed correctly")
}

// TestProxyLargeTransportPacket verifies near-MTU transport packets
// are handled correctly in both directions.
func TestProxyLargeTransportPacket(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	proxyRemoteAddr := establishSession(t, cfg, clientConn, mockServer)

	// Outbound: 1400-byte transport packet (near MTU).
	bigPkt := makeWGPacket(wgTransportData, 1400)
	savedPayload := make([]byte, 1400)
	copy(savedPayload, bigPkt)

	if _, err := clientConn.Write(bigPkt); err != nil {
		t.Fatal("write large transport: ", err)
	}

	packets := readPackets(mockServer, 3*time.Second, 3)
	if len(packets) < 1 {
		t.Fatal("no large transport at server")
	}
	if len(packets[0]) != 1400 {
		t.Fatalf("outbound: size %d, expected 1400", len(packets[0]))
	}
	if !cfg.H4.Contains(binary.LittleEndian.Uint32(packets[0][:4])) {
		t.Fatal("outbound: type mismatch")
	}
	for i := 4; i < 1400; i++ {
		if packets[0][i] != savedPayload[i] {
			t.Fatalf("outbound: byte %d mismatch", i)
		}
	}

	// Inbound: 1400-byte transport from server.
	bigInbound := make([]byte, 1400)
	binary.LittleEndian.PutUint32(bigInbound[:4], cfg.H4.Min)
	for i := 4; i < 1400; i++ {
		bigInbound[i] = byte(i*3 + 7)
	}

	if _, err := mockServer.WriteToUDP(bigInbound, proxyRemoteAddr); err != nil {
		t.Fatal("write large inbound: ", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatal("read large inbound: ", err)
	}
	if n != 1400 {
		t.Fatalf("inbound: size %d, expected 1400", n)
	}
	if binary.LittleEndian.Uint32(buf[:4]) != wgTransportData {
		t.Fatal("inbound: type mismatch")
	}
	for i := 4; i < 1400; i++ {
		if buf[i] != byte(i*3+7) {
			t.Fatalf("inbound: byte %d mismatch", i)
		}
	}

	t.Log("1400-byte transport packets handled correctly both ways")
}

// TestProxyV2PaddedTransport verifies v2 config with S4>0 works correctly:
// outbound transport gets S4 padding, inbound has it stripped.
func TestProxyV2PaddedTransport(t *testing.T) {
	cfg := v2Config()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	proxyRemoteAddr := establishSession(t, cfg, clientConn, mockServer)

	// Outbound: client sends 80-byte transport (type=4).
	transport := makeWGPacket(wgTransportData, 80)
	savedPayload := make([]byte, 80)
	copy(savedPayload, transport)

	if _, err := clientConn.Write(transport); err != nil {
		t.Fatal("write transport: ", err)
	}

	serverPkts := readPackets(mockServer, 3*time.Second, 3)
	if len(serverPkts) < 1 {
		t.Fatal("no transport at server")
	}

	pkt := serverPkts[0]
	expectedSize := cfg.S4 + 80
	if len(pkt) != expectedSize {
		t.Fatalf("outbound: size %d, expected S4(%d)+80=%d", len(pkt), cfg.S4, expectedSize)
	}

	// H4 type should be at offset S4.
	gotType := binary.LittleEndian.Uint32(pkt[cfg.S4 : cfg.S4+4])
	if !cfg.H4.Contains(gotType) {
		t.Fatalf("outbound: type %d at offset %d, expected H4=%d", gotType, cfg.S4, cfg.H4.Min)
	}
	for i := 4; i < 80; i++ {
		if pkt[cfg.S4+i] != savedPayload[i] {
			t.Fatalf("outbound: byte %d mismatch", i)
		}
	}

	// Inbound: server sends S4-padded transport.
	transportIn := make([]byte, cfg.S4+100)
	randFill(transportIn[:cfg.S4])
	binary.LittleEndian.PutUint32(transportIn[cfg.S4:cfg.S4+4], cfg.H4.Min)
	for i := 4; i < 100; i++ {
		transportIn[cfg.S4+i] = byte(i + 33)
	}

	if _, err := mockServer.WriteToUDP(transportIn, proxyRemoteAddr); err != nil {
		t.Fatal("write inbound transport: ", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatal("read inbound transport: ", err)
	}

	if n != 100 {
		t.Fatalf("inbound: size %d, expected 100 (S4 stripped)", n)
	}
	if binary.LittleEndian.Uint32(buf[:4]) != wgTransportData {
		t.Fatalf("inbound: type %d, expected %d", binary.LittleEndian.Uint32(buf[:4]), wgTransportData)
	}
	for i := 4; i < 100; i++ {
		if buf[i] != byte(i+33) {
			t.Fatalf("inbound: byte %d mismatch", i)
		}
	}

	t.Log("v2 S4-padded transport works correctly both directions")
}

// TestProxyV2PaddedCookie verifies v2 config with S3>0 for cookie replies:
// inbound cookie with S3 padding is stripped correctly.
func TestProxyV2PaddedCookie(t *testing.T) {
	cfg := v2Config()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	proxyRemoteAddr := establishSession(t, cfg, clientConn, mockServer)

	// Server sends S3-padded cookie reply.
	cookiePkt := make([]byte, cfg.S3+WgCookieReplySize)
	randFill(cookiePkt[:cfg.S3])
	binary.LittleEndian.PutUint32(cookiePkt[cfg.S3:cfg.S3+4], cfg.H3.Min)
	for i := 4; i < WgCookieReplySize; i++ {
		cookiePkt[cfg.S3+i] = byte(i + 111)
	}

	if _, err := mockServer.WriteToUDP(cookiePkt, proxyRemoteAddr); err != nil {
		t.Fatal("write cookie: ", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatal("read cookie: ", err)
	}

	if n != WgCookieReplySize {
		t.Fatalf("cookie size %d, expected %d", n, WgCookieReplySize)
	}
	if binary.LittleEndian.Uint32(buf[:4]) != wgCookieReply {
		t.Fatalf("cookie type %d, expected %d", binary.LittleEndian.Uint32(buf[:4]), wgCookieReply)
	}
	for i := 4; i < WgCookieReplySize; i++ {
		if buf[i] != byte(i+111) {
			t.Fatalf("cookie byte %d mismatch", i)
		}
	}

	t.Log("v2 S3-padded cookie reply forwarded correctly")
}

// TestProxyV2HandshakeS1S2 verifies v2 init/response with custom S1/S2
// padding through the proxy.
func TestProxyV2HandshakeS1S2(t *testing.T) {
	cfg := v2Config()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Send handshake init.
	initPkt := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	savedInit := make([]byte, WgHandshakeInitSize)
	copy(savedInit, initPkt)

	if _, err := clientConn.Write(initPkt); err != nil {
		t.Fatal("write init: ", err)
	}

	serverPkts, proxyRemoteAddr := readPacketsWithAddr(mockServer, 3*time.Second, cfg.Jc+2)
	if len(serverPkts) < cfg.Jc+1 {
		t.Fatalf("expected >= %d packets, got %d", cfg.Jc+1, len(serverPkts))
	}

	// Verify init: S1 padding + H1 type.
	hsInit := serverPkts[cfg.Jc]
	if len(hsInit) != cfg.S1+WgHandshakeInitSize {
		t.Fatalf("init size %d, expected %d", len(hsInit), cfg.S1+WgHandshakeInitSize)
	}
	if !cfg.H1.Contains(binary.LittleEndian.Uint32(hsInit[cfg.S1 : cfg.S1+4])) {
		t.Fatal("init: H1 type mismatch")
	}
	for i := 4; i < WgHandshakeInitSize; i++ {
		if hsInit[cfg.S1+i] != savedInit[i] {
			t.Fatalf("init byte %d mismatch", i)
		}
	}

	// Server sends S2-padded response.
	innerResp := make([]byte, WgHandshakeResponseSize)
	binary.LittleEndian.PutUint32(innerResp[:4], cfg.H2.Min)
	for i := 4; i < WgHandshakeResponseSize; i++ {
		innerResp[i] = byte(i + 88)
	}

	awgResp := make([]byte, cfg.S2+WgHandshakeResponseSize)
	randFill(awgResp[:cfg.S2])
	copy(awgResp[cfg.S2:], innerResp)

	if _, err := mockServer.WriteToUDP(awgResp, proxyRemoteAddr); err != nil {
		t.Fatal("write response: ", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatal("read response: ", err)
	}

	if n != WgHandshakeResponseSize {
		t.Fatalf("response size %d, expected %d", n, WgHandshakeResponseSize)
	}
	if binary.LittleEndian.Uint32(buf[:4]) != wgHandshakeResponse {
		t.Fatalf("response type mismatch")
	}
	for i := 4; i < WgHandshakeResponseSize; i++ {
		if buf[i] != byte(i+88) {
			t.Fatalf("response byte %d mismatch", i)
		}
	}

	t.Log("v2 S1/S2 handshake through proxy works correctly")
}

// TestProxyGracefulShutdown verifies the proxy shuts down cleanly
// without panic or hang after processing some traffic.
func TestProxyGracefulShutdown(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

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

	proxy := NewProxy(cfg, proxyAddr, mockAddr)
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		proxy.Run(stop)
	}()

	time.Sleep(50 * time.Millisecond)

	// Generate some traffic.
	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	for i := 0; i < 5; i++ {
		pkt := makeWGPacket(wgTransportData, 100)
		clientConn.Write(pkt)
	}
	clientConn.Close()

	time.Sleep(100 * time.Millisecond)

	// Trigger shutdown.
	close(stop)

	select {
	case <-done:
		t.Log("proxy shut down gracefully")
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not shut down within 3 seconds")
	}
}

// startProxyWildcard starts the proxy with wildcard listen addr ":0" (nil IP),
// reproducing production AWG_LISTEN=:51820 behavior.
func startProxyWildcard(t *testing.T, cfg *Config, remoteAddr *net.UDPAddr) (*net.UDPAddr, func()) {
	t.Helper()

	listenAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatal("resolve wildcard addr: ", err)
	}

	// Pre-bind to discover port, then close and let the proxy use it.
	tmpConn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		t.Fatal("tmp listen wildcard: ", err)
	}
	actualPort := tmpConn.LocalAddr().(*net.UDPAddr).Port
	tmpConn.Close()
	time.Sleep(10 * time.Millisecond)

	// Use nil IP (wildcard) for proxy listen address.
	proxyListenAddr := &net.UDPAddr{Port: actualPort}

	proxy := NewProxy(cfg, proxyListenAddr, remoteAddr)
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		proxy.Run(stop)
	}()

	time.Sleep(50 * time.Millisecond)

	// Client connects to 127.0.0.1:<port>.
	proxyAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: actualPort}

	cleanup := func() {
		close(stop)
		<-done
	}

	return proxyAddr, cleanup
}

// TestProxyListenWildcardAddr is a regression test for dual-stack socket issues.
// When proxy listens on ":0" (nil IP, like production AWG_LISTEN=:51820),
// Go creates an AF_INET6 dual-stack socket on Linux. Without the "udp4" fix,
// recvmmsg returns AF_INET6 sockaddrs which don't match the AF_INET check,
// causing clientAddr to never be set and all server responses to be dropped.
func TestProxyListenWildcardAddr(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxyWildcard(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Phase 1: Handshake init (client -> proxy -> server).
	initPayload := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	if _, err := clientConn.Write(initPayload); err != nil {
		t.Fatal("write init: ", err)
	}

	serverPkts, proxyRemoteAddr := readPacketsWithAddr(mockServer, 3*time.Second, cfg.Jc+2)
	if len(serverPkts) < cfg.Jc+1 {
		t.Fatalf("phase1: expected >= %d packets, got %d", cfg.Jc+1, len(serverPkts))
	}

	// Phase 2: Handshake response (server -> proxy -> client).
	innerResp := make([]byte, WgHandshakeResponseSize)
	binary.LittleEndian.PutUint32(innerResp[:4], cfg.H2.Min)
	for i := 4; i < WgHandshakeResponseSize; i++ {
		innerResp[i] = byte(i + 50)
	}

	awgResp := make([]byte, cfg.S2+WgHandshakeResponseSize)
	randFill(awgResp[:cfg.S2])
	copy(awgResp[cfg.S2:], innerResp)

	if _, err := mockServer.WriteToUDP(awgResp, proxyRemoteAddr); err != nil {
		t.Fatal("write response: ", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, 1500)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatal("read response: ", err, " -- clientAddr was likely never set (dual-stack bug)")
	}
	if n != WgHandshakeResponseSize {
		t.Fatalf("phase2: size %d, expected %d", n, WgHandshakeResponseSize)
	}
	if binary.LittleEndian.Uint32(respBuf[:4]) != wgHandshakeResponse {
		t.Fatalf("phase2: type %d, expected %d", binary.LittleEndian.Uint32(respBuf[:4]), wgHandshakeResponse)
	}

	t.Log("wildcard listen addr: handshake roundtrip passed (dual-stack regression OK)")
}

// TestProxyMixedTraffic sends a mix of packet types (init, transport,
// cookie) and verifies each is transformed correctly.
func TestProxyMixedTraffic(t *testing.T) {
	cfg := proxyTestConfig()

	mockServer := startMockServer(t)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startProxy(t, cfg, mockAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Establish session.
	_ = establishSession(t, cfg, clientConn, mockServer)

	// Send a sequence: transport, cookie, transport, transport, cookie.
	type pktSpec struct {
		msgType uint32
		size    int
		hRange  HRange
	}
	specs := []pktSpec{
		{wgTransportData, 100, cfg.H4},
		{wgCookieReply, WgCookieReplySize, cfg.H3},
		{wgTransportData, 200, cfg.H4},
		{wgTransportData, 64, cfg.H4},
		{wgCookieReply, WgCookieReplySize, cfg.H3},
	}

	for i, spec := range specs {
		pkt := makeWGPacket(spec.msgType, spec.size)
		if _, err := clientConn.Write(pkt); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	received := readPackets(mockServer, 5*time.Second, len(specs))
	if len(received) < len(specs) {
		t.Fatalf("received %d/%d packets", len(received), len(specs))
	}

	for i, spec := range specs {
		pkt := received[i]
		if len(pkt) != spec.size {
			t.Fatalf("packet %d: size %d, expected %d", i, len(pkt), spec.size)
		}
		gotType := binary.LittleEndian.Uint32(pkt[:4])
		if !spec.hRange.Contains(gotType) {
			t.Fatalf("packet %d: type %d not in expected H range [%d,%d]",
				i, gotType, spec.hRange.Min, spec.hRange.Max)
		}
	}

	t.Logf("mixed traffic: all %d packets transformed correctly", len(specs))
}
