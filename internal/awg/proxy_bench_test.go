package awg

import (
	"encoding/binary"
	"net"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// --- Helpers ---

// benchConfig returns a synthetic config with logging disabled for benchmarks.
func benchConfig() *Config {
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
		LogLevel: LevelNone,
	}
	cfg.ComputeFastPath()
	return cfg
}

// startBenchProxy starts the proxy for benchmarks and returns its listen address
// and a cleanup function. Uses the same bind-discover-close-rebind pattern.
func startBenchProxy(b *testing.B, cfg *Config, remoteAddr *net.UDPAddr) (*net.UDPAddr, func()) {
	b.Helper()

	listenAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal("resolve listen addr: ", err)
	}

	tmpConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		b.Fatal("tmp listen: ", err)
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

	return proxyAddr, cleanup
}

// startSinkServer starts a UDP listener that reads and discards all incoming packets.
func startSinkServer(b *testing.B) *net.UDPConn {
	b.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal("resolve sink addr: ", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		b.Fatal("listen sink: ", err)
	}

	go func() {
		buf := make([]byte, 2048)
		for {
			_, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
		}
	}()

	return conn
}

// startBenchMockServer creates a UDP listener without any reader goroutine.
func startBenchMockServer(b *testing.B) *net.UDPConn {
	b.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal("resolve mock addr: ", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		b.Fatal("listen mock: ", err)
	}
	return conn
}

// establishBenchSessionSink sends a handshake init and waits for the proxy to process it.
// Use when the server has a sink goroutine that consumes packets (no drain needed).
func establishBenchSessionSink(b *testing.B, clientConn *net.UDPConn) {
	b.Helper()
	initPacket := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	if _, err := clientConn.Write(initPacket); err != nil {
		b.Fatal("establish: write init: ", err)
	}
	time.Sleep(100 * time.Millisecond)
}

// establishBenchSessionDrain sends a handshake init and drains all transformed packets
// from the mock server. Use when no goroutine is reading from mockServer.
func establishBenchSessionDrain(b *testing.B, cfg *Config, clientConn *net.UDPConn, mockServer *net.UDPConn) {
	b.Helper()
	initPacket := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	if _, err := clientConn.Write(initPacket); err != nil {
		b.Fatal("establish: write init: ", err)
	}
	mockServer.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	for i := 0; i < cfg.Jc+2; i++ {
		if _, _, err := mockServer.ReadFromUDP(buf); err != nil {
			break
		}
	}
	mockServer.SetReadDeadline(time.Time{})
}

// makeTransportPacket creates a WireGuard transport data packet of the given size.
func makeTransportPacket(size int) []byte {
	buf := make([]byte, size)
	binary.LittleEndian.PutUint32(buf[:4], wgTransportData)
	for i := 4; i < size; i++ {
		buf[i] = byte(i)
	}
	return buf
}

// --- A. End-to-end throughput ---

func BenchmarkProxyThroughput(b *testing.B) {
	sizes := []int{100, 500, 1400}
	for _, size := range sizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			cfg := benchConfig()
			sink := startSinkServer(b)
			defer sink.Close()
			sinkAddr := sink.LocalAddr().(*net.UDPAddr)

			proxyAddr, stopProxy := startBenchProxy(b, cfg, sinkAddr)
			defer stopProxy()

			clientConn, err := net.DialUDP("udp", nil, proxyAddr)
			if err != nil {
				b.Fatal("dial: ", err)
			}
			defer clientConn.Close()

			establishBenchSessionSink(b, clientConn)

			pkt := makeTransportPacket(size)
			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				binary.LittleEndian.PutUint32(pkt[:4], wgTransportData)
				if _, err := clientConn.Write(pkt); err != nil {
					b.Fatal("write: ", err)
				}
			}

			b.StopTimer()
			elapsed := b.Elapsed()
			if elapsed > 0 {
				pps := float64(b.N) / elapsed.Seconds()
				b.ReportMetric(pps, "pkt/s")
			}
		})
	}
}

// --- B. Latency ---

// latencyBatchSize is the number of roundtrips per timing batch.
// Batch measurement avoids zero-duration reads caused by multi-core pipelining
// where the proxy+echo roundtrip completes within a single Write syscall.
const latencyBatchSize = 50

func BenchmarkProxyLatency(b *testing.B) {
	sizes := []int{100, 500, 1400}
	for _, size := range sizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			cfg := benchConfig()

			// Create a plain mock server (no goroutine) to establish session cleanly.
			mockServer := startBenchMockServer(b)
			defer mockServer.Close()
			mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

			proxyAddr, stopProxy := startBenchProxy(b, cfg, mockAddr)
			defer stopProxy()

			clientConn, err := net.DialUDP("udp", nil, proxyAddr)
			if err != nil {
				b.Fatal("dial: ", err)
			}
			defer clientConn.Close()

			// Establish session: drain at server (no racing goroutine).
			establishBenchSessionDrain(b, cfg, clientConn, mockServer)

			// Now start the echo goroutine.
			go func() {
				buf := make([]byte, 2048)
				for {
					n, raddr, err := mockServer.ReadFromUDP(buf)
					if err != nil {
						return
					}
					mockServer.WriteToUDP(buf[:n], raddr)
				}
			}()

			pkt := makeTransportPacket(size)
			recvBuf := make([]byte, 2048)

			// Warmup.
			clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			for i := 0; i < 10; i++ {
				binary.LittleEndian.PutUint32(pkt[:4], wgTransportData)
				clientConn.Write(pkt)
				clientConn.Read(recvBuf)
			}

			// Collect per-batch average latencies. Each batch does latencyBatchSize
			// roundtrips and records the average per-packet time.
			maxBatches := b.N/latencyBatchSize + 1
			batchLatencies := make([]int64, 0, maxBatches)
			received := 0

			clientConn.SetReadDeadline(time.Now().Add(time.Minute))

			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; {
				count := latencyBatchSize
				if i+count > b.N {
					count = b.N - i
				}

				start := time.Now()
				ok := true
				for j := 0; j < count; j++ {
					binary.LittleEndian.PutUint32(pkt[:4], wgTransportData)
					if _, werr := clientConn.Write(pkt); werr != nil {
						ok = false
						break
					}
					if _, rerr := clientConn.Read(recvBuf); rerr != nil {
						ok = false
						break
					}
				}
				batchNs := time.Since(start).Nanoseconds()

				if ok {
					perPkt := batchNs / int64(count)
					batchLatencies = append(batchLatencies, perPkt)
					received += count
				}
				i += count
			}

			b.StopTimer()

			if len(batchLatencies) > 0 {
				sort.Slice(batchLatencies, func(i, j int) bool { return batchLatencies[i] < batchLatencies[j] })
				p50 := batchLatencies[len(batchLatencies)*50/100]
				p95 := batchLatencies[len(batchLatencies)*95/100]
				p99 := batchLatencies[len(batchLatencies)*99/100]
				b.ReportMetric(float64(p50)/1e3, "p50-us")
				b.ReportMetric(float64(p95)/1e3, "p95-us")
				b.ReportMetric(float64(p99)/1e3, "p99-us")
			}

			if b.N > 0 {
				deliveryPct := float64(received) / float64(b.N) * 100
				b.ReportMetric(deliveryPct, "delivery-%")
			}
		})
	}
}

// --- C. Baseline benchmarks ---

func BenchmarkBaselineUDPWrite(b *testing.B) {
	sink := startSinkServer(b)
	defer sink.Close()
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	conn, err := net.DialUDP("udp", nil, sinkAddr)
	if err != nil {
		b.Fatal("dial: ", err)
	}
	defer conn.Close()

	pkt := makeTransportPacket(1400)
	b.SetBytes(1400)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(pkt); err != nil {
			b.Fatal("write: ", err)
		}
	}

	b.StopTimer()
	elapsed := b.Elapsed()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed.Seconds(), "pkt/s")
	}
}

func BenchmarkBaselineUDPRoundtrip(b *testing.B) {
	mockServer := startBenchMockServer(b)
	defer mockServer.Close()
	mockAddr := mockServer.LocalAddr().(*net.UDPAddr)

	// Start echo goroutine.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := mockServer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mockServer.WriteToUDP(buf[:n], raddr)
		}
	}()

	conn, err := net.DialUDP("udp", nil, mockAddr)
	if err != nil {
		b.Fatal("dial: ", err)
	}
	defer conn.Close()

	pkt := makeTransportPacket(1400)
	recvBuf := make([]byte, 2048)
	conn.SetReadDeadline(time.Now().Add(time.Minute))
	b.SetBytes(1400)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(pkt); err != nil {
			b.Fatal("write: ", err)
		}
		if _, err := conn.Read(recvBuf); err != nil {
			b.Fatal("read: ", err)
		}
	}

	b.StopTimer()
	elapsed := b.Elapsed()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed.Seconds(), "roundtrip/s")
	}
}

func BenchmarkBaselineTransformAndWrite(b *testing.B) {
	sink := startSinkServer(b)
	defer sink.Close()
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	conn, err := net.DialUDP("udp", nil, sinkAddr)
	if err != nil {
		b.Fatal("dial: ", err)
	}
	defer conn.Close()

	cfg := benchConfig()
	pkt := makeTransportPacket(1400)
	b.SetBytes(1400)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint32(pkt[:4], wgTransportData)
		out, _ := TransformOutbound(pkt, 0, 1400, cfg)
		if _, err := conn.Write(out); err != nil {
			b.Fatal("write: ", err)
		}
	}

	b.StopTimer()
	elapsed := b.Elapsed()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed.Seconds(), "pkt/s")
	}
}

// --- D. Concurrency ---

func BenchmarkProxyConcurrent(b *testing.B) {
	counts := []int{1, 4, 8, 16}
	for _, numSenders := range counts {
		b.Run(strconv.Itoa(numSenders), func(b *testing.B) {
			cfg := benchConfig()
			sink := startSinkServer(b)
			defer sink.Close()
			sinkAddr := sink.LocalAddr().(*net.UDPAddr)

			proxyAddr, stopProxy := startBenchProxy(b, cfg, sinkAddr)
			defer stopProxy()

			// Create connections.
			conns := make([]*net.UDPConn, numSenders)
			for i := 0; i < numSenders; i++ {
				c, err := net.DialUDP("udp", nil, proxyAddr)
				if err != nil {
					b.Fatal("dial: ", err)
				}
				defer c.Close()
				conns[i] = c
			}

			// Establish session with the first connection.
			establishBenchSessionSink(b, conns[0])

			b.SetBytes(1400)
			b.ResetTimer()

			var connIdx atomic.Int32
			b.RunParallel(func(pb *testing.PB) {
				idx := int(connIdx.Add(1)-1) % numSenders
				conn := conns[idx]
				pkt := makeTransportPacket(1400)

				for pb.Next() {
					binary.LittleEndian.PutUint32(pkt[:4], wgTransportData)
					conn.Write(pkt)
				}
			})

			b.StopTimer()
			elapsed := b.Elapsed()
			if elapsed > 0 {
				b.ReportMetric(float64(b.N)/elapsed.Seconds(), "pkt/s")
			}
		})
	}
}

// --- E. Handshake burst ---

func BenchmarkProxyHandshakeBurst(b *testing.B) {
	cfg := benchConfig()
	sink := startSinkServer(b)
	defer sink.Close()
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startBenchProxy(b, cfg, sinkAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		b.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	// Establish initial session.
	establishBenchSessionSink(b, clientConn)

	pkt := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	b.SetBytes(WgHandshakeInitSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint32(pkt[:4], wgHandshakeInit)
		if _, err := clientConn.Write(pkt); err != nil {
			b.Fatal("write: ", err)
		}
	}

	b.StopTimer()
	elapsed := b.Elapsed()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed.Seconds(), "handshake/s")
	}
}

// benchConfigMAC1 returns a config with synthetic MAC1 keys for benchmarking.
func benchConfigMAC1() *Config {
	cfg := benchConfig()
	serverPub := make([]byte, 32)
	serverPub[0] = 1
	clientPub := make([]byte, 32)
	clientPub[0] = 2
	copy(cfg.ServerPub[:], serverPub)
	copy(cfg.ClientPub[:], clientPub)
	cfg.ComputeMAC1Keys()
	return cfg
}

func BenchmarkProxyHandshakeBurstMAC1(b *testing.B) {
	cfg := benchConfigMAC1()
	sink := startSinkServer(b)
	defer sink.Close()
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyAddr, stopProxy := startBenchProxy(b, cfg, sinkAddr)
	defer stopProxy()

	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		b.Fatal("dial: ", err)
	}
	defer clientConn.Close()

	establishBenchSessionSink(b, clientConn)

	pkt := makeWGPacket(wgHandshakeInit, WgHandshakeInitSize)
	b.SetBytes(WgHandshakeInitSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint32(pkt[:4], wgHandshakeInit)
		if _, err := clientConn.Write(pkt); err != nil {
			b.Fatal("write: ", err)
		}
	}

	b.StopTimer()
	elapsed := b.Elapsed()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed.Seconds(), "handshake/s")
	}
}
