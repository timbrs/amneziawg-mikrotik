package awg

import (
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const bufSize = 1500 // standard MTU

const defaultSocketBuf = 16 * 1024 * 1024 // 16 MB request; kernel clamps to rmem_max

// SocketBufSize is the requested socket buffer size (configurable via AWG_SOCKET_BUF).
var SocketBufSize = defaultSocketBuf

// Proxy is a UDP proxy that transforms WireGuard packets to AmneziaWG format.
type Proxy struct {
	cfg        *Config
	listenAddr *net.UDPAddr
	remoteAddr *net.UDPAddr
	clientAddr atomic.Pointer[netip.AddrPort]
	remoteConn atomic.Pointer[net.UDPConn]
	stopped    atomic.Bool
	lastActive atomic.Bool // activity flag; set on recv, cleared by timeout checker
	cpsCounter uint32      // counter for CPS <c> tags
	junkBuf    []byte      // pre-allocated: Jc * Jmax bytes for junk generation
	junkPkts   [][]byte    // pre-allocated: Jc slice headers for junk packets
}

// NewProxy creates a new Proxy instance.
func NewProxy(cfg *Config, listenAddr, remoteAddr *net.UDPAddr) *Proxy {
	p := &Proxy{
		cfg:        cfg,
		listenAddr: listenAddr,
		remoteAddr: remoteAddr,
	}
	if cfg.Jc > 0 && cfg.Jmax > 0 {
		p.junkBuf = make([]byte, cfg.Jc*cfg.Jmax)
		p.junkPkts = make([][]byte, cfg.Jc)
	}
	return p
}

// generateJunk fills pre-allocated junk buffers with random data and returns
// slices of random sizes in [Jmin, Jmax]. Zero allocations per call.
func (p *Proxy) generateJunk() [][]byte {
	if p.cfg.Jc <= 0 || p.cfg.Jmax <= 0 {
		return nil
	}
	jmin := p.cfg.Jmin
	if jmin <= 0 {
		jmin = 1
	}
	jmax := p.cfg.Jmax
	if jmax < jmin {
		jmax = jmin
	}
	randFill(p.junkBuf)
	off := 0
	for i := 0; i < p.cfg.Jc; i++ {
		size := jmin
		if jmax > jmin {
			size = jmin + rand.IntN(jmax-jmin+1)
		}
		p.junkPkts[i] = p.junkBuf[off : off+size]
		off += size
	}
	return p.junkPkts[:p.cfg.Jc]
}

func setSocketBuffers(conn *net.UDPConn, size int) {
	conn.SetReadBuffer(size)
	conn.SetWriteBuffer(size)
}

func setSocketBuffersLog(conn *net.UDPConn, size int, cfg *Config, label string) {
	conn.SetReadBuffer(size)
	conn.SetWriteBuffer(size)
	if cfg.LogLevel >= LevelDebug {
		actualR, actualW := getSocketBufSizes(conn)
		LogDebug(cfg, label, " socket buf: requested=", strconv.Itoa(size/1024), "KB, actual read=", strconv.Itoa(actualR/1024), "KB write=", strconv.Itoa(actualW/1024), "KB")
	}
}

// Run starts the proxy and blocks until stop is called or a fatal error occurs.
// The stop channel is closed to signal shutdown.
func (p *Proxy) Run(stop <-chan struct{}) error {
	listenConn, err := net.ListenUDP("udp4", p.listenAddr)
	if err != nil {
		return err
	}
	defer listenConn.Close()
	setSocketBuffersLog(listenConn, SocketBufSize, p.cfg, "listen")

	remoteConn, err := net.DialUDP("udp4", nil, p.remoteAddr)
	if err != nil {
		return err
	}
	setSocketBuffersLog(remoteConn, SocketBufSize, p.cfg, "remote")

	p.remoteConn.Store(remoteConn)
	p.lastActive.Store(true)

	timeout := time.Duration(p.cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 180 * time.Second
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Stop handler: close connections to unblock read goroutines.
	go func() {
		defer wg.Done()
		<-stop
		p.stopped.Store(true)
		listenConn.Close()
		if rc := p.remoteConn.Load(); rc != nil {
			rc.Close()
		}
	}()

	// Timeout checker: periodically check for inactivity and trigger reconnect.
	go func() {
		const checkInterval = 5 * time.Second
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()
		checksNeeded := int(timeout / checkInterval)
		if checksNeeded < 1 {
			checksNeeded = 1
		}
		inactiveCount := 0
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if p.lastActive.CompareAndSwap(true, false) {
					inactiveCount = 0
				} else {
					inactiveCount++
					if inactiveCount >= checksNeeded {
						LogInfo(p.cfg, "remote timeout, triggering reconnect")
						if rc := p.remoteConn.Load(); rc != nil {
							rc.Close()
						}
						inactiveCount = 0
					}
				}
			}
		}
	}()

	useBatch := batchAvailable()
	if useBatch {
		LogDebug(p.cfg, "batch I/O: enabled (recvmmsg/sendmmsg)")
	} else {
		LogDebug(p.cfg, "batch I/O: unavailable, using single-packet mode")
	}

	go func() {
		defer wg.Done()
		if useBatch {
			p.clientToServerBatch(listenConn)
		} else {
			p.clientToServer(listenConn)
		}
	}()

	go func() {
		defer wg.Done()
		if useBatch {
			p.serverToClientBatch(listenConn, remoteConn, stop)
		} else {
			p.serverToClient(listenConn, remoteConn, stop)
		}
	}()

	wg.Wait()
	if rc := p.remoteConn.Load(); rc != nil {
		rc.Close()
	}
	return nil
}

func (p *Proxy) clientToServer(listenConn *net.UDPConn) {
	runtime.LockOSThread()
	prefix := p.cfg.S4
	buf := make([]byte, prefix+bufSize)

	for {
		n, addr, err := listenConn.ReadFromUDPAddrPort(buf[prefix : prefix+bufSize])
		if err != nil {
			if p.stopped.Load() || isClosedErr(err) {
				return
			}
			LogError(p.cfg, "listen read: ", err.Error())
			continue
		}
		p.lastActive.Store(true)

		// Update client address.
		if cur := p.clientAddr.Load(); cur == nil || *cur != addr {
			a := addr
			p.clientAddr.Store(&a)
			LogInfo(p.cfg, "client: ", addr.String())
		}

		currentRemote := p.remoteConn.Load()
		out, sendJunk := TransformOutbound(buf, prefix, n, p.cfg)

		if p.cfg.LogLevel >= LevelDebug {
			LogDebug(p.cfg, "c->s: recv ", strconv.Itoa(n), "B, send ", strconv.Itoa(len(out)), "B, junk=", strconv.FormatBool(sendJunk))
		}

		if sendJunk {
			LogDebug(p.cfg, "c->s: handshake init ", strconv.Itoa(n), "B -> ", strconv.Itoa(len(out)), "B")
			// CPS packets (I1->I2->I3->I4->I5).
			cpsPackets := GenerateCPSPackets(p.cfg.CPS, &p.cpsCounter)
			for ci, pkt := range cpsPackets {
				if _, err := currentRemote.Write(pkt); err != nil {
					if p.cfg.LogLevel >= LevelDebug {
						LogDebug(p.cfg, "c->s: cps ", strconv.Itoa(ci), " write err: ", err.Error())
					}
					break
				}
				if p.cfg.LogLevel >= LevelDebug {
					LogDebug(p.cfg, "c->s: cps ", strconv.Itoa(ci+1), "/", strconv.Itoa(len(cpsPackets)), " ", strconv.Itoa(len(pkt)), "B sent")
				}
			}
			// Junk packets (zero-alloc, pre-allocated buffers).
			junkPackets := p.generateJunk()
			for i, junk := range junkPackets {
				if _, err := currentRemote.Write(junk); err != nil {
					if p.cfg.LogLevel >= LevelDebug {
						LogDebug(p.cfg, "c->s: junk ", strconv.Itoa(i), " write err: ", err.Error())
					}
					break // connection likely closed during reconnect
				}
				if p.cfg.LogLevel >= LevelDebug {
					LogDebug(p.cfg, "c->s: junk ", strconv.Itoa(i+1), "/", strconv.Itoa(len(junkPackets)), " ", strconv.Itoa(len(junk)), "B sent")
				}
			}
		}

		_, err = currentRemote.Write(out)
		if err != nil {
			if isClosedErr(err) {
				continue // reconnect in progress, WG will retransmit
			}
			LogError(p.cfg, "remote write: ", err.Error())
		} else if p.cfg.LogLevel >= LevelDebug {
			LogDebug(p.cfg, "c->s: transformed ", strconv.Itoa(len(out)), "B sent to server")
		}
	}
}

func (p *Proxy) serverToClient(listenConn *net.UDPConn, remoteConn *net.UDPConn, stop <-chan struct{}) {
	runtime.LockOSThread()
	buf := make([]byte, bufSize)
	currentRemote := remoteConn
	backoff := time.Second
	var pktCount uint8 = 255

	for {
		n, err := currentRemote.Read(buf)
		if err != nil {
			if p.stopped.Load() {
				return
			}
			LogInfo(p.cfg, "remote: ", err.Error(), ", reconnecting")
			newConn := p.reconnectRemote(stop, &backoff)
			if newConn == nil {
				return // shutdown
			}
			currentRemote.Close()
			currentRemote = newConn
			p.remoteConn.Store(newConn)
			setSocketBuffers(newConn, SocketBufSize)
			p.lastActive.Store(true)
			p.clientAddr.Store(nil)
			pktCount = 255
			if p.stopped.Load() {
				newConn.Close()
				return
			}
			continue
		}

		pktCount++
		if pktCount == 0 {
			p.lastActive.Store(true)
		}
		backoff = time.Second // reset backoff on success

		if p.cfg.LogLevel >= LevelDebug {
			LogDebug(p.cfg, "s->c: recv ", strconv.Itoa(n), "B from server")
		}

		out, valid := TransformInbound(buf, n, p.cfg)
		if !valid {
			if p.cfg.LogLevel >= LevelDebug {
				LogDebug(p.cfg, "s->c: invalid/junk packet ", strconv.Itoa(n), "B, dropped")
			}
			continue
		}

		hsIn := len(out) >= 4 && out[0] != byte(wgTransportData)

		if p.cfg.LogLevel >= LevelDebug {
			LogDebug(p.cfg, "s->c: transformed ", strconv.Itoa(len(out)), "B, valid=true")
		}

		clientAddr := p.clientAddr.Load()
		if clientAddr != nil {
			_, err = listenConn.WriteToUDPAddrPort(out, *clientAddr)
			if err != nil {
				LogError(p.cfg, "listen write: ", err.Error())
			} else if hsIn && p.cfg.LogLevel >= LevelDebug {
				LogDebug(p.cfg, "s->c: handshake ", strconv.Itoa(n), "B -> ", strconv.Itoa(len(out)), "B, forwarded to ", clientAddr.String())
			} else if p.cfg.LogLevel >= LevelDebug {
				LogDebug(p.cfg, "s->c: sent ", strconv.Itoa(len(out)), "B to ", clientAddr.String())
			}
		} else if hsIn {
			LogInfo(p.cfg, "s->c: handshake ", strconv.Itoa(n), "B -> ", strconv.Itoa(len(out)), "B, no client addr!")
		} else if p.cfg.LogLevel >= LevelDebug {
			LogDebug(p.cfg, "s->c: no client addr, packet dropped")
		}
	}
}

// reconnectRemote attempts to reconnect to the remote AWG server with exponential backoff.
func (p *Proxy) reconnectRemote(stop <-chan struct{}, backoff *time.Duration) *net.UDPConn {
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-stop:
			return nil
		default:
		}

		LogInfo(p.cfg, "reconnecting to ", p.remoteAddr.String())

		// Re-resolve the address (handles DNS changes).
		addr, err := net.ResolveUDPAddr("udp4", p.remoteAddr.String())
		if err != nil {
			LogError(p.cfg, "resolve: ", err.Error())
		} else {
			conn, err := net.DialUDP("udp4", nil, addr)
			if err == nil {
				LogInfo(p.cfg, "reconnected to ", addr.String())
				p.lastActive.Store(true)
				*backoff = time.Second
				return conn
			}
			LogError(p.cfg, "dial: ", err.Error())
		}

		// Wait with backoff.
		timer := time.NewTimer(*backoff)
		select {
		case <-stop:
			timer.Stop()
			return nil
		case <-timer.C:
		}

		*backoff *= 2
		if *backoff > maxBackoff {
			*backoff = maxBackoff
		}
	}
}

func isClosedErr(err error) bool {
	if err == net.ErrClosed {
		return true
	}
	if errno, ok := err.(syscall.Errno); ok && errno == syscall.EBADF {
		return true
	}
	return isClosedErrString(err)
}

func isClosedErrString(err error) bool {
	s := err.Error()
	for i := 0; i+len("use of closed") <= len(s); i++ {
		if s[i:i+len("use of closed")] == "use of closed" {
			return true
		}
	}
	return false
}

// Logging helpers — write directly to stdout, no fmt/log dependency.

func LogInfo(cfg *Config, parts ...string) {
	if cfg.LogLevel < LevelInfo {
		return
	}
	writeLog("INFO: ", parts)
}

func LogError(cfg *Config, parts ...string) {
	if cfg.LogLevel < LevelError {
		return
	}
	writeLog("ERROR: ", parts)
}

func LogDebug(cfg *Config, parts ...string) {
	if cfg.LogLevel < LevelDebug {
		return
	}
	writeLog("DEBUG: ", parts)
}

func writeLog(prefix string, parts []string) {
	io.WriteString(os.Stderr, prefix)
	for _, s := range parts {
		io.WriteString(os.Stderr, s)
	}
	io.WriteString(os.Stderr, "\n")
}
