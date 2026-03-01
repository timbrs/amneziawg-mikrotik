//go:build linux

package awg

import (
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const (
	batchSize    = 128
	msgWaitfirst = 0x10000 // MSG_WAITFORONE

	// UDP GRO/GSO constants.
	ipprotoUDP = 17
	udpGRO     = 104 // setsockopt to enable GRO
	udpSegment = 103 // cmsg type for segment size

	groRecvBufSize = 65536 // 64KB buffer for GRO coalesced receives
)

func batchAvailable() bool { return true }

// getSocketBufSizes returns actual read/write buffer sizes via getsockopt.
func getSocketBufSizes(conn *net.UDPConn) (r int, w int) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0
	}
	raw.Control(func(fd uintptr) {
		v, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if err == nil {
			r = v
		}
		v, err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		if err == nil {
			w = v
		}
	})
	return
}

// sockaddr_in is a raw IPv4 socket address (16 bytes).
type sockaddrIn struct {
	Family uint16
	Port   [2]byte // network byte order
	Addr   [4]byte
	_      [8]byte // padding to 16 bytes
}

const sockaddrInSize = 16

func addrPortToSockaddr(ap netip.AddrPort, sa *sockaddrIn) {
	sa.Family = syscall.AF_INET
	p := ap.Port()
	sa.Port[0] = byte(p >> 8)
	sa.Port[1] = byte(p)
	a := ap.Addr().As4()
	sa.Addr = a
}

func sockaddrToAddrPort(sa *sockaddrIn) netip.AddrPort {
	port := uint16(sa.Port[0])<<8 | uint16(sa.Port[1])
	return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port)
}

// batchState holds pre-allocated buffers for batch I/O on one direction.
type batchState struct {
	bufs   [batchSize][bufSize + 256]byte // extra room for S4 prefix
	iovecs [batchSize]iovec
	msgs   [batchSize]mmsghdr
	addrs  [batchSize]sockaddrIn
}

func (bs *batchState) initRecv(needAddr bool, offset int) {
	for i := range bs.msgs {
		bs.iovecs[i].Base = &bs.bufs[i][offset]
		setIovecLen(&bs.iovecs[i], uint64(len(bs.bufs[i])-offset))
		bs.msgs[i].Hdr.Iov = &bs.iovecs[i]
		setIovlen(&bs.msgs[i].Hdr, 1)
		if needAddr {
			bs.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&bs.addrs[i]))
			bs.msgs[i].Hdr.Namelen = sockaddrInSize
		}
	}
}

// initRecvFirstAddr sets up recv buffers with addr capture only for msg[0].
// Saves ~2KB/batch of kernel addr writes for msgs[1..N-1].
func (bs *batchState) initRecvFirstAddr(offset int) {
	for i := range bs.msgs {
		bs.iovecs[i].Base = &bs.bufs[i][offset]
		setIovecLen(&bs.iovecs[i], uint64(len(bs.bufs[i])-offset))
		bs.msgs[i].Hdr.Iov = &bs.iovecs[i]
		setIovlen(&bs.msgs[i].Hdr, 1)
	}
	bs.msgs[0].Hdr.Name = (*byte)(unsafe.Pointer(&bs.addrs[0]))
	bs.msgs[0].Hdr.Namelen = sockaddrInSize
}

func (bs *batchState) initSend(needAddr bool) {
	for i := range bs.msgs {
		bs.iovecs[i].Base = &bs.bufs[i][0]
		bs.msgs[i].Hdr.Iov = &bs.iovecs[i]
		setIovlen(&bs.msgs[i].Hdr, 1)
		if needAddr {
			bs.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&bs.addrs[i]))
			bs.msgs[i].Hdr.Namelen = sockaddrInSize
		}
	}
}

// sendState holds pre-allocated iovecs/msgs for send-only (no bufs).
// Used in c2s where transport fast-path points iovecs at recvBS.bufs (zero-copy).
type sendState struct {
	iovecs [batchSize]iovec
	msgs   [batchSize]mmsghdr
}

func (ss *sendState) init() {
	for i := range ss.msgs {
		ss.msgs[i].Hdr.Iov = &ss.iovecs[i]
		setIovlen(&ss.msgs[i].Hdr, 1)
	}
}

// dupBlockingFD extracts fd from UDPConn, duplicates it and sets to blocking mode.
// The caller owns the returned fd and must close it via syscall.Close.
func dupBlockingFD(conn *net.UDPConn) (int, error) {
	var fd int
	var dupErr error
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	raw.Control(func(f uintptr) {
		fd, dupErr = syscall.Dup(int(f))
	})
	if dupErr != nil {
		return -1, dupErr
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// recvBatchFD calls recvmmsg directly on a blocking fd (no Go poller overhead).
func recvBatchFD(fd int, bs *batchState) (int, error) {
	r, _, errno := syscall.Syscall6(
		sysRecvmmsg,
		uintptr(fd),
		uintptr(unsafe.Pointer(&bs.msgs[0])),
		uintptr(batchSize),
		uintptr(msgWaitfirst),
		0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// sendmmsgSlice calls sendmmsg on a slice of mmsghdr with retry for partial sends.
func sendmmsgSlice(fd int, msgs []mmsghdr) (int, error) {
	count := len(msgs)
	if count <= 0 {
		return 0, nil
	}
	total := 0
	for total < count {
		r, _, errno := syscall.Syscall6(
			sysSendmmsg,
			uintptr(fd),
			uintptr(unsafe.Pointer(&msgs[total])),
			uintptr(count-total),
			0, 0, 0,
		)
		if errno != 0 {
			return total, errno
		}
		total += int(r)
	}
	return total, nil
}

// sendSinglePacketFD sends a single packet via sendmmsg on a blocking fd.
// Zero-copy: points iovec directly at data (data must remain valid until return).
func sendSinglePacketFD(fd int, data []byte, ss *sendState) error {
	ss.iovecs[0].Base = &data[0]
	setIovecLen(&ss.iovecs[0], uint64(len(data)))
	_, err := sendmmsgSlice(fd, ss.msgs[:1])
	return err
}

// sendGSO sends a prefix of same-size packets via one sendmsg with UDP_SEGMENT (GSO).
// Returns number of packets sent. On ENOPROTOOPT/EIO returns (0, err) for fallback.
// addr may be nil for connected sockets.
func sendGSO(fd int, iovecs *[batchSize]iovec, count int, addr *sockaddrIn) (int, error) {
	if count <= 1 {
		return 0, nil
	}

	// Find longest prefix of same-size packets.
	segSize := int(iovecs[0].Len)
	gsoCount := 1
	for gsoCount < count && int(iovecs[gsoCount].Len) == segSize {
		gsoCount++
	}
	// Last segment may be shorter per GSO spec.
	if gsoCount < count && int(iovecs[gsoCount].Len) < segSize {
		gsoCount++
	}
	if gsoCount <= 1 {
		return 0, nil
	}

	// Build cmsg with UDP_SEGMENT = segSize.
	var cmsgBuf [32]byte
	hdrSize := cmsgAlignOf(int(unsafe.Sizeof(cmsghdr{})))
	cmsg := (*cmsghdr)(unsafe.Pointer(&cmsgBuf[0]))
	setCmsghdrLen(cmsg, hdrSize+2)
	cmsg.Level = ipprotoUDP
	cmsg.Type = udpSegment
	*(*uint16)(unsafe.Pointer(&cmsgBuf[hdrSize])) = uint16(segSize)

	// Build scatter-gather msghdr.
	var hdr msghdr
	hdr.Iov = &iovecs[0]
	setIovlen(&hdr, uint64(gsoCount))
	hdr.Control = &cmsgBuf[0]
	setControllen(&hdr, uint64(cmsgSpace(2)))
	if addr != nil {
		hdr.Name = (*byte)(unsafe.Pointer(addr))
		hdr.Namelen = sockaddrInSize
	}

	_, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&hdr)), 0)
	if errno != 0 {
		return 0, errno
	}
	return gsoCount, nil
}

// cmsgAlignOf aligns n to cmsg boundary (platform-specific).
func cmsgAlignOf(n int) int { return (n + cmsgAlign - 1) &^ (cmsgAlign - 1) }

// cmsgSpace returns space needed for a cmsg with given data length.
func cmsgSpace(datalen int) int {
	return cmsgAlignOf(int(unsafe.Sizeof(cmsghdr{}))) + cmsgAlignOf(datalen)
}

// enableGRO tries to enable UDP_GRO on a socket fd. Returns true on success.
func enableGRO(fd int) bool {
	return syscall.SetsockoptInt(fd, ipprotoUDP, udpGRO, 1) == nil
}

// groState holds buffers for GRO-enabled receives.
type groState struct {
	buf     [groRecvBufSize]byte
	iov     iovec
	hdr     msghdr
	cmsgBuf [32]byte // enough for cmsghdr + uint16 segment size
}

func (gs *groState) init() {
	gs.iov.Base = &gs.buf[0]
	setIovecLen(&gs.iov, groRecvBufSize)
	gs.hdr.Iov = &gs.iov
	setIovlen(&gs.hdr, 1)
	gs.hdr.Control = &gs.cmsgBuf[0]
	setControllen(&gs.hdr, uint64(len(gs.cmsgBuf)))
}

// recvGRO receives a potentially coalesced UDP buffer. Returns total bytes and segment size.
// If segSize == 0, no coalescing occurred (single packet).
func recvGRO(fd int, gs *groState) (n int, segSize int, err error) {
	// Reset control length for each call.
	setControllen(&gs.hdr, uint64(len(gs.cmsgBuf)))
	gs.hdr.Flags = 0

	r, _, errno := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&gs.hdr)), 0)
	if errno != 0 {
		return 0, 0, errno
	}
	n = int(r)

	// Parse cmsg for UDP_GRO segment size.
	cmsgLen := getControllen(&gs.hdr)
	if cmsgLen > 0 {
		hdrSize := cmsgAlignOf(int(unsafe.Sizeof(cmsghdr{})))
		if cmsgLen >= hdrSize+2 {
			cmsg := (*cmsghdr)(unsafe.Pointer(&gs.cmsgBuf[0]))
			if cmsg.Level == ipprotoUDP && cmsg.Type == udpSegment {
				segSize = int(*(*uint16)(unsafe.Pointer(&gs.cmsgBuf[hdrSize])))
			}
		}
	}
	return n, segSize, nil
}

// clientToServerBatch is the batch version of clientToServer.
// Uses blocking raw fds (no Go poller overhead). LockOSThread makes this safe.
// Zero-copy: recv with S4 headroom, transform in-place, send from recvBS.
func (p *Proxy) clientToServerBatch(listenConn *net.UDPConn) {
	runtime.LockOSThread()

	recvFD, err := dupBlockingFD(listenConn)
	if err != nil {
		LogError(p.cfg, "listen dup fd: ", err.Error())
		return
	}
	defer syscall.Close(recvFD)
	p.registerShutdownFD(recvFD)

	recvBS := new(batchState)
	sendSS := new(sendState)
	prefix := p.cfg.S4
	recvBS.initRecvFirstAddr(prefix)
	sendSS.init()

	var sendFD int = -1
	var sendConn *net.UDPConn
	cfg := p.cfg
	gsoOK := true
	var pktCount uint8 = 255

	for {
		nRecv, err := recvBatchFD(recvFD, recvBS)
		if err != nil {
			if p.stopped.Load() || isClosedErr(err) {
				return
			}
			LogError(cfg, "listen batch read: ", err.Error())
			continue
		}

		pktCount += uint8(nRecv)
		if pktCount < uint8(nRecv) {
			p.lastActive.Store(true)
		}

		currentRemote := p.remoteConn.Load()
		if currentRemote != sendConn {
			if sendFD >= 0 {
				p.removeShutdownFD(sendFD)
				syscall.Close(sendFD)
			}
			sendFD, err = dupBlockingFD(currentRemote)
			if err != nil {
				LogError(cfg, "remote dup fd: ", err.Error())
				continue
			}
			p.registerShutdownFD(sendFD)
			sendConn = currentRemote
		}
		nSend := 0

		// Micro-opt: check client address only from first packet in batch.
		if nRecv > 0 && recvBS.addrs[0].Family == syscall.AF_INET {
			addr := sockaddrToAddrPort(&recvBS.addrs[0])
			if cur := p.clientAddr.Load(); cur == nil || *cur != addr {
				a := addr
				p.clientAddr.Store(&a)
				LogInfo(cfg, "client: ", addr.String())
				if p.autoSrcPort {
					clientPort := int32(addr.Port())
					if old := p.localPort.Load(); old != clientPort {
						p.localPort.Store(clientPort)
						if rc := p.remoteConn.Load(); rc != nil {
							LogInfo(cfg, "src port: auto ", strconv.Itoa(int(clientPort)), ", reconnecting")
							rc.Close()
						}
					}
				}
			}
		} else if nRecv > 0 && p.clientAddr.Load() == nil {
			LogInfo(cfg, "client: unexpected addr family=", strconv.Itoa(int(recvBS.addrs[0].Family)))
		}

		for i := 0; i < nRecv; i++ {
			n := int(recvBS.msgs[i].Len)
			if n <= 0 {
				continue
			}

			data := recvBS.bufs[i][prefix : prefix+n]

			// Transport data fast-path: in-place transform, zero-copy send.
			if n >= WgTransportMinSize {
				h := binary.LittleEndian.Uint32(data[:4])
				if h == wgTransportData {
					binary.LittleEndian.PutUint32(data[:4], p.pickH4())
					if prefix > 0 {
						p.fillRand(recvBS.bufs[i][:prefix])
					}
					sendSS.iovecs[nSend].Base = &recvBS.bufs[i][0]
					setIovecLen(&sendSS.iovecs[nSend], uint64(prefix+n))
					nSend++
					continue
				}
			}

			// Handshake fallback: flush batch before sendSingle.
			if nSend > 0 {
				sendmmsgSlice(sendFD, sendSS.msgs[:nSend])
				nSend = 0
			}

			out, sendJunk := TransformOutbound(recvBS.bufs[i][:prefix+n], prefix, n, cfg)

			if cfg.LogLevel >= LevelDebug {
				LogDebug(cfg, "c->s batch: recv ", strconv.Itoa(n), "B, send ", strconv.Itoa(len(out)), "B, junk=", strconv.FormatBool(sendJunk))
			}

			if sendJunk {
				LogDebug(cfg, "c->s: handshake init ", strconv.Itoa(n), "B -> ", strconv.Itoa(len(out)), "B")
				cpsPackets := GenerateCPSPackets(cfg.CPS, &p.cpsCounter)
				for _, pkt := range cpsPackets {
					sendSinglePacketFD(sendFD, pkt, sendSS)
				}
				junkPackets := p.generateJunk()
				for _, junk := range junkPackets {
					sendSinglePacketFD(sendFD, junk, sendSS)
				}
				sendSinglePacketFD(sendFD, out, sendSS)
				continue
			}

			// Non-junk handshake: point iovec directly at out (valid until next recvBatchFD).
			sendSS.iovecs[nSend].Base = &out[0]
			setIovecLen(&sendSS.iovecs[nSend], uint64(len(out)))
			nSend++
		}

		if nSend > 0 {
			sent := 0
			if gsoOK {
				n, err := sendGSO(sendFD, &sendSS.iovecs, nSend, nil)
				if err != nil {
					if err == syscall.ENOPROTOOPT || err == syscall.EIO {
						gsoOK = false
					}
				}
				sent = n
			}
			if sent < nSend {
				_, err := sendmmsgSlice(sendFD, sendSS.msgs[sent:nSend])
				if err != nil {
					if isClosedErr(err) {
						continue
					}
					LogError(cfg, "remote batch write: ", err.Error())
				}
			}
		}
	}
}

// processS2CPacket transforms one inbound AWG packet and fills sendBS slot.
// Returns updated nSend. pkt must be a mutable slice.
func processS2CPacket(pkt []byte, n, s4 int, cfg *Config, sendBS *batchState, nSend int) int {
	if n >= s4+WgTransportMinSize && n != cfg.initTotal && n != cfg.respTotal && n != cfg.cookieTotal {
		h := binary.LittleEndian.Uint32(pkt[s4 : s4+4])
		if cfg.H4.Contains(h) {
			binary.LittleEndian.PutUint32(pkt[s4:s4+4], wgTransportData)
			sendBS.iovecs[nSend].Base = &pkt[s4]
			setIovecLen(&sendBS.iovecs[nSend], uint64(n-s4))
			return nSend + 1
		}
	}

	out, valid := TransformInbound(pkt, n, cfg)
	if !valid {
		return nSend
	}

	if cfg.LogLevel >= LevelDebug && len(out) >= 4 && out[0] != byte(wgTransportData) {
		LogDebug(cfg, "s->c: handshake ", strconv.Itoa(n), "B -> ", strconv.Itoa(len(out)), "B")
	}

	sendBS.iovecs[nSend].Base = &out[0]
	setIovecLen(&sendBS.iovecs[nSend], uint64(len(out)))
	return nSend + 1
}

// serverToClientBatch is the batch version of serverToClient.
// Uses raw blocking fds + optional UDP GRO. Sends via dup'd listen fd with per-packet addr.
func (p *Proxy) serverToClientBatch(listenConn *net.UDPConn, remoteConn *net.UDPConn, stop <-chan struct{}) {
	runtime.LockOSThread()

	recvFD, err := dupBlockingFD(remoteConn)
	if err != nil {
		LogError(p.cfg, "remote dup fd: ", err.Error())
		return
	}
	defer syscall.Close(recvFD)
	p.registerShutdownFD(recvFD)

	// Dup listen fd for sending (raw blocking, no Go poller overhead).
	sendFD, err := dupBlockingFD(listenConn)
	if err != nil {
		LogError(p.cfg, "listen send dup fd: ", err.Error())
		return
	}
	defer syscall.Close(sendFD)
	p.registerShutdownFD(sendFD)

	// Try to enable GRO on recv socket.
	useGRO := enableGRO(recvFD)
	var gs *groState
	recvBS := new(batchState)
	if useGRO {
		gs = new(groState)
		gs.init()
		LogInfo(p.cfg, "s->c: UDP GRO enabled")
	} else {
		recvBS.initRecv(false, 0)
	}

	sendBS := new(batchState)
	sendBS.initSend(true) // need client addr for unconnected listen socket

	currentRemote := remoteConn
	backoff := time.Second
	var pktCount uint8 = 255

	var cachedAddr netip.AddrPort
	var cachedSA sockaddrIn
	var addrCached bool
	gsoOK := true

	cfg := p.cfg
	s4 := cfg.S4

	for {
		// === Receive ===
		var nSend int
		var recvErr error
		var pktCountIncr int

		if useGRO {
			n, segSize, err := recvGRO(recvFD, gs)
			recvErr = err
			if err == nil {
				if segSize > 0 && n > segSize {
					for off := 0; off < n && nSend < batchSize; off += segSize {
						end := off + segSize
						if end > n {
							end = n
						}
						pktLen := end - off
						nSend = processS2CPacket(gs.buf[off:end], pktLen, s4, cfg, sendBS, nSend)
					}
					pktCountIncr = (n + segSize - 1) / segSize
				} else if n > 0 {
					pktCountIncr = 1
					nSend = processS2CPacket(gs.buf[:n], n, s4, cfg, sendBS, nSend)
				}
			}
		} else {
			nRecv, err := recvBatchFD(recvFD, recvBS)
			recvErr = err
			if err == nil {
				pktCountIncr = nRecv
				for i := 0; i < nRecv; i++ {
					pn := int(recvBS.msgs[i].Len)
					if pn <= 0 {
						continue
					}
					nSend = processS2CPacket(recvBS.bufs[i][:pn], pn, s4, cfg, sendBS, nSend)
				}
			}
		}

		// === Error handling / reconnect ===
		if recvErr != nil {
			if p.stopped.Load() {
				return
			}
			LogInfo(cfg, "remote: ", recvErr.Error(), ", reconnecting")
			newConn := p.reconnectRemote(stop, &backoff)
			if newConn == nil {
				return
			}
			currentRemote.Close()
			currentRemote = newConn
			p.remoteConn.Store(newConn)
			setSocketBuffers(newConn, SocketBufSize)
			p.removeShutdownFD(recvFD)
			syscall.Close(recvFD)
			recvFD, err = dupBlockingFD(newConn)
			if err != nil {
				LogError(cfg, "remote dup fd: ", err.Error())
				return
			}
			p.registerShutdownFD(recvFD)
			if useGRO {
				useGRO = enableGRO(recvFD)
			}
			p.lastActive.Store(true)
			p.clientAddr.Store(nil)
			pktCount = 255
			addrCached = false
			if p.stopped.Load() {
				newConn.Close()
				return
			}
			continue
		}

		// === Activity tracking ===
		pktCount += uint8(pktCountIncr)
		if pktCount < uint8(pktCountIncr) {
			p.lastActive.Store(true)
		}
		backoff = time.Second

		// === Client addr check ===
		clientAddr := p.clientAddr.Load()
		if clientAddr == nil || nSend == 0 {
			continue
		}

		if !clientAddr.Addr().Is4() {
			for i := 0; i < nSend; i++ {
				pkt := unsafe.Slice(sendBS.iovecs[i].Base, sendBS.iovecs[i].Len)
				listenConn.WriteToUDPAddrPort(pkt, *clientAddr)
			}
			continue
		}

		// Micro-opt: update cached sockaddr and fill all addrs once on change.
		if !addrCached || *clientAddr != cachedAddr {
			cachedAddr = *clientAddr
			addrPortToSockaddr(cachedAddr, &cachedSA)
			for i := range sendBS.addrs {
				sendBS.addrs[i] = cachedSA
			}
			addrCached = true
		}

		// === Send batch ===
		if nSend > 0 {
			sent := 0
			if gsoOK {
				n, err := sendGSO(sendFD, &sendBS.iovecs, nSend, &cachedSA)
				if err != nil {
					if err == syscall.ENOPROTOOPT || err == syscall.EIO {
						gsoOK = false
					}
				}
				sent = n
			}
			if sent < nSend {
				_, err := sendmmsgSlice(sendFD, sendBS.msgs[sent:nSend])
				if err != nil {
					LogError(cfg, "listen batch write: ", err.Error())
				}
			}
		}
	}
}
