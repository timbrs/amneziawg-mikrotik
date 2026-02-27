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
	batchSize    = 32
	msgWaitfirst = 0x10000 // MSG_WAITFORONE
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

func (bs *batchState) initRecv(needAddr bool) {
	for i := range bs.msgs {
		bs.iovecs[i].Base = &bs.bufs[i][0]
		setIovecLen(&bs.iovecs[i], uint64(len(bs.bufs[i])))
		bs.msgs[i].Hdr.Iov = &bs.iovecs[i]
		setIovlen(&bs.msgs[i].Hdr, 1)
		if needAddr {
			bs.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&bs.addrs[i]))
			bs.msgs[i].Hdr.Namelen = sockaddrInSize
		}
	}
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

// recvBatch calls recvmmsg via RawConn. Returns number of messages received.
func recvBatch(raw syscall.RawConn, bs *batchState) (int, error) {
	var (
		n      int
		sysErr error
	)

	err := raw.Read(func(fd uintptr) bool {
		r, _, errno := syscall.Syscall6(
			sysRecvmmsg,
			fd,
			uintptr(unsafe.Pointer(&bs.msgs[0])),
			uintptr(batchSize),
			uintptr(msgWaitfirst),
			0, 0,
		)
		if errno != 0 {
			if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
				return false // tell Go poller to wait
			}
			sysErr = errno
			return true
		}
		n = int(r)
		return true
	})

	if sysErr != nil {
		return 0, sysErr
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// sendBatch calls sendmmsg via RawConn with retry for partial sends.
func sendBatch(raw syscall.RawConn, bs *batchState, count int) (int, error) {
	if count <= 0 {
		return 0, nil
	}

	total := 0
	for total < count {
		var (
			n      int
			sysErr error
		)

		err := raw.Write(func(fd uintptr) bool {
			r, _, errno := syscall.Syscall6(
				sysSendmmsg,
				fd,
				uintptr(unsafe.Pointer(&bs.msgs[total])),
				uintptr(count-total),
				0, 0, 0,
			)
			if errno != 0 {
				if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
					return false
				}
				sysErr = errno
				return true
			}
			n = int(r)
			return true
		})

		if sysErr != nil {
			return total, sysErr
		}
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// sendSingle sends a single packet via sendmmsg (count=1).
func sendSingle(raw syscall.RawConn, data []byte, bs *batchState) error {
	copy(bs.bufs[0][:len(data)], data)
	bs.iovecs[0].Base = &bs.bufs[0][0]
	setIovecLen(&bs.iovecs[0], uint64(len(data)))
	bs.msgs[0].Hdr.Iov = &bs.iovecs[0]
	setIovlen(&bs.msgs[0].Hdr, 1)
	bs.msgs[0].Hdr.Name = nil
	bs.msgs[0].Hdr.Namelen = 0
	_, err := sendBatch(raw, bs, 1)
	return err
}

// clientToServerBatch is the batch version of clientToServer.
// For the client->server direction: listenConn is unconnected (need addr),
// remoteConn is connected (no addr needed for send).
func (p *Proxy) clientToServerBatch(listenConn *net.UDPConn) {
	runtime.LockOSThread()

	recvBS := new(batchState)
	sendBS := new(batchState)
	recvBS.initRecv(true)  // need client addr from listenConn
	sendBS.initSend(false) // remoteConn is connected, no addr needed

	listenRaw, err := listenConn.SyscallConn()
	if err != nil {
		LogError(p.cfg, "listen syscall conn: ", err.Error())
		return
	}

	var sendRaw syscall.RawConn
	var sendConn *net.UDPConn

	for {
		nRecv, err := recvBatch(listenRaw, recvBS)
		if err != nil {
			if p.stopped.Load() || isClosedErr(err) {
				return
			}
			LogError(p.cfg, "listen batch read: ", err.Error())
			continue
		}
		p.lastActive.Store(true)

		currentRemote := p.remoteConn.Load()
		if currentRemote != sendConn {
			sendRaw, err = currentRemote.SyscallConn()
			if err != nil {
				LogError(p.cfg, "remote syscall conn: ", err.Error())
				continue
			}
			sendConn = currentRemote
		}
		nSend := 0
		prefix := p.cfg.S4
		var tmpBuf [bufSize + 256]byte

		for i := 0; i < nRecv; i++ {
			n := int(recvBS.msgs[i].Len)
			if n <= 0 {
				continue
			}

			// Update client address from first packet with valid addr.
			if recvBS.addrs[i].Family == syscall.AF_INET {
				addr := sockaddrToAddrPort(&recvBS.addrs[i])
				if cur := p.clientAddr.Load(); cur == nil || *cur != addr {
					a := addr
					p.clientAddr.Store(&a)
					LogInfo(p.cfg, "client: ", addr.String())
				}
			} else if p.clientAddr.Load() == nil {
				LogInfo(p.cfg, "client: unexpected addr family=", strconv.Itoa(int(recvBS.addrs[i].Family)))
			}

			data := recvBS.bufs[i][:n]

			// Fast path: H4 identity transform (no type change, no S4 padding).
			// Avoid tmpBuf entirely — copy directly to send buffer.
			if p.cfg.h4NoOp && n >= WgTransportMinSize {
				h := binary.LittleEndian.Uint32(data[:4])
				if h == wgTransportData {
					copy(sendBS.bufs[nSend][:n], data)
					sendBS.iovecs[nSend].Base = &sendBS.bufs[nSend][0]
					setIovecLen(&sendBS.iovecs[nSend], uint64(n))
					sendBS.msgs[nSend].Hdr.Iov = &sendBS.iovecs[nSend]
					setIovlen(&sendBS.msgs[nSend].Hdr, 1)
					sendBS.msgs[nSend].Hdr.Name = nil
					sendBS.msgs[nSend].Hdr.Namelen = 0
					nSend++
					continue
				}
			}

			// For handshake packets that need junk/CPS, fall back to single sends.
			copy(tmpBuf[prefix:prefix+n], data)
			out, sendJunk := TransformOutbound(tmpBuf[:prefix+n], prefix, n, p.cfg)

			if p.cfg.LogLevel >= LevelDebug {
				LogDebug(p.cfg, "c->s batch: recv ", strconv.Itoa(n), "B, send ", strconv.Itoa(len(out)), "B, junk=", strconv.FormatBool(sendJunk))
			}

			if sendJunk {
				LogDebug(p.cfg, "c->s: handshake init ", strconv.Itoa(n), "B -> ", strconv.Itoa(len(out)), "B")
				// CPS and junk need individual sends (rare, handshake only).
				cpsPackets := GenerateCPSPackets(p.cfg.CPS, &p.cpsCounter)
				for _, pkt := range cpsPackets {
					sendSingle(sendRaw, pkt, sendBS)
				}
				junkPackets := p.generateJunk()
				for _, junk := range junkPackets {
					sendSingle(sendRaw, junk, sendBS)
				}
				// Send the transformed packet individually too.
				sendSingle(sendRaw, out, sendBS)
				continue
			}

			// Batch the transformed packet for sendmmsg.
			copy(sendBS.bufs[nSend][:len(out)], out)
			sendBS.iovecs[nSend].Base = &sendBS.bufs[nSend][0]
			setIovecLen(&sendBS.iovecs[nSend], uint64(len(out)))
			sendBS.msgs[nSend].Hdr.Iov = &sendBS.iovecs[nSend]
			setIovlen(&sendBS.msgs[nSend].Hdr, 1)
			sendBS.msgs[nSend].Hdr.Name = nil
			sendBS.msgs[nSend].Hdr.Namelen = 0
			nSend++
		}

		if nSend > 0 {
			_, err := sendBatch(sendRaw, sendBS, nSend)
			if err != nil {
				if isClosedErr(err) {
					continue
				}
				LogError(p.cfg, "remote batch write: ", err.Error())
			}
		}
	}
}

// serverToClientBatch is the batch version of serverToClient.
// remoteConn is connected (recv no addr), listenConn is unconnected (send needs addr).
func (p *Proxy) serverToClientBatch(listenConn *net.UDPConn, remoteConn *net.UDPConn, stop <-chan struct{}) {
	runtime.LockOSThread()

	recvBS := new(batchState)
	sendBS := new(batchState)
	recvBS.initRecv(false) // remoteConn is connected
	sendBS.initSend(true)  // need client addr for listenConn sends

	sendRaw, err := listenConn.SyscallConn()
	if err != nil {
		LogError(p.cfg, "listen syscall conn: ", err.Error())
		return
	}

	currentRemote := remoteConn
	recvRaw, err := currentRemote.SyscallConn()
	if err != nil {
		LogError(p.cfg, "remote syscall conn: ", err.Error())
		return
	}

	backoff := time.Second
	var pktCount uint8 = 255

	for {
		nRecv, err := recvBatch(recvRaw, recvBS)
		if err != nil {
			if p.stopped.Load() {
				return
			}
			LogInfo(p.cfg, "remote: ", err.Error(), ", reconnecting")
			newConn := p.reconnectRemote(stop, &backoff)
			if newConn == nil {
				return
			}
			currentRemote.Close()
			currentRemote = newConn
			p.remoteConn.Store(newConn)
			setSocketBuffers(newConn, SocketBufSize)
			recvRaw, err = newConn.SyscallConn()
			if err != nil {
				LogError(p.cfg, "remote syscall conn: ", err.Error())
				return
			}
			p.lastActive.Store(true)
			p.clientAddr.Store(nil)
			pktCount = 255
			if p.stopped.Load() {
				newConn.Close()
				return
			}
			continue
		}

		pktCount += uint8(nRecv)
		if pktCount < uint8(nRecv) { // overflow = 256+ packets
			p.lastActive.Store(true)
		}
		backoff = time.Second

		clientAddr := p.clientAddr.Load()
		if clientAddr == nil {
			if p.cfg.LogLevel >= LevelDebug {
				LogDebug(p.cfg, "s->c: ", strconv.Itoa(nRecv), " pkt(s) dropped, no client addr")
			}
			continue
		}

		// Check IPv4 for batch path.
		if !clientAddr.Addr().Is4() {
			// IPv6 fallback: send individually.
			for i := 0; i < nRecv; i++ {
				n := int(recvBS.msgs[i].Len)
				out, valid := TransformInbound(recvBS.bufs[i][:n], n, p.cfg)
				if valid {
					listenConn.WriteToUDPAddrPort(out, *clientAddr)
				}
			}
			continue
		}

		nSend := 0
		for i := 0; i < nRecv; i++ {
			n := int(recvBS.msgs[i].Len)
			if n <= 0 {
				continue
			}

			out, valid := TransformInbound(recvBS.bufs[i][:n], n, p.cfg)
			if !valid {
				if p.cfg.LogLevel >= LevelDebug {
					LogDebug(p.cfg, "s->c batch: invalid/junk packet ", strconv.Itoa(n), "B, dropped")
				}
				continue
			}

			if p.cfg.LogLevel >= LevelDebug && len(out) >= 4 && out[0] != byte(wgTransportData) {
				LogDebug(p.cfg, "s->c: handshake ", strconv.Itoa(n), "B -> ", strconv.Itoa(len(out)), "B, forwarding to ", clientAddr.String())
			}

			// Copy transformed packet into send buffer and set up sockaddr.
			copy(sendBS.bufs[nSend][:len(out)], out)
			sendBS.iovecs[nSend].Base = &sendBS.bufs[nSend][0]
			setIovecLen(&sendBS.iovecs[nSend], uint64(len(out)))
			sendBS.msgs[nSend].Hdr.Iov = &sendBS.iovecs[nSend]
			setIovlen(&sendBS.msgs[nSend].Hdr, 1)
			addrPortToSockaddr(*clientAddr, &sendBS.addrs[nSend])
			sendBS.msgs[nSend].Hdr.Name = (*byte)(unsafe.Pointer(&sendBS.addrs[nSend]))
			sendBS.msgs[nSend].Hdr.Namelen = sockaddrInSize
			nSend++
		}

		if nSend > 0 {
			_, err := sendBatch(sendRaw, sendBS, nSend)
			if err != nil {
				LogError(p.cfg, "listen batch write: ", err.Error())
			}
		}
	}
}
