//go:build !linux

package awg

import "net"

func batchAvailable() bool { return false }

func getSocketBufSizes(_ *net.UDPConn) (int, int) { return 0, 0 }

func (p *Proxy) clientToServerBatch(listenConn *net.UDPConn) {
	p.clientToServer(listenConn)
}

func (p *Proxy) serverToClientBatch(listenConn *net.UDPConn, remoteConn *net.UDPConn, stop <-chan struct{}) {
	p.serverToClient(listenConn, remoteConn, stop)
}
