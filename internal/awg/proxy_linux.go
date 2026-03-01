//go:build linux

package awg

import "syscall"

// shutdownAllFDs closes all registered blocking fds to unblock recvmmsg/sendmmsg.
// shutdown(SHUT_RDWR) alone doesn't reliably unblock UDP recvmmsg;
// close(fd) guarantees EBADF wakeup.
func (p *Proxy) shutdownAllFDs() {
	p.shutdownMu.Lock()
	for _, fd := range p.shutdownFDs {
		syscall.Shutdown(fd, syscall.SHUT_RDWR)
		syscall.Close(fd)
	}
	p.shutdownFDs = p.shutdownFDs[:0]
	p.shutdownMu.Unlock()
}

