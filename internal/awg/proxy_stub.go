//go:build !linux

package awg

func (p *Proxy) shutdownAllFDs() {
	p.shutdownMu.Lock()
	p.shutdownFDs = p.shutdownFDs[:0]
	p.shutdownMu.Unlock()
}

