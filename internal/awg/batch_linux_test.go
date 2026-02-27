//go:build linux

package awg

import (
	"net"
	"net/netip"
	"syscall"
	"testing"
)

// TestRecvmmsgIPv4Family verifies that a "udp4" socket + recvmmsg
// returns AF_INET (2) in the sockaddr, not AF_INET6 (10).
// This catches the dual-stack regression: if the socket were "udp"
// and dual-stack, recvmmsg would fill sockaddr_in6 with Family=10.
func TestRecvmmsgIPv4Family(t *testing.T) {
	// Create "udp4" listen socket.
	listenAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("resolve: ", err)
	}
	listenConn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		t.Fatal("listen: ", err)
	}
	defer listenConn.Close()

	actualAddr := listenConn.LocalAddr().(*net.UDPAddr)

	// Create sender socket.
	senderConn, err := net.DialUDP("udp4", nil, actualAddr)
	if err != nil {
		t.Fatal("dial: ", err)
	}
	defer senderConn.Close()

	// Send a packet.
	payload := []byte("test-packet-for-family-check")
	if _, err := senderConn.Write(payload); err != nil {
		t.Fatal("write: ", err)
	}

	// Receive via recvBatch.
	raw, err := listenConn.SyscallConn()
	if err != nil {
		t.Fatal("syscall conn: ", err)
	}

	bs := new(batchState)
	bs.initRecv(true)

	nRecv, err := recvBatch(raw, bs)
	if err != nil {
		t.Fatal("recvBatch: ", err)
	}
	if nRecv < 1 {
		t.Fatal("recvBatch returned 0 messages")
	}

	// Assert: address family must be AF_INET (2).
	family := bs.addrs[0].Family
	if family != syscall.AF_INET {
		t.Fatalf("expected AF_INET (%d), got family=%d", syscall.AF_INET, family)
	}

	// Verify the address is parseable.
	addr := sockaddrToAddrPort(&bs.addrs[0])
	if !addr.IsValid() {
		t.Fatal("sockaddrToAddrPort returned invalid addr")
	}
	if !addr.Addr().Is4() {
		t.Fatalf("expected IPv4 addr, got %s", addr.Addr().String())
	}

	t.Logf("recvmmsg returned AF_INET family=%d, addr=%s", family, addr.String())
}

// TestSockaddrAddrPortRoundtrip verifies addrPortToSockaddr and
// sockaddrToAddrPort are inverse operations.
func TestSockaddrAddrPortRoundtrip(t *testing.T) {
	cases := []string{
		"192.168.1.100:12345",
		"127.0.0.1:51820",
		"10.0.0.1:1",
		"255.255.255.255:65535",
		"0.0.0.0:0",
	}

	for _, s := range cases {
		ap := netip.MustParseAddrPort(s)
		var sa sockaddrIn
		addrPortToSockaddr(ap, &sa)

		if sa.Family != syscall.AF_INET {
			t.Fatalf("%s: expected AF_INET, got family=%d", s, sa.Family)
		}

		got := sockaddrToAddrPort(&sa)
		if got != ap {
			t.Fatalf("%s: roundtrip mismatch: got %s", s, got.String())
		}
	}

	t.Log("sockaddr <-> AddrPort roundtrip passed for all cases")
}
