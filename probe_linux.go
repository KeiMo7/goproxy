//go:build linux

package goproxy

import (
	"net"
	"sync"
	"syscall"
	"unsafe"
)

// readableProbe reports whether a connection's read side has reached
// end-of-file (the peer closed or reset it), without consuming any payload.
// It is used to detect a client disconnect on a hijacked MITM connection.
type readableProbe interface {
	// PeerGone reports whether the peer has closed its write direction.
	// Pending data that has not been consumed yet is not a disconnect and
	// reports false.
	PeerGone() bool
}

// tcpProbe implements readableProbe on any connection that exposes a raw
// descriptor.
type tcpProbe struct {
	fd int
}

// newReadableProbe returns a probe for conn, or nil when the platform or
// connection type does not support one.
func newReadableProbe(conn net.Conn) readableProbe {
	conn = unwrapConn(conn)
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	var fd int
	if cerr := raw.Control(func(descriptor uintptr) { fd = int(descriptor) }); cerr != nil {
		return nil
	}
	if fd <= 0 {
		return nil
	}
	// A raw descriptor is not reference counted: keep the connection alive
	// for as long as the probe (or its watcher goroutine) may use it.
	p := &tcpProbe{fd: fd}
	trackProbeOwner(p, conn)
	return p
}

// probeOwners keeps probed connections reachable while a watcher goroutine
// polls their descriptor, preventing the finalizer from closing the fd under
// it.
var probeOwners sync.Map // map[*tcpProbe]net.Conn

// trackProbeOwner pins conn while p may still use its descriptor.
func trackProbeOwner(p *tcpProbe, conn net.Conn) {
	probeOwners.Store(p, conn)
}

// releaseProbe drops the reference that keeps a probed connection alive.
func releaseProbe(p readableProbe) {
	if tp, ok := p.(*tcpProbe); ok {
		probeOwners.Delete(tp)
	}
}

// PeerGone reports whether the peer closed or reset the connection. It uses a
// non-blocking poll, which reports POLLRDHUP / POLLHUP even when unread bytes
// (for example a TLS close-notify record) are still queued. It never blocks
// and never consumes data.
func (p *tcpProbe) PeerGone() bool {
	return pollPeerGone(uintptr(p.fd))
}

// poll(2) event flags. The syscall package does not export the poll event
// constants on Linux, so they are declared here.
const (
	pollIn    = 0x1
	pollErr   = 0x8
	pollHup   = 0x10
	pollRdHup = 0x2000
)

// pollFd mirrors struct pollfd.
type pollFd struct {
	fd      int32
	events  int16
	revents int16
}

// pollPeerGone reports whether fd reports a hangup (peer FIN or reset) on a
// non-blocking poll. Readable data alone is not a disconnect.
//
// ppoll is used instead of poll because syscall.SYS_POLL is not defined on
// every Linux architecture (notably arm64 and riscv64), while SYS_PPOLL is.
// A zero timeout makes the call non-blocking.
func pollPeerGone(fd uintptr) bool {
	var pfd pollFd
	pfd.fd = int32(fd)
	pfd.events = pollIn | pollRdHup
	var timeout syscall.Timespec // zero: do not block
	for {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_PPOLL,
			uintptr(unsafe.Pointer(&pfd)),
			1,
			uintptr(unsafe.Pointer(&timeout)),
			0,
			0,
			0,
		)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return false
		}
		return pfd.revents&(pollRdHup|pollHup|pollErr) != 0
	}
}
