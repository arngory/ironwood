package encrypted

import (
	"crypto/ed25519"
	"net"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/network"
	"github.com/Arceliar/ironwood/types"
)

type PacketConn struct {
	actor phony.Inbox
	*network.PacketConn
	secretEd  edPriv
	secretBox boxPriv
	publicEd  edPub
	groupAuth groupAuth
	sessions  sessionManager
	network   netManager
	pq        pqState
	Debug     Debug
	// testDrop: a test's own loss below the sessions (a packet it reports is not sent); nil outside tests
	testDrop func(data []byte) bool
}

// NewPacketConn returns a *PacketConn struct which implements the types.PacketConn interface.
func NewPacketConn(secret ed25519.PrivateKey, options ...network.Option) (*PacketConn, error) {
	return newPacketConn(secret, groupAuth{}, options...)
}

// NewPacketConnWithPassword returns a *PacketConn that only completes handshakes
// with peers configured with the same password. The packet format is unchanged;
// the password is folded into the handshake signature preimage.
func NewPacketConnWithPassword(secret ed25519.PrivateKey, password string, options ...network.Option) (*PacketConn, error) {
	return newPacketConn(secret, newGroupAuth(password), options...)
}

func newPacketConn(secret ed25519.PrivateKey, auth groupAuth, options ...network.Option) (*PacketConn, error) {
	npc, err := network.NewPacketConn(secret, options...)
	if err != nil {
		return nil, err
	}
	pc := &PacketConn{PacketConn: npc, groupAuth: auth}
	copy(pc.secretEd[:], secret[:])
	pc.secretBox = *pc.secretEd.toBox()
	pc.publicEd = *pc.secretEd.pub()
	pc.pq.init()
	pc.sessions.init(pc)
	pc.network.init(pc)
	pc.Debug.init(pc)
	return pc, nil
}

func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	pc.network.read()
	info := <-pc.network.readCh
	if info.err != nil {
		err = info.err
		return
	}
	n, from = len(info.data), types.Addr(info.from.asKey())
	if n > len(p) {
		n = len(p)
	}
	copy(p, info.data[:n])
	freeBytes(info.data)
	return
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-pc.network.closed:
		return 0, types.ErrClosed
	default:
	}
	destKey, ok := addr.(types.Addr)
	if !ok || len(destKey) != edPubSize {
		return 0, types.ErrBadAddress
	}
	if uint64(len(p)) > pc.MTU() {
		return 0, types.ErrOversizedMessage
	}
	n = len(p)
	var dest edPub
	copy(dest[:], destKey)
	pc.sessions.writeTo(dest, append(allocBytes(0), p...))
	return
}

// MTU returns the maximum transmission unit of the PacketConn, i.e. maximum safe message size to send over the network.
// It leaves room for the larger of the two traffic headers, the classic and the PQ one (a byte more), so that it
// does not change when PQ sessions are turned on.
func (pc *PacketConn) MTU() uint64 {
	return pc.PacketConn.MTU() - max(sessionTrafficOverhead, pqTrafficOverhead)
}

// SetPQ turns the hybrid post-quantum sessions on or off, and sets which keys must have them (PQConfig). Sessions
// that are up stay as they are.
func (pc *PacketConn) SetPQ(cfg PQConfig) {
	if cfg.Enabled {
		pc.pqOwn() // the process's ML-KEM key, made now rather than on the first contact
	}
	pc.pq.cfg.Store(&cfg)
}

// writeRaw sends a session packet to dest below the sessions.
func (pc *PacketConn) writeRaw(data []byte, dest *edPub) {
	if pc.testDrop != nil && pc.testDrop(data) {
		return
	}
	pc.PacketConn.WriteTo(data, types.Addr(dest.asKey()))
}
