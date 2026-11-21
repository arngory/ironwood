package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"testing"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// TestRepeatedInitIsAckedAgain: the receiver of a first init answers with an ack, and the ack is lost (here: the
// receiver's traffic frames to the sender are lost for a moment; in a network, the ack waits for a path back that a
// lookup lost while the tree converges never brings). The sender resends the same init with each packet; the receiver must
// ack it again, or the contact waits for the receiver's session to time out (sessionTimeout, a minute).
func TestRepeatedInitIsAckedAgain(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	a, err := NewPacketConn(privA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewPacketConn(privB)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var dropBToA atomic.Bool
	cA, cB := newLossyLink(&dropBToA)
	defer cA.Close()
	go a.HandleConn(pubB, cA, 0)
	go b.HandleConn(pubA, cB, 0)
	addrA, addrB := types.Addr(pubA), types.Addr(pubB)

	// paths both ways first, without a session: packets below the sessions, ignored by them
	hasPath := func(pc *PacketConn, key ed25519.PublicKey) bool {
		for _, p := range pc.PacketConn.Debug.GetPaths() {
			if bytes.Equal(p.Key, key) {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(30 * time.Second); !hasPath(a, pubB) || !hasPath(b, pubA); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no paths between the two nodes in 30 s")
		}
		a.PacketConn.WriteTo([]byte{sessionTypeDummy}, addrB)
		b.PacketConn.WriteTo([]byte{sessionTypeDummy}, addrA)
	}

	// both read, as a node does (the sessions take their packets only while someone reads)
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := a.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	heard := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			n, _, err := b.ReadFrom(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "hello" {
				close(heard)
				return
			}
		}
	}()

	// A's first packet: an init to B, whose ack is lost
	dropBToA.Store(true)
	a.WriteTo([]byte("hello"), addrB)
	for deadline := time.Now().Add(5 * time.Second); len(b.Debug.GetSessions()) == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("B took no init in 5 s")
		}
	}
	time.Sleep(200 * time.Millisecond)
	dropBToA.Store(false)

	// A resends the same init with each packet: B must ack it again
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		select {
		case <-heard:
			return
		default:
		}
		a.WriteTo([]byte("hello"), addrB)
	}
	t.Fatalf("B did not hear A in 10 s after its ack was lost: the repeated init went unanswered (peers A %d B %d, sessions A %d B %d, paths A %v B %v)",
		len(a.PacketConn.Debug.GetPeers()), len(b.PacketConn.Debug.GetPeers()), len(a.Debug.GetSessions()), len(b.Debug.GetSessions()),
		hasPath(a, pubB), hasPath(b, pubA))
}

// TestReplayedInitKeepsKeys: once the handshake is done and traffic came, the same init again (duplicated by the
// network, or replayed by someone on the path) answers nothing that moves the sender's keys: the receiver sends no
// ack, and an ack of the first time would be dropped by its seq. A fresh ack to each replay would ratchet the
// sender's keys, one replay a second keeping the session renegotiating.
func TestReplayedInitKeepsKeys(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	a, _ := NewPacketConn(privA)
	defer a.Close()
	b, _ := NewPacketConn(privB)
	defer b.Close()
	cA, cB := newLossyLink(nil)
	defer cA.Close()
	go a.HandleConn(pubB, cA, 0)
	go b.HandleConn(pubA, cB, 0)
	addrB := types.Addr(pubB)
	warmPaths(t, a, b, pubA, pubB)
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := a.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	heard := make(chan string, 16)
	go func() {
		buf := make([]byte, 64)
		for {
			n, _, err := b.ReadFrom(buf)
			if err != nil {
				return
			}
			heard <- string(buf[:n])
		}
	}()
	hears := func(msg string) bool {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			a.WriteTo([]byte(msg), addrB)
			select {
			case got := <-heard:
				if got == msg {
					return true
				}
			case <-time.After(250 * time.Millisecond):
			}
		}
		return false
	}

	// the handshake, A's init kept as it went out
	cA.capture.Store(true)
	if !hears("hello") {
		t.Fatal("no handshake in 5 s")
	}
	cA.capture.Store(false)
	frames := cA.frames()
	if len(frames) == 0 {
		t.Fatal("no traffic frame captured")
	}
	keySeq := func() uint64 {
		var k edPub
		copy(k[:], pubB)
		var info *sessionInfo
		phony.Block(&a.sessions, func() { info = a.sessions.sessions[k] })
		if info == nil {
			t.Fatal("A has no session with B")
		}
		var seq uint64
		phony.Block(info, func() { seq = info.localKeySeq })
		return seq
	}
	// a second on, so that a fresh ack would carry a newer seq than the session has
	time.Sleep(1100 * time.Millisecond)
	before := keySeq()
	for i := 0; i < 2; i++ {
		cA.replay(frames[0])
		time.Sleep(1100 * time.Millisecond)
	}
	if after := keySeq(); after != before {
		t.Fatalf("A's keys moved on replays of its init: key seq %d, then %d", before, after)
	}
	if !hears("again") {
		t.Fatal("the session stopped carrying after the replays")
	}
}

// warmPaths: a path each way, without a session: packets below the sessions, ignored by them.
func warmPaths(t *testing.T, a, b *PacketConn, pubA, pubB ed25519.PublicKey) {
	t.Helper()
	hasPath := func(pc *PacketConn, key ed25519.PublicKey) bool {
		for _, p := range pc.PacketConn.Debug.GetPaths() {
			if bytes.Equal(p.Key, key) {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(30 * time.Second); !hasPath(a, pubB) || !hasPath(b, pubA); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no paths between the two nodes in 30 s")
		}
		a.PacketConn.WriteTo([]byte{sessionTypeDummy}, types.Addr(pubB))
		b.PacketConn.WriteTo([]byte{sessionTypeDummy}, types.Addr(pubA))
	}
}

// wireTraffic is the network package's frame type of traffic (network/wire.go): what a session's init, ack and data
// ride in.
const wireTraffic = 9

// lossyConn is one end of an in-memory link. While drop is set (nil: never), the traffic frames it writes are lost
// whole; the link's own frames (keepalives, the tree, the bloom filters, lookups) still pass, so the link and the
// paths stay up. A frame is a uvarint length and that many bytes, the first its type (network/peers.go).
type lossyConn struct {
	recv, send chan []byte
	buf        []byte
	pending    []byte
	readLock   sync.Mutex
	writeLock  sync.Mutex
	closed     chan struct{}
	closeOnce  *sync.Once
	drop       *atomic.Bool
	// while capture is set, the traffic frames written are kept too (captured), for replay
	capture  atomic.Bool
	captured [][]byte
}

// replay writes a frame again, as the network would if it duplicated it (or someone on the path replayed it).
func (c *lossyConn) replay(frame []byte) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	select {
	case <-c.closed:
	case c.send <- append([]byte(nil), frame...):
	}
}

// frames: the captured traffic frames so far.
func (c *lossyConn) frames() [][]byte {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	return append([][]byte(nil), c.captured...)
}

// newLossyLink: two ends, the second's traffic frames (B to A) lost while drop is set.
func newLossyLink(drop *atomic.Bool) (*lossyConn, *lossyConn) {
	toA, toB := make(chan []byte), make(chan []byte)
	closed := make(chan struct{})
	once := new(sync.Once)
	return &lossyConn{recv: toA, send: toB, closed: closed, closeOnce: once},
		&lossyConn{recv: toB, send: toA, closed: closed, closeOnce: once, drop: drop}
}

func (c *lossyConn) Read(p []byte) (int, error) {
	c.readLock.Lock()
	defer c.readLock.Unlock()
	if len(c.buf) == 0 {
		select {
		case <-c.closed:
			return 0, errors.New("closed")
		case bs := <-c.recv:
			c.buf = bs
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *lossyConn) Write(p []byte) (int, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	// whole frames only: a write may end inside one, the rest comes with the next
	c.pending = append(c.pending, p...)
	var out []byte
	for {
		size, n := binary.Uvarint(c.pending)
		if n <= 0 || len(c.pending) < n+int(size) {
			break
		}
		frame := c.pending[:n+int(size)]
		traffic := size > 0 && frame[n] == wireTraffic
		if traffic && c.capture.Load() {
			c.captured = append(c.captured, append([]byte(nil), frame...))
		}
		if !(traffic && c.drop != nil && c.drop.Load()) {
			out = append(out, frame...)
		}
		c.pending = c.pending[n+int(size):]
	}
	if len(out) == 0 {
		return len(p), nil
	}
	select {
	case <-c.closed:
		return 0, errors.New("closed")
	case c.send <- out:
		return len(p), nil
	}
}

func (c *lossyConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *lossyConn) LocalAddr() net.Addr                { return nil }
func (c *lossyConn) RemoteAddr() net.Addr               { return nil }
func (c *lossyConn) SetDeadline(t time.Time) error      { return nil }
func (c *lossyConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *lossyConn) SetWriteDeadline(t time.Time) error { return nil }
