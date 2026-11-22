package encrypted

import (
	"bytes"
	"container/list"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// The tests of the fourth review of the PQ sessions (R4), and pins of behaviours earlier mutants removed.

// forgeInit: a PQ init to `to` from the key priv, made by forge (its ML-KEM key kept: no new one a key)
func forgeInit(t *testing.T, forge, to *PacketConn, priv ed25519.PrivateKey) (edPub, []byte) {
	t.Helper()
	copy(forge.secretEd[:], priv)
	forge.secretBox = *forge.secretEd.toBox()
	forge.publicEd = *forge.secretEd.pub()
	return forge.publicEd, pqInitFrom(t, forge, to)
}

func heapNow() uint64 {
	var m runtime.MemStats
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// fill: n's PQ sessions up to count, from light peers' PQ inits (their keys)
func fill(t *testing.T, n *pqNode, count int) (keys []edPub) {
	t.Helper()
	for i := 0; n.pc.PQSessionCount() < count; i++ {
		if i >= 4*count {
			t.Fatalf("fill: %d PQ sessions after %d inits, %d wanted", n.pc.PQSessionCount(), i, count)
		}
		p := lightPC(t)
		k := edOf(p)
		deliverTo(n, k, pqInitFrom(t, p, n.pc))
		keys = append(keys, k)
	}
	return
}

// inUse: the PQ sessions of keys confirmed, a packet opened under each just now
func inUse(n *pqNode, keys []edPub) {
	phony.Block(&n.pc.sessions, func() {
		now := n.pc.pq.now().UnixNano()
		for _, k := range keys {
			if s := n.pc.sessions.sessions[k]; s != nil && s.pq {
				s.confirmed.Store(true)
				s.openedAt.Store(now)
			}
		}
	})
}

// hearsWithin: from writes to `to` every 100 ms until heard, within d; the time it took (0: not heard)
func hearsWithin(from, to *pqNode, msg string, d time.Duration) time.Duration {
	start := time.Now()
	for time.Since(start) < d {
		if hears(from, to, msg, 500*time.Millisecond) {
			return time.Since(start)
		}
	}
	return 0
}

/********
 * R4-1 *
 ********/

// R4-1: A holds B to PQ and only reads; B, past SessionMax, does not hold A, and writes. A answers B's classic init
// with a PQ init of its own (B takes a peer's PQ init past SessionMax): a session, and B's traffic over it.
func TestPQHeldReceiverPastSessionMax(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, PQConfig{Enabled: true, SessionMax: 1})
	c := lightPC(t)
	deliverTo(b, edOf(c), pqInitFrom(t, c, b.pc)) // a filler: B at SessionMax
	knows(t, a.pc, b.pc)
	bKey := b.key()
	a.pc.pq.markSticky(&bKey, b.pc.pqOwn().notAfter, true) // an earlier session
	linkPQ(t, a, b)
	streamCount(b, a, "warm", 2*time.Second)
	if s, g := streamCount(b, a, "B to A", 2*time.Second); g < s*9/10 {
		t.Fatalf("only B writes, B past SessionMax, A holds B: %d of %d heard; A %s, B %s; A sent PQ init %d", g, s, session(a, b), session(b, a), a.sent[sessionTypePQInit].Load())
	}
	if session(a, b) != "pq" {
		t.Fatalf("A's session: %s", session(a, b))
	}
}

/********
 * R4-2 *
 ********/

// R4-2: B past SessionMax lost its PQ session with A and its hold on A; A, confirmed, holds B and writes. B answers
// A's PQ traffic with a PQ init (by the hard limit, not SessionMax): both ways again in a second or so, not after A's
// session expires (idleTimeout).
func TestPQReplyPastSessionMax(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, PQConfig{Enabled: true, SessionMax: 1})
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic over PQ")
	}
	aKey := a.key()
	var gone *sessionInfo
	phony.Block(&b.pc.sessions, func() {
		gone = b.pc.sessions.sessions[aKey]
		b.pc.sessions._put(aKey, nil)
	})
	phony.Block(gone, func() { gone.timer.Stop() })
	b.pc.pq.mu.Lock()
	b.pc.pq.stickyLRU.Remove(b.pc.pq.sticky[aKey])
	delete(b.pc.pq.sticky, aKey)
	b.pc.pq.mu.Unlock()
	c := lightPC(t)
	deliverTo(b, edOf(c), pqInitFrom(t, c, b.pc)) // B at SessionMax
	if took := hearsWithin(a, b, "A to B", 6*time.Second); took == 0 {
		t.Fatalf("A to B not heard in 6 s: A %s, B %s; B sent PQ init %d", session(a, b), session(b, a), b.sent[sessionTypePQInit].Load())
	}
	if !hears(b, a, "B to A", 3*time.Second) {
		t.Fatalf("B to A not heard: A %s, B %s", session(a, b), session(b, a))
	}
}

// R4-2 (Q44 of the third round, reversed by it): forged PQ traffic claimed from a key with a classic session here
// gets one PQ init past SessionMax (PQ traffic: its sender has a PQ session with us and wants PQ, which SessionMax
// does not refuse it), and none at the hard limit.
func TestPQReplyInitPastSessionMax(t *testing.T) {
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1})
	c := lightPC(t)
	deliverTo(n, edOf(c), pqInitFrom(t, c, n.pc)) // a filler: at SessionMax
	classicPeer := func() edPub {
		q := lightPC(t)
		qk := edOf(q)
		deliverTo(n, qk, classicInitFrom(t, q, n.pc))
		knows(t, n.pc, q)
		return qk
	}
	qk := classicPeer()
	before := n.sent[sessionTypePQInit].Load()
	deliverTo(n, qk, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	if got := n.sent[sessionTypePQInit].Load() - before; got != 1 {
		t.Fatalf("past SessionMax: %d PQ inits in reply to PQ traffic of a key with a classic session, want 1", got)
	}
	fill(t, n, n.pc.pq.hardMax())
	rk := classicPeer()
	before = n.sent[sessionTypePQInit].Load()
	deliverTo(n, rk, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	if got := n.sent[sessionTypePQInit].Load() - before; got != 0 {
		t.Fatalf("at the hard limit: %d PQ inits in reply to PQ traffic", got)
	}
}

/********
 * R4-3 *
 ********/

// R4-3: an attacker fills B's table with PQ sessions of its own keys and keeps them in use; A, a genuine peer held to
// PQ, is quiet longer than evictIdle. The attacker's next PQ init does not push A's session out (a key held to PQ
// keeps its session while anything opened under it in idleTimeout): both ways still go.
func TestPQHeldSessionNotEvicted(t *testing.T) {
	t.Parallel()
	var logB logSink
	a := newPQNode(t, pqOn)
	b := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1, Logf: logB.f})
	b.pc.sessions.evictIdle = time.Second
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic over PQ")
	}
	aKey := a.key()
	if !b.pc.pq.isSticky(&aKey) {
		t.Fatal("setup: B does not hold A to PQ")
	}
	att := fill(t, b, b.pc.pq.hardMax())
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			inUse(b, att) // a packet of the attacker's that opens, every 300 ms
			time.Sleep(300 * time.Millisecond)
		}
	}()
	defer func() { stop.Store(true); wg.Wait() }()
	before := sessionOf(b, aKey)
	time.Sleep(2 * time.Second) // A and B quiet, twice evictIdle
	last := lightPC(t)
	deliverTo(b, edOf(last), pqInitFrom(t, last, b.pc))
	if sessionOf(b, aKey) != before {
		t.Fatal("the attacker's PQ init pushed out the session of a peer held to PQ, quiet for twice evictIdle")
	}
	s1, g1 := streamCount(a, b, "A to B", 2*time.Second)
	s2, g2 := streamCount(b, a, "B to A", 2*time.Second)
	if g1 < s1*9/10 || g2 < s2*9/10 {
		t.Fatalf("A and B with the attacker's sessions in use: A to B %d/%d, B to A %d/%d", g1, s1, g2, s2)
	}
	logSync(b.pc)
	if logB.count("each in use") == 0 {
		t.Fatalf("no line of the refusal: %q", logB.all())
	}
}

// R4-3 (Q13, Q17, Q18): at the hard limit, of the PQ sessions not in use, one nothing opened under goes before a
// confirmed one (even a newer one); of confirmed ones, the one opened under longest ago (not the oldest started);
// one opened 15 s ago is not in use (evictIdle, 10 s). A key held to PQ: its session, opened 30 s ago, stays (in use
// until idleTimeout) while one that may be classic goes; idle past idleTimeout, it goes only once no other may.
func TestPQEvictionOrder(t *testing.T) {
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1})
	hard := n.pc.pq.hardMax()
	keys := fill(t, n, hard)
	now := n.pc.pq.now()
	set := func(k edPub, confirmed bool, ago time.Duration) {
		phony.Block(&n.pc.sessions, func() {
			s := n.pc.sessions.sessions[k]
			s.confirmed.Store(confirmed)
			s.openedAt.Store(now.Add(-ago).UnixNano())
		})
	}
	for i, k := range keys {
		switch i {
		case 0:
			set(k, true, 15*time.Second) // started first, opened 15 s ago
		case 1:
			set(k, true, 30*time.Second) // started second, opened 30 s ago: goes first of the confirmed
		case 2:
			set(k, true, 30*time.Second) // held to PQ below: in use until idleTimeout
		case hard - 1:
			set(k, false, 0) // the newest, nothing opened under it: goes before any confirmed
		default:
			set(k, true, 0)
		}
	}
	held := keys[2]
	n.pc.pq.markSticky(&held, uint64(time.Now().Add(time.Hour).Unix()), true)
	pqWith := func(k edPub) bool { s := sessionOf(n, k); return s != nil && s.pq }
	more := func() edPub {
		p := lightPC(t)
		k := edOf(p)
		deliverTo(n, k, pqInitFrom(t, p, n.pc))
		return k
	}
	k1 := more()
	if !pqWith(k1) || pqWith(keys[hard-1]) || !pqWith(keys[0]) || !pqWith(keys[1]) {
		t.Fatalf("one nothing opened under not first to go: new %v, unconfirmed %v, confirmed idle %v %v", pqWith(k1), pqWith(keys[hard-1]), pqWith(keys[0]), pqWith(keys[1]))
	}
	set(k1, true, 0)
	k2 := more()
	if !pqWith(k2) || pqWith(keys[1]) || !pqWith(keys[0]) || !pqWith(held) {
		t.Fatalf("of confirmed ones, not the one opened under longest ago that may be classic: new %v, opened 30 s ago %v, 15 s ago %v, held, 30 s ago %v",
			pqWith(k2), pqWith(keys[1]), pqWith(keys[0]), pqWith(held))
	}
	set(k2, true, 0)
	k3 := more()
	if !pqWith(k3) || pqWith(keys[0]) || !pqWith(held) {
		t.Fatalf("a held key's session went before one that may be classic: new %v, 15 s ago %v, held %v", pqWith(k3), pqWith(keys[0]), pqWith(held))
	}
	set(k3, true, 0)
	if k := more(); pqWith(k) || !pqWith(held) {
		t.Fatalf("every other in use, the held key's session opened under 30 s ago: new taken %v, held kept %v", pqWith(k), pqWith(held))
	}
	set(held, true, n.pc.sessions.idleTimeout+time.Second)
	if k := more(); !pqWith(k) || pqWith(held) {
		t.Fatalf("every other in use, the held key's session idle past idleTimeout: new taken %v, held gone %v", pqWith(k), !pqWith(held))
	}
}

// R4-3, R4-1 of the server's: the time of the last packet opened under a session moves only for packets that open
// under its keys (the genuine peer's): not for forged PQ traffic, forged classic traffic, a changed copy of a real
// packet, or one replayed (TestPQReplayNoRemark).
func TestPQOpenedAtOnlyByPeer(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	captured := make(chan []byte, 1)
	tap := func(d []byte) bool {
		if d[0] == sessionTypePQTraffic {
			select {
			case captured <- append([]byte(nil), d...):
			default:
			}
		}
		return false
	}
	a.tap.Store(&tap)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic over PQ")
	}
	a.tap.Store(nil)
	real := <-captured
	time.Sleep(300 * time.Millisecond)
	syncSessions(b)
	aKey := a.key()
	info := sessionOf(b, aKey)
	opened := info.openedAt.Load()
	changed := append([]byte(nil), real...)
	changed[len(changed)-1] ^= 1
	for _, d := range [][]byte{
		junk(sessionTypePQTraffic, pqTrafficOverheadMin),
		junk(sessionTypePQTraffic, 200),
		junk(sessionTypeTraffic, 200),
		append(allocBytes(0), changed...),
	} {
		deliverTo(b, aKey, d)
		if info.openedAt.Load() != opened {
			t.Fatalf("a packet that does not open under the session (type %#x, %d bytes) moved the time of the last packet opened", d[0], len(d))
		}
	}
	if !hears(a, b, "genuine", 3*time.Second) {
		t.Fatal("no traffic")
	}
	syncSessions(b)
	if info.openedAt.Load() <= opened {
		t.Fatal("a packet of the peer's did not move the time of the last packet opened")
	}
}

// R4-3 (Q11): the hard limit is SessionMax and a quarter of it more, at least 64 more.
func TestPQHardMaxFormula(t *testing.T) {
	for _, c := range []struct{ max, want int }{{0, 2048 + 512}, {1, 65}, {100, 164}, {256, 320}, {1024, 1280}} {
		pc := newBarePC(t)
		pc.SetPQ(PQConfig{Enabled: true, SessionMax: c.max})
		if got := pc.pq.hardMax(); got != c.want {
			t.Errorf("SessionMax %d: hard limit %d, want %d", c.max, got, c.want)
		}
	}
}

// R3-3: keys held to PQ (as an attacker can make its own) do not pass the hard limit either, some of them in use.
func TestPQHardLimitSticky(t *testing.T) {
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1})
	hard := n.pc.pq.hardMax()
	for i := 0; i < hard+15; i++ {
		p := lightPC(t)
		k := edOf(p)
		n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true)
		n.pc.sessions.handleData(nil, &k, pqInitFrom(t, p, n.pc))
		if i%8 == 0 {
			inUse(n, []edPub{k})
		}
	}
	phony.Block(&n.pc.sessions, func() {})
	if got := n.pc.PQSessionCount(); got > hard {
		t.Fatalf("%d PQ sessions of keys held to PQ, the hard limit %d", got, hard)
	}
}

/*********
 * R4B-1 *
 *********/

// R4B-1: a churn of PQ inits at the hard limit (each one pushes one out) keeps the sessions of the hard limit alive,
// not those of the inits: the session that goes has its timer stopped, and is let go at once (held for idleTimeout
// instead, each would hold some 6.5 KB, the parsed init's state, for a minute). Counted by weak pointers.
func TestPQEvictFreesMemory(t *testing.T) {
	b := newPQNode(t, PQConfig{Enabled: true, SessionMax: 64}) // hard limit 128; no link
	// what b sends is counted and dropped here: the network would queue it for keys it has no path to, and the address
	// in the queue (a slice of the session's key, as upstream's) would hold the session while it waits
	drop := func([]byte) bool { return true }
	b.tap.Store(&drop)
	forge := lightPC(t)
	const n = 1000
	var made []weak.Pointer[sessionInfo]
	var all []*sessionInfo // held until each one's actor is done (the stop of its timer is a message to it)
	h0 := heapNow()
	for i := 0; i < n; i++ {
		_, priv, _ := ed25519.GenerateKey(nil)
		k, d := forgeInit(t, forge, b.pc, priv)
		b.pc.sessions.handleData(nil, &k, d)
		phony.Block(&b.pc.sessions, func() {
			if s := b.pc.sessions.sessions[k]; s != nil {
				made, all = append(made, weak.Make(s)), append(all, s)
			}
		})
	}
	// each session's own work done (its ack sealed and sent), pushed out or not
	for deadline := time.Now().Add(30 * time.Second); b.sent[sessionTypePQAck].Load() < n; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d acks of %d in 30 s", b.sent[sessionTypePQAck].Load(), n)
		}
	}
	for _, s := range all {
		phony.Block(s, func() {})
	}
	all = nil
	h1 := heapNow()
	alive := 0
	for _, w := range made {
		if w.Value() != nil {
			alive++
		}
	}
	t.Logf("%d PQ inits, hard limit %d: %d PQ sessions, %d of the %d made alive; heap +%.1f MB", n, b.pc.pq.hardMax(), b.pc.PQSessionCount(),
		alive, len(made), float64(int64(h1)-int64(h0))/1e6)
	// the sessions of the hard limit, and what the process's goroutines still hold of the last ones (up to a few tens);
	// every one pushed out held by its timer instead: all of them
	if alive > 2*b.pc.pq.hardMax() {
		t.Fatalf("%d sessions alive with at most %d up: the ones pushed out are still held", alive, b.pc.pq.hardMax())
	}
}

/*****************
 * R4-4 / R4B-2 *
 *****************/

// r4OneWay: a and b with a confirmed PQ session (or classic, pq false), idleTimeout idle on both
func r4OneWay(t *testing.T, pq bool, idle time.Duration) (a, b *pqNode) {
	t.Helper()
	cfg := pqOn
	if !pq {
		cfg = PQConfig{}
	}
	a, b = newPQNode(t, cfg), newPQNode(t, cfg)
	for _, n := range []*pqNode{a, b} {
		n.pc.sessions.idleTimeout = idle
	}
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	want := "classic"
	if pq {
		want = "pq"
	}
	waitSessions(t, a, b, want, 10*time.Second)
	if !hears(a, b, "x", 3*time.Second) || !hears(b, a, "y", 3*time.Second) {
		t.Fatal("no traffic")
	}
	return
}

func handshakePackets(ns ...*pqNode) (n int64) {
	for _, x := range ns {
		for _, typ := range []byte{sessionTypeInit, sessionTypeAck, sessionTypePQInit, sessionTypePQAck} {
			n += x.sent[typ].Load()
		}
	}
	return
}

// dropFirstProbe: a tap that drops the first empty PQ packet (a keepalive) the node sends
func dropFirstProbe() *func([]byte) bool {
	var dropped atomic.Bool
	tap := func(d []byte) bool {
		return d[0] == sessionTypePQTraffic && len(d) < 60 && dropped.CompareAndSwap(false, true)
	}
	return &tap
}

// R4-4, R4B-2: a one-way flow, the reader's first keepalive lost: the next one (a quarter of idleTimeout on) still
// comes before the writer's session would go. No handshake, nothing lost.
func TestPQKeepaliveLost(t *testing.T) {
	t.Parallel()
	a, b := r4OneWay(t, true, 2*time.Second) // 2 s: the sleep and the setup well inside idleTimeout
	time.Sleep(600 * time.Millisecond)
	b.tap.Store(dropFirstProbe())
	bKey := b.key()
	before, hs := sessionOf(a, bKey), handshakePackets(a, b)
	s, g := streamCount(a, b, "one way", 4*time.Second)
	b.tap.Store(nil)
	if sessionOf(a, bKey) != before || handshakePackets(a, b) != hs || g < s-1 {
		t.Fatalf("one lost keepalive: the writer's session replaced %v, %d handshake packets, %d of %d heard",
			sessionOf(a, bKey) != before, handshakePackets(a, b)-hs, g, s)
	}
}

// The same with a dense flow (a packet a millisecond).
func TestPQKeepaliveLostDense(t *testing.T) {
	t.Parallel()
	a, b := r4OneWay(t, true, 2*time.Second) // 2 s: the sleep and the setup well inside idleTimeout
	time.Sleep(600 * time.Millisecond)
	b.tap.Store(dropFirstProbe())
	for len(b.heard) > 0 {
		<-b.heard
	}
	bKey := b.key()
	before, hs := sessionOf(a, bKey), handshakePackets(a, b)
	for stop := time.Now().Add(3 * time.Second); time.Now().Before(stop); time.Sleep(time.Millisecond) {
		a.pc.WriteTo([]byte("dense"), types.Addr(b.pub))
	}
	b.tap.Store(nil)
	if sessionOf(a, bKey) != before || handshakePackets(a, b) != hs {
		t.Fatalf("a dense one-way flow, one keepalive lost: the writer's session replaced %v, %d handshake packets", sessionOf(a, bKey) != before, handshakePackets(a, b)-hs)
	}
}

// R4-4 (Q35, Q37): the keepalive of a one-way PQ flow goes about four times an idleTimeout, not once a packet.
func TestPQKeepaliveRate(t *testing.T) {
	t.Parallel()
	a, b := r4OneWay(t, true, 2*time.Second) // 2 s: the sleep and the setup well inside idleTimeout
	time.Sleep(600 * time.Millisecond)
	var sent atomic.Int64
	tap := func(d []byte) bool {
		if d[0] == sessionTypePQTraffic {
			sent.Add(1)
		}
		return false
	}
	b.tap.Store(&tap)
	s, _ := streamCount(a, b, "one way", 3*time.Second)
	b.tap.Store(nil)
	if got := sent.Load(); got < 6 || got > 24 {
		t.Fatalf("the reader of a one-way flow (%d packets in 3 s, idleTimeout 1 s) sent %d PQ packets, want about 12", s, got)
	}
}

// Q39: over a classic session the reader of a one-way flow sends nothing (as upstream); over PQ, its keepalives.
func TestPQKeepaliveCost(t *testing.T) {
	t.Parallel()
	for _, pq := range []bool{true, false} {
		name := map[bool]string{true: "pq", false: "classic"}[pq]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, b := r4OneWay(t, pq, time.Second)
			time.Sleep(600 * time.Millisecond)
			var n, size atomic.Int64
			tap := func(d []byte) bool {
				if d[0] == sessionTypeTraffic || d[0] == sessionTypePQTraffic {
					n.Add(1)
					size.Add(int64(len(d)))
				}
				return false
			}
			b.tap.Store(&tap)
			emptyA := a.empty.Load()
			s, g := streamCount(a, b, "one way", 3*time.Second)
			b.tap.Store(nil)
			t.Logf("%s, idleTimeout 1 s, one way 3 s: %d of %d heard; the reader sent %d packets, %d bytes", name, g, s, n.Load(), size.Load())
			if !pq && (n.Load() != 0 || a.empty.Load() != emptyA) {
				t.Fatalf("classic: the reader sent %d packets on a one-way flow", n.Load())
			}
		})
	}
}

/********
 * R4-5 *
 ********/

// replayAfterReinit: A's traffic to B captured; A re-inits (forged traffic to A asks for it), B answers; the captured
// packets replayed to B open no more
func replayAfterReinit(t *testing.T, cfg PQConfig) {
	a, b := newPQNode(t, cfg), newPQNode(t, cfg)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	traffic, initType := byte(sessionTypeTraffic), byte(sessionTypeInit)
	if cfg.Enabled {
		waitSessions(t, a, b, "pq", 10*time.Second)
		traffic, initType = sessionTypePQTraffic, sessionTypePQInit
	}
	var mu sync.Mutex
	var caps [][]byte
	tap := func(d []byte) bool {
		if d[0] == traffic {
			mu.Lock()
			caps = append(caps, append([]byte(nil), d...))
			mu.Unlock()
		}
		return false
	}
	a.tap.Store(&tap)
	for i := 0; i < 20; i++ {
		a.pc.WriteTo([]byte(fmt.Sprintf("cap %d", i)), types.Addr(b.pub))
		b.pc.WriteTo([]byte(fmt.Sprintf("back %d", i)), types.Addr(a.pub))
		time.Sleep(20 * time.Millisecond)
	}
	a.tap.Store(nil)
	time.Sleep(1100 * time.Millisecond) // the re-init numbered after the session's seq
	bKey, aKey := b.key(), a.key()
	sent := a.sent[initType].Load()
	for deadline := time.Now().Add(5 * time.Second); a.sent[initType].Load() == sent; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("A sent no re-init")
		}
		deliverTo(a, bKey, junk(traffic, 120))
	}
	time.Sleep(500 * time.Millisecond)
	if !hears(a, b, "after reinit", 3*time.Second) {
		t.Fatal("no traffic after the re-init")
	}
	time.Sleep(200 * time.Millisecond)
	for len(b.heard) > 0 {
		<-b.heard
	}
	mu.Lock()
	replay := caps
	mu.Unlock()
	for _, d := range replay {
		deliverTo(b, aKey, append(allocBytes(0), d...))
	}
	opened := 0
	for deadline := time.After(500 * time.Millisecond); ; {
		select {
		case m := <-b.heard:
			if strings.HasPrefix(m, "cap ") {
				opened++
			}
			continue
		case <-deadline:
		}
		break
	}
	if opened != 0 {
		t.Fatalf("%d of %d captured packets opened again after a re-init", opened, len(replay))
	}
}

// R4-5: after a re-init (one forged packet asks for one), packets captured before it do not open again at the peer.
func TestPQReplayAfterReinit(t *testing.T) { t.Parallel(); replayAfterReinit(t, pqOn) }

// R4-5: the same over classic sessions (the replay state is the same code): stricter than upstream, nothing on the
// wire changed.
func TestPQReplayAfterReinitClassic(t *testing.T) { t.Parallel(); replayAfterReinit(t, PQConfig{}) }

/********
 * R4-6 *
 ********/

// R4-6: forged PQ traffic from random keys at both ends drains the bucket of answers to unknown keys; two new
// contacts still come up PQ (their PQInfos go by the bucket of signed contacts, or by none for our own data).
func TestPQFloodKeepsNewContacts(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			for _, n := range []*pqNode{a, b} {
				var k edPub
				binary.BigEndian.PutUint64(k[:], uint64(i)) // a random key: no ed25519 point needed for no entry
				k[31] = byte(i >> 8)
				n.pc.sessions.handleData(nil, &k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
			}
			if i%10 == 0 {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	defer func() { stop.Store(true); wg.Wait() }()
	time.Sleep(time.Second)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
}

// R4-6: our PQInfo for an upgrade (after a peer's signed classic init) that gets no token schedules the upgrade
// again later, rather than dropping it.
func TestPQStarvedUpgradeLater(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	n.pc.pq.mu.Lock()
	n.pc.pq.signedBucket = pqBucket{at: time.Now().Add(time.Hour)} // empty, for the next hour
	n.pc.pq.mu.Unlock()
	p := lightPC(t)
	k := edOf(p)
	deliverTo(n, k, classicInitFrom(t, p, n.pc))
	var retry bool
	phony.Block(&n.pc.sessions, func() { retry = n.pc.sessions.pqRetry[k] })
	if n.sent[sessionTypePQInfo].Load() != 0 || !retry {
		t.Fatalf("no token for our PQInfo: %d PQInfos, an upgrade scheduled %v", n.sent[sessionTypePQInfo].Load(), retry)
	}
}

// R3-5 (N-1 of the third round), R4-1: an answer to a forged classic init claimed from a known key held to PQ (our PQ
// init now, as it has no session) takes a token: with the known bucket empty and the per-key limits flushed, none
// goes.
func TestPQKnownAskBucketEmpty(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true)
	answers := func() int64 { return n.sent[sessionTypePQInfo].Load() + n.sent[sessionTypePQInit].Load() }
	deliverTo(n, k, junk(sessionTypeInit, sessionInitSize))
	if answers() != 1 || n.sent[sessionTypePQInit].Load() != 1 {
		t.Fatalf("setup: %d answers (%d PQ inits) to a forged classic init of a held key", answers(), n.sent[sessionTypePQInit].Load())
	}
	n.pc.pq.mu.Lock()
	n.pc.pq.knownBucket = pqBucket{at: time.Now().Add(time.Hour)}
	n.pc.pq.limits = make(map[edPub]*list.Element)
	n.pc.pq.limitsLRU.Init()
	n.pc.pq.mu.Unlock()
	deliverTo(n, k, junk(sessionTypeInit, sessionInitSize))
	if got := answers(); got != 1 {
		t.Fatalf("%d answers in all, the known bucket empty", got)
	}
}

// R4-6 (Q28), reversed by R6A-3: our PQInfo in reply to a PQ init sealed to a key not ours (nothing checked it) takes
// no token (it is half the size of the ask), only the key's pqInfoInterval.
func TestPQUnknownKeyInfoToken(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	data := pqInitFrom(t, p, n.pc)
	binary.BigEndian.PutUint64(data[1:9], binary.BigEndian.Uint64(data[1:9])+12345) // a key number not ours
	deliverTo(n, k, append(allocBytes(0), data...))
	if n.sent[sessionTypePQInfo].Load() == 0 {
		t.Fatal("setup: no PQInfo to a PQ init sealed to a key not ours")
	}
	n.pc.pq.mu.Lock()
	n.pc.pq.knownBucket = pqBucket{at: time.Now().Add(time.Hour)}
	n.pc.pq.limits = make(map[edPub]*list.Element)
	n.pc.pq.limitsLRU.Init()
	n.pc.pq.unknownBucket = pqBucket{at: time.Now().Add(time.Hour)}
	n.pc.pq.mu.Unlock()
	before := n.sent[sessionTypePQInfo].Load()
	deliverTo(n, k, append(allocBytes(0), data...))
	if got := n.sent[sessionTypePQInfo].Load() - before; got != 1 {
		t.Fatalf("%d PQInfos with the buckets empty for a PQ init sealed to a key not ours, want 1", got)
	}
	deliverTo(n, k, data)
	if got := n.sent[sessionTypePQInfo].Load() - before; got != 1 {
		t.Fatalf("%d PQInfos within pqInfoInterval, want 1", got)
	}
}

/**********
 * R4B-3 *
 **********/

// P29: past SessionMax, a key that must be PQ (Required) still gets a PQ init of ours when data waits for it.
func TestPQRequiredPastSessionMax(t *testing.T) {
	r := lightPC(t)
	rk := edOf(r)
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1, Required: func(k ed25519.PublicKey) bool { return bytes.Equal(k, rk[:]) }})
	c := lightPC(t)
	deliverTo(n, edOf(c), pqInitFrom(t, c, n.pc)) // a filler: at SessionMax
	knows(t, n.pc, r)
	n.pc.WriteTo([]byte("data"), types.Addr(r.publicEd[:]))
	phony.Block(&n.pc.sessions, func() {})
	if got := n.sent[sessionTypePQInit].Load(); got != 1 {
		t.Fatalf("past SessionMax, data to a Required key: %d PQ inits, want 1", got)
	}
}

// P30: with exactly SessionMax PQ sessions up, no PQ init or PQInfo of ours to a key that may be classic.
func TestPQAtSessionMaxExactly(t *testing.T) {
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1})
	c := lightPC(t)
	deliverTo(n, edOf(c), pqInitFrom(t, c, n.pc))
	if n.pc.PQSessionCount() != 1 {
		t.Fatal("setup")
	}
	q := lightPC(t)
	qk := edOf(q)
	knows(t, n.pc, q)
	before := n.sent[sessionTypePQInit].Load() + n.sent[sessionTypePQInfo].Load()
	deliverTo(n, qk, classicInitFrom(t, q, n.pc))
	n.pc.WriteTo([]byte("data"), types.Addr(q.publicEd[:]))
	phony.Block(&n.pc.sessions, func() {})
	if got := n.sent[sessionTypePQInit].Load() + n.sent[sessionTypePQInfo].Load() - before; got != 0 {
		t.Fatalf("at SessionMax exactly: %d PQ inits or PQInfos to a key that may be classic", got)
	}
}

// Q2: a newer signed classic init does not replace a confirmed PQ session with a packet opened half an idleTimeout
// ago.
func TestPQClassicInitOpenedWindow(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	peer := lightPC(t)
	k := edOf(peer)
	deliverTo(n, k, pqInitFrom(t, peer, n.pc))
	pq := sessionOf(n, k)
	var initSeq uint64
	phony.Block(&n.pc.sessions, func() { initSeq = pq.initSeq })
	pq.confirmed.Store(true)
	pq.openedAt.Store(n.pc.pq.now().Add(-n.pc.sessions.idleTimeout / 2).UnixNano())
	deliverTo(n, k, classicInitSeq(t, peer, n.pc, initSeq+1))
	if sessionOf(n, k) != pq {
		t.Fatal("a newer classic init replaced a PQ session with a packet opened half an idleTimeout ago")
	}
}

// Q31, Q32, Q33: PQ off, PQ traffic of a key with no session gets one classic init in initReplyInterval; a packet
// too short to be PQ traffic, none; a key with a session, none.
func TestPQOffReplyRules(t *testing.T) {
	n := newPQNode(t, PQConfig{}) // no link
	k := newPeerEd(t)
	for i := 0; i < 10; i++ {
		n.pc.sessions.handleData(nil, &k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	}
	phony.Block(&n.pc.sessions, func() {})
	if got := n.sent[sessionTypeInit].Load(); got != 1 {
		t.Fatalf("PQ off: %d classic inits for 10 PQ packets of a key with no session, want 1", got)
	}
	short := newPeerEd(t)
	deliverTo(n, short, junk(sessionTypePQTraffic, pqTrafficOverheadMin-1))
	p := lightPC(t)
	pk := edOf(p)
	deliverTo(n, pk, classicInitFrom(t, p, n.pc))
	inits := n.sent[sessionTypeInit].Load()
	deliverTo(n, pk, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	if got := n.sent[sessionTypeInit].Load(); got != inits || inits != 1 {
		t.Fatalf("PQ off: a short PQ packet or one of a key with a session answered (%d inits, then %d)", inits, got)
	}
}

// Q41: a PQ init repeated (the same one again) to a PQ session up gets no empty packet besides its re-ack.
func TestPQRepeatInitNoProbe(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	init := pqInitFrom(t, p, n.pc)
	deliverTo(n, k, append(allocBytes(0), init...))
	before := n.sent[sessionTypePQTraffic].Load()
	deliverTo(n, k, append(allocBytes(0), init...))
	time.Sleep(pqInitRetry/2 + 100*time.Millisecond)
	deliverTo(n, k, append(allocBytes(0), init...))
	if got := n.sent[sessionTypePQTraffic].Load() - before; got != 0 {
		t.Fatalf("%d PQ packets in reply to a repeated PQ init", got)
	}
}

// Q23: a PQ init of ours under way (not one sent in reply) is not sent again on a forged packet.
func TestPQOwnPendingNotResentOnForged(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), false) })
	before := n.sent[sessionTypePQInit].Load()
	deliverTo(n, k, junk(sessionTypeTraffic, sessionTrafficOverheadMin))
	if got := n.sent[sessionTypePQInit].Load() - before; got != 0 {
		t.Fatalf("%d PQ inits sent again for a forged packet while our own is under way", got)
	}
}

// N13: PQ traffic to a classic session: our PQInfo if the peer's ML-KEM key is unknown, our PQ init if it is known.
func TestPQPQTrafficToClassic(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	q, r := lightPC(t), lightPC(t)
	qk, rk := edOf(q), edOf(r)
	deliverTo(n, qk, classicInitFrom(t, q, n.pc))
	deliverTo(n, rk, classicInitFrom(t, r, n.pc))
	knows(t, n.pc, r)
	n.pc.pq.mu.Lock()
	n.pc.pq.limits = make(map[edPub]*list.Element) // our PQInfo after the handshakes forgotten
	n.pc.pq.limitsLRU.Init()
	n.pc.pq.mu.Unlock()
	infos, inits := n.sent[sessionTypePQInfo].Load(), n.sent[sessionTypePQInit].Load()
	deliverTo(n, qk, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	deliverTo(n, rk, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	if n.sent[sessionTypePQInfo].Load()-infos != 1 || n.sent[sessionTypePQInit].Load()-inits != 1 {
		t.Fatalf("PQ traffic to classic sessions: %d PQInfos (key unknown), %d PQ inits (key known), want 1 and 1",
			n.sent[sessionTypePQInfo].Load()-infos, n.sent[sessionTypePQInit].Load()-inits)
	}
}

// M8: traffic that does not open under a classic session gets one init in reply in initReplyInterval.
func TestPQInitReplyLimitedSession(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	deliverTo(n, k, classicInitFrom(t, p, n.pc))
	if s := sessionOf(n, k); s == nil || s.pq {
		t.Fatal("setup: no classic session")
	}
	before := n.sent[sessionTypeInit].Load()
	for i := 0; i < 10; i++ {
		n.pc.sessions.handleData(nil, &k, junk(sessionTypeTraffic, sessionTrafficOverheadMin+20))
	}
	phony.Block(&n.pc.sessions, func() {})
	syncSessions(n)
	if got := n.sent[sessionTypeInit].Load() - before; got != 1 {
		t.Fatalf("%d inits in reply to 10 packets that do not open under a classic session, want 1", got)
	}
}

// M9: classic traffic of a key with no session gets one init in reply in initReplyInterval.
func TestPQInitReplyLimitedNoSession(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	k := newPeerEd(t)
	for i := 0; i < 10; i++ {
		n.pc.sessions.handleData(nil, &k, junk(sessionTypeTraffic, sessionTrafficOverheadMin+20))
	}
	phony.Block(&n.pc.sessions, func() {})
	if got := n.sent[sessionTypeInit].Load(); got != 1 {
		t.Fatalf("%d inits in reply to 10 classic packets of a key with no session, want 1", got)
	}
}

// M6: a verified PQ ack with no classic session beside holds the peer to PQ at once, before any of its traffic opens.
func TestPQAckAloneSticky(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	bKey := b.key()
	a.pc.SetPQ(PQConfig{Enabled: true, Required: func(k ed25519.PublicKey) bool { return bytes.Equal(k, b.pub) }})
	knows(t, a.pc, b.pc)
	b.dropType[sessionTypePQTraffic].Store(true) // nothing of B's opens at A
	linkPQ(t, a, b)
	for deadline := time.Now().Add(5 * time.Second); stickyFor(a.pc, bKey) == nil; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no hold on B at A after its verified ack: A %s, B %s; B sent %d PQ acks", session(a, b), session(b, a), b.sent[sessionTypePQAck].Load())
		}
		a.pc.WriteTo([]byte("x"), types.Addr(b.pub))
	}
}

// M16: the PQInfo signature is over its context string and the fields, not over the bytes on the wire alone.
func TestPQInfoSigContext(t *testing.T) {
	pc := newBarePC(t)
	info := pc.pqOwn().info
	raw, sig := info[:len(info)-edSigSize], info[len(info)-edSigSize:]
	pub := pc.publicEd[:]
	if ed25519.Verify(pub, raw, sig) {
		t.Fatal("the PQInfo signature verifies over the wire bytes alone: no context")
	}
	if !ed25519.Verify(pub, append([]byte(pqInfoSigCtx), raw...), sig) {
		t.Fatal("the PQInfo signature is not over the context and the fields")
	}
}

// M18: a message of MTU() bytes over a PQ session, every varint of the header at its longest, fits the network's
// MTU.
func TestPQMTUWithLongVarints(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	deliverTo(n, k, pqInitFrom(t, p, n.pc))
	s := sessionOf(n, k)
	if s == nil || !s.pq {
		t.Fatal("setup: no PQ session")
	}
	phony.Block(s, func() {
		s.sendNonce, s.localKeySeq, s.remoteKeySeq = 1<<63, 1<<63, 1<<63
	})
	s.confirmed.Store(true)
	var size atomic.Int64
	tap := func(d []byte) bool {
		if d[0] == sessionTypePQTraffic {
			size.Store(int64(len(d)))
		}
		return false
	}
	n.tap.Store(&tap)
	n.pc.WriteTo(make([]byte, n.pc.MTU()), types.Addr(p.publicEd[:]))
	syncSessions(n)
	if got := size.Load(); got == 0 || uint64(got) > n.pc.PacketConn.MTU() {
		t.Fatalf("a message of MTU() %d bytes made a PQ packet of %d bytes, the network's MTU %d", n.pc.MTU(), got, n.pc.PacketConn.MTU())
	}
}

// N3: a PQInfo of the key a pending PQ init of ours is sealed to does not reseal it, nor send it again.
func TestPQNoResealSameKey(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	var before []byte
	var tries int
	phony.Block(&n.pc.sessions, func() {
		mgr := &n.pc.sessions
		mgr._startPQ(&k, n.pc.pq.usableKey(&k), false)
		before, tries = mgr.pqPending[k].data, mgr.pqPending[k].tries
	})
	sent := n.sent[sessionTypePQInit].Load()
	deliverTo(n, k, append(allocBytes(0), p.pqOwn().info...)) // the same key again
	var after []byte
	var tries2 int
	phony.Block(&n.pc.sessions, func() {
		if q := n.pc.sessions.pqPending[k]; q != nil {
			after, tries2 = q.data, q.tries
		}
	})
	if !bytes.Equal(before, after) || tries2 != tries || n.sent[sessionTypePQInit].Load() != sent {
		t.Fatalf("a PQInfo of the key the pending init is sealed to: resealed %v, tries %d -> %d, %d more PQ inits sent",
			!bytes.Equal(before, after), tries, tries2, n.sent[sessionTypePQInit].Load()-sent)
	}
}

// M5: two PQ inits crossed: the end with the lower key keeps its own and does not answer the other's.
func TestPQCrossingTieBreak(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	var p *PacketConn
	for {
		p = lightPC(t)
		if bytes.Compare(n.pc.publicEd[:], p.publicEd[:]) < 0 {
			break
		}
	}
	k := edOf(p)
	knows(t, n.pc, p)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), false) })
	acks := n.sent[sessionTypePQAck].Load()
	deliverTo(n, k, pqInitFrom(t, p, n.pc))
	var pending bool
	phony.Block(&n.pc.sessions, func() { pending = n.pc.sessions.pqPending[k] != nil })
	if !pending || n.sent[sessionTypePQAck].Load() != acks {
		t.Fatalf("the lower key, inits crossed: own init kept %v, %d PQ acks sent to the other's", pending, n.sent[sessionTypePQAck].Load()-acks)
	}
}

/*********
 * minor *
 *********/

// A, the lower key, holds B to PQ; a forged packet claimed from B makes A's PQ init sent once in reply, and that is
// lost. B's PQ init crosses it: A's, sent once, gives way to B's, rather than stalling B until it expires.
func TestPQOnceInitYieldsToCrossing(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	a.pc.pq.pendingTimeout = 8 * time.Second
	bKey := b.key()
	knows(t, a.pc, b.pc)
	knows(t, b.pc, a.pc)
	a.pc.pq.markSticky(&bKey, b.pc.pqOwn().notAfter, true)
	var dropped atomic.Bool
	tap := func(d []byte) bool { return d[0] == sessionTypePQInit && dropped.CompareAndSwap(false, true) }
	a.tap.Store(&tap)
	linkPQ(t, a, b)
	deliverTo(a, bKey, junk(sessionTypeTraffic, sessionTrafficOverheadMin)) // forged: A's once-sent init, lost
	a.tap.Store(nil)
	if !dropped.Load() {
		t.Fatal("setup: A's PQ init in reply was not sent")
	}
	if took := hearsWithin(b, a, "B to A", 4*time.Second); took == 0 {
		t.Fatalf("B to A not heard in 4 s (A's once-sent init expires in %v): A %s, B %s", a.pc.pq.pendingTimeout, session(a, b), session(b, a))
	}
}

// _evict does not put back the classic session beside a confirmed PQ session (a stale one, the peer left it): our
// next write does not go out classic.
func TestPQEvictNoStaleClassic(t *testing.T) {
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1}) // no link
	p0 := lightPC(t)
	k0 := edOf(p0)
	deliverTo(n, k0, classicInitFrom(t, p0, n.pc))
	deliverTo(n, k0, pqInitFrom(t, p0, n.pc))
	phony.Block(&n.pc.sessions, func() {
		s := n.pc.sessions.sessions[k0]
		s.confirmed.Store(true) // a packet opened (its hold since ended)
		s.openedAt.Store(n.pc.pq.now().Add(-time.Minute / 2).UnixNano())
	})
	if n.pc.pq.isSticky(&k0) {
		t.Fatal("setup: sticky")
	}
	inUse(n, fill(t, n, n.pc.pq.hardMax()))
	q := lightPC(t)
	deliverTo(n, edOf(q), pqInitFrom(t, q, n.pc)) // k0's session goes
	if s := sessionOf(n, k0); s != nil {
		t.Fatalf("after its eviction, the table holds a session with k0 (PQ %v)", s.pq)
	}
	classic := n.sent[sessionTypeTraffic].Load()
	n.pc.WriteTo([]byte("after eviction"), types.Addr(p0.publicEd[:]))
	phony.Block(&n.pc.sessions, func() {})
	syncSessions(n)
	if got := n.sent[sessionTypeTraffic].Load() - classic; got != 0 {
		t.Fatalf("%d classic packets went by the stale classic session", got)
	}
}

// Forged PQ traffic claimed from a key whose ML-KEM key is known, past SessionMax: no line in the log names the key
// of a packet no one signed.
func TestPQUnsignedNoKeyLogged(t *testing.T) {
	var log logSink
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1, Logf: log.f}) // no link
	c := lightPC(t)
	deliverTo(n, edOf(c), pqInitFrom(t, c, n.pc)) // at SessionMax
	fill(t, n, n.pc.pq.hardMax())                 // and at the hard limit
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true) // its classic asks for a PQ init of ours too
	for _, typ := range []byte{sessionTypePQTraffic, sessionTypeTraffic, sessionTypeInit} {
		deliverTo(n, k, junk(typ, max(pqTrafficOverheadMin, sessionInitSize)))
	}
	logSync(n.pc)
	if got := log.count(fmt.Sprintf("%x", k[:8])); got != 0 {
		t.Fatalf("a line of the log names the key of an unsigned packet: %q", log.all())
	}
}

// Logf may call into the PacketConn (here Debug.GetSessions) for a line logged in the manager's actor: it runs from
// a goroutine of its own, and nothing waits on it.
func TestPQLogfReentrant(t *testing.T) {
	var n *pqNode
	var calls atomic.Int64
	n = newPQNode(t, PQConfig{Enabled: true, SessionMax: 1, Logf: func(string, ...any) {
		calls.Add(1)
		n.pc.Debug.GetSessions()
	}})
	c := lightPC(t)
	deliverTo(n, edOf(c), pqInitFrom(t, c, n.pc)) // at SessionMax
	q := lightPC(t)
	qk := edOf(q)
	knows(t, n.pc, q)
	n.pc.sessions.handleData(nil, &qk, classicInitFrom(t, q, n.pc)) // past SessionMax: a line from the manager's actor
	done := make(chan struct{})
	go func() { phony.Block(&n.pc.sessions, func() {}); logSync(n.pc); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("deadlock: Logf calling Debug.GetSessions (%d lines)", calls.Load())
	}
	if calls.Load() == 0 {
		t.Fatal("setup: no line logged")
	}
}

// pqInitSeq: a PQ init of from's to `to`, its seq given
func pqInitSeq(t *testing.T, from, to *PacketConn, seq uint64) []byte {
	t.Helper()
	toEd := edOf(to)
	own := to.pqOwn()
	key := newPQPeerKey(&toEd, &own.pub, own.seq, own.notAfter)
	cur, _ := newBoxKeys()
	nxt, _ := newBoxKeys()
	secret := newRatchetSecret()
	init := newPQInit(&cur, &nxt, 0, &secret, from.pq.nextSecretNo())
	init.seq = seq
	data, err := init.encrypt(from, sessionTypePQInit, &toEd, key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The seq of an init is in whole seconds: a PQ init of the same second as the one a session took, with other keys,
// is a new one of the peer's (it began anew within the second), and is taken; the same one again is a repeat.
func TestPQSameSecondInit(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	seq := uint64(time.Now().Unix())
	first := pqInitSeq(t, p, n.pc, seq)
	deliverTo(n, k, append(allocBytes(0), first...))
	s := sessionOf(n, k)
	phony.Block(s, func() { s.rx = 1 }) // traffic came: a repeat is not answered
	acks := n.sent[sessionTypePQAck].Load()
	deliverTo(n, k, append(allocBytes(0), first...))
	if got := n.sent[sessionTypePQAck].Load() - acks; got != 0 {
		t.Fatalf("a repeated PQ init answered (%d acks)", got)
	}
	deliverTo(n, k, pqInitSeq(t, p, n.pc, seq))
	if got := n.sent[sessionTypePQAck].Load() - acks; got != 1 || sessionOf(n, k) != s {
		t.Fatalf("a new PQ init of the same second: %d acks, the same session %v", got, sessionOf(n, k) == s)
	}
}

// pqAckSeq: a PQ ack of from's to `to`, its seq and current key given
func pqAckSeq(t *testing.T, from, to *PacketConn, seq uint64, cur boxPub) []byte {
	t.Helper()
	toEd := edOf(to)
	own := to.pqOwn()
	key := newPQPeerKey(&toEd, &own.pub, own.seq, own.notAfter)
	nxt, _ := newBoxKeys()
	secret := newRatchetSecret()
	ack := newPQInit(&cur, &nxt, 1, &secret, from.pq.nextSecretNo())
	ack.seq = seq
	data, err := ack.encrypt(from, sessionTypePQAck, &toEd, key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The same for a PQ ack: one of the same second as the last one taken, with other keys, is taken (the peer took an
// init of ours of that second and moved on), or the two ends part.
func TestPQSameSecondAck(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), false) })
	seq := uint64(time.Now().Unix())
	cur1, _ := newBoxKeys()
	cur2, _ := newBoxKeys()
	deliverTo(n, k, pqAckSeq(t, p, n.pc, seq, cur1))
	s := sessionOf(n, k)
	if s == nil || !s.pq {
		t.Fatal("setup: no PQ session from the ack")
	}
	current := func() (c boxPub) { phony.Block(s, func() { c = s.current }); return }
	if current() != cur1 {
		t.Fatal("setup: the session not under the ack's keys")
	}
	deliverTo(n, k, pqAckSeq(t, p, n.pc, seq, cur1)) // the same keys again: not taken
	if current() != cur1 {
		t.Fatal("an ack of the same second and keys moved the session")
	}
	deliverTo(n, k, pqAckSeq(t, p, n.pc, seq, cur2))
	if current() != cur2 {
		t.Fatal("a PQ ack of the same second with other keys not taken")
	}
}

// Logf's lines wait for its goroutine, at most pqLogQueue of them; the rest are dropped, and their number logged.
func TestPQLogQueueDrops(t *testing.T) {
	pc := newBarePC(t)
	var log logSink
	release := make(chan struct{})
	var first sync.Once
	cfg := pqOn
	cfg.Logf = func(f string, args ...any) {
		first.Do(func() { <-release }) // the first line holds the goroutine
		log.f(f, args...)
	}
	pc.SetPQ(cfg)
	for i := 0; i < pqLogQueue+10; i++ {
		pc.pq.logf("line %d", i)
	}
	close(release)
	logSync(pc)
	if lines := log.all(); len(lines) > pqLogQueue+2 || log.count("dropped") != 1 {
		t.Fatalf("%d lines for %d logged with the queue full, %d of them on the dropped ones", len(lines), pqLogQueue+10, log.count("dropped"))
	}
}

// R4-6: forged PQ traffic from keys unknown here drains their bucket only: our PQInfo after a signed classic init of
// a key unknown here still goes (the bucket of signed contacts).
func TestPQFloodSparesSignedAsks(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	for i := 0; i < 3*int(pqUnsolicitedRate); i++ {
		k := newPeerEd(t)
		n.pc.sessions.handleData(nil, &k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	}
	phony.Block(&n.pc.sessions, func() {})
	p := lightPC(t)
	before := n.sent[sessionTypePQInfo].Load()
	deliverTo(n, edOf(p), classicInitFrom(t, p, n.pc))
	if got := n.sent[sessionTypePQInfo].Load() - before; got != 1 {
		t.Fatalf("after a flood of forged PQ traffic, our PQInfo to a signed classic init: %d, want 1", got)
	}
}

// R4-6: our PQInfo for data of ours waiting for a session takes no token: with both buckets empty it still goes.
func TestPQOwnDataNoToken(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	n.pc.pq.mu.Lock()
	n.pc.pq.knownBucket = pqBucket{at: time.Now().Add(time.Hour)}
	n.pc.pq.unknownBucket = pqBucket{at: time.Now().Add(time.Hour)}
	n.pc.pq.mu.Unlock()
	p := lightPC(t)
	n.pc.WriteTo([]byte("data"), types.Addr(p.publicEd[:]))
	phony.Block(&n.pc.sessions, func() {})
	if got := n.sent[sessionTypePQInfo].Load(); got != 1 {
		t.Fatalf("data waiting, both buckets empty: %d PQInfos, want 1", got)
	}
}

// A PQ init of ours sent once in reply to a packet no one signed gives way to the peer's, crossed, though ours is the
// lower key's: ours may have been lost, and is not sent again on its own.
func TestPQOnceYieldsUnit(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	var p *PacketConn
	for {
		p = lightPC(t)
		if bytes.Compare(n.pc.publicEd[:], p.publicEd[:]) < 0 {
			break
		}
	}
	k := edOf(p)
	knows(t, n.pc, p)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), true) })
	acks := n.sent[sessionTypePQAck].Load()
	deliverTo(n, k, pqInitFrom(t, p, n.pc))
	var pending bool
	phony.Block(&n.pc.sessions, func() { pending = n.pc.sessions.pqPending[k] != nil })
	if pending || n.sent[sessionTypePQAck].Load() != acks+1 {
		t.Fatalf("ours sent once, the peer's crossed: ours kept %v, %d acks to the peer's", pending, n.sent[sessionTypePQAck].Load()-acks)
	}
}

// An ML-KEM key that is not one (bytes out of the field), announced with a valid signature, is not taken.
func TestPQInvalidKeyRefused(t *testing.T) {
	pc := newBarePC(t)
	k := newPeerEd(t)
	var bad pqPub
	for i := range bad {
		bad[i] = 0xff
	}
	now := uint64(time.Now().Unix())
	if ok, _ := pc.pq.accept(&k, &bad, now, now+3600); ok || pc.pq.usableKey(&k) != nil {
		t.Fatal("an ML-KEM key out of the field taken")
	}
}
