package encrypted

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// The tests of the second review of the PQ sessions (R2), and of the behaviours of the first (S1-S9) no test held.

// streamCount: from writes to `to` every 50 ms for d; how many it wrote, and how many of them `to` heard
func streamCount(from, to *pqNode, tag string, d time.Duration) (sent, got int) {
	for stop := time.Now().Add(d); time.Now().Before(stop); sent++ {
		from.pc.WriteTo([]byte(fmt.Sprintf("%s %d", tag, sent)), types.Addr(to.pub))
		for deadline := time.After(50 * time.Millisecond); ; {
			select {
			case m := <-to.heard:
				if strings.HasPrefix(m, tag+" ") {
					got++
				}
				continue
			case <-deadline:
			}
			break
		}
	}
	return
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) f(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

// count: the lines with sub in them
func (l *logSink) count(sub string) (n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, sub) {
			n++
		}
	}
	return
}

func (l *logSink) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// testClock: pc's clock (pq.now), the real one and an offset the test moves. Installed before pc is linked or reads,
// while nothing else reads it.
func testClock(pc *PacketConn) *atomic.Int64 {
	var offset atomic.Int64
	pc.pq.now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	return &offset
}

// knows: n takes peer's ML-KEM key, as from a PQInfo
func knows(t *testing.T, n *PacketConn, peer *PacketConn) {
	t.Helper()
	var k edPub
	copy(k[:], peer.publicEd[:])
	own := peer.pqOwn()
	if ok, _ := n.pq.accept(&k, &own.pub, own.seq, own.notAfter); !ok {
		t.Fatal("the peer's key not taken")
	}
}

// classicInitFrom: a classic init of from's to to
func classicInitFrom(t *testing.T, from, to *PacketConn) []byte {
	t.Helper()
	var toEd edPub
	copy(toEd[:], to.publicEd[:])
	cur, _ := newBoxKeys()
	nxt, _ := newBoxKeys()
	init := newSessionInit(&cur, &nxt, 0)
	data, err := init.encrypt(&from.secretEd, &toEd, from.groupAuth)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func edOf(pc *PacketConn) (k edPub) {
	copy(k[:], pc.publicEd[:])
	return
}

// stickyFor: n's sticky entry for k, nil if none
func stickyFor(n *PacketConn, k edPub) *stickyKey {
	n.pq.mu.Lock()
	defer n.pq.mu.Unlock()
	if e, ok := n.pq.sticky[k]; ok {
		return e.Value.(*stickyKey)
	}
	return nil
}

func sentAll(n *pqNode) (total int64) {
	for i := range n.sent {
		total += n.sent[i].Load()
	}
	return
}

// classicThenPQ links a and b (a the lower key): a classic session first, PQ packets lost meanwhile; then a, given
// b's PQInfo, starts the PQ init that replaces it. No data waits at either end (it would go over the PQ session the
// moment it comes up): until a probe opens, both have a PQ session with the classic one beside it.
func classicThenPQ(t *testing.T, a, b *pqNode) {
	t.Helper()
	a.dropPQ.Store(true)
	b.dropPQ.Store(true)
	linkPQ(t, a, b)
	if !hears(b, a, "classic", 3*time.Second) || !hears(a, b, "classic back", 3*time.Second) {
		t.Fatal("no classic session")
	}
	a.dropPQ.Store(false)
	b.dropPQ.Store(false)
	bKey := b.key()
	a.pc.sessions.handleData(nil, &bKey, append(allocBytes(0), b.pc.pqOwn().info...))
	for deadline := time.Now().Add(5 * time.Second); session(a, b) != "pq, unconfirmed" || session(b, a) != "pq, unconfirmed"; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no PQ sessions beside the classic ones in 5 s: A %s, B %s", session(a, b), session(b, a))
		}
	}
}

/********
 * R2-1 *
 ********/

// R2-1: A, the lower key, starts the upgrade, and only reads; B writes. The one packet lost is A's ack to B's ack
// (0x12, its type in the clear). B's first probe confirms A's PQ session; B has no PQ packet of A's to confirm its
// own. A answers B's classic packets with a probe: B's session is confirmed too, and B's traffic goes on, over PQ.
func TestPQAckToAckLost(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	b.pc.pq.pendingTimeout, b.pc.pq.upgradeRetry = 3*time.Second, 2*time.Second
	knows(t, a.pc, b.pc) // A starts the PQ init once the classic session is up (B learns A's key from it)
	a.dropType[sessionTypePQAck].Store(true)
	linkPQ(t, a, b)
	s0, g0 := streamCount(b, a, "warm", 2*time.Second)
	s, g := streamCount(b, a, "after", 4*time.Second)
	t.Logf("B to A: %d/%d in the first 2 s, %d/%d in the next 4 s; A %s, B %s", g0, s0, g, s, session(a, b), session(b, a))
	if a.sent[sessionTypePQAck].Load() == 0 {
		t.Fatal("A sent no PQ ack: the case the test is for did not come")
	}
	if g < s*9/10 {
		t.Fatalf("B to A: %d of %d heard after the lost ack: A %s, B %s", g, s, session(a, b), session(b, a))
	}
	if session(a, b) != "pq" || session(b, a) != "pq" {
		t.Fatalf("sessions: A %s, B %s", session(a, b), session(b, a))
	}
	if b.sent[sessionTypePQTraffic].Load() < int64(s)/2 {
		t.Fatalf("B's traffic did not go over PQ: %d PQ packets of B's", b.sent[sessionTypePQTraffic].Load())
	}
}

// R2-1: A holds B to PQ and lost its session with it; B went back to classic, has the higher key and nothing
// waiting. B's classic traffic has A start a PQ init (a PQInfo alone would bring none): PQ again, both ways.
func TestPQStickyNoSessionStartsInit(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	for _, n := range []*pqNode{a, b} {
		n.dropPQ.Store(true)
	}
	linkPQ(t, a, b)
	if !hears(b, a, "classic", 3*time.Second) || !hears(a, b, "back", 3*time.Second) {
		t.Fatal("no classic session")
	}
	knows(t, a.pc, b.pc)
	bKey := b.key()
	a.pc.pq.markSticky(&bKey, b.pc.pqOwn().notAfter, true)
	dropSessions(a)
	for _, n := range []*pqNode{a, b} {
		n.dropPQ.Store(false)
	}
	if !hears(b, a, "again", 5*time.Second) {
		t.Fatalf("B to A not heard in 5 s: A %s, B %s; A sent PQ init %d, PQInfo %d", session(a, b), session(b, a),
			a.sent[sessionTypePQInit].Load(), a.sent[sessionTypePQInfo].Load())
	}
	if a.sent[sessionTypePQInit].Load() == 0 {
		t.Fatal("A started no PQ init")
	}
	if session(a, b) != "pq" {
		t.Fatalf("A's session with the key it holds to PQ: %s", session(a, b))
	}
}

/********
 * R2-2 *
 ********/

// R2-2: as R2-1, and B's PQ packets do not reach A: A has nothing opened under its PQ session, and does not hold B
// to PQ for the verified ack alone: B's classic traffic is taken, consistently. Once A holds B to PQ (Required),
// the classic session beside goes, and B's classic is taken no more.
func TestPQAckAloneNotSticky(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	b.pc.pq.pendingTimeout, b.pc.pq.upgradeRetry = 3*time.Second, 10*time.Minute
	knows(t, a.pc, b.pc)
	a.dropType[sessionTypePQAck].Store(true)
	b.dropType[sessionTypePQTraffic].Store(true)
	linkPQ(t, a, b)
	streamCount(b, a, "warm", time.Second)
	s, g := streamCount(b, a, "classic", 3*time.Second)
	bKey := b.key()
	if g < s*9/10 {
		t.Fatalf("B to A: %d of %d heard: A %s, B %s", g, s, session(a, b), session(b, a))
	}
	if sticky(a, b) || a.pc.pq.required(&bKey) {
		t.Fatal("A holds B to PQ for a verified ack, with nothing of B's opened, and takes its classic traffic")
	}
	if session(a, b) != "pq, unconfirmed" {
		t.Fatalf("A's session: %s (the case the test is for did not come)", session(a, b))
	}
	a.pc.SetPQ(PQConfig{Enabled: true, Required: func(k ed25519.PublicKey) bool { return string(k) == string(b.pub) }})
	streamCount(b, a, "settle", 500*time.Millisecond)
	if s, g := streamCount(b, a, "required", 2*time.Second); g != 0 {
		t.Fatalf("B to A: %d of %d classic packets taken from a key that must be PQ", g, s)
	}
	if session(a, b) == "classic" || session(a, b) == "pq, unconfirmed" {
		t.Fatalf("A's session with a key that must be PQ: %s", session(a, b))
	}
}

/****************************
 * R2-3, R2-5, S2's and S8's *
 ****************************/

// pqBeside: n's PQ session with peer, a classic one beside it (a classic handshake, then a PQ init of the peer's;
// n does not know the peer's ML-KEM key before, or it might start a PQ init of its own)
func pqBeside(t *testing.T, n *pqNode, peer *PacketConn) (pq, classic *sessionInfo) {
	t.Helper()
	k := edOf(peer)
	n.pc.sessions.handleData(nil, &k, classicInitFrom(t, peer, n.pc))
	n.pc.sessions.handleData(nil, &k, pqInitFrom(t, peer, n.pc))
	phony.Block(&n.pc.sessions, func() {
		if pq = n.pc.sessions.sessions[k]; pq != nil {
			classic = pq.fallback
		}
	})
	if pq == nil || !pq.pq || classic == nil {
		t.Fatal("no PQ session with a classic one beside it")
	}
	syncSessions(n)
	return
}

// timerLive: info's timer is pending (stopped here: the test's end)
func timerLive(info *sessionInfo) (live bool) {
	phony.Block(info, func() { live = info.timer != nil && info.timer.Stop() })
	return
}

// R2-3, S2, S8, R2-5: each way the classic session beside a PQ one takes its place again — the PQ one's timer (S2),
// the rollback of a probe after pendingTimeout (S2), the eviction of the oldest unconfirmed one (S8), PQ turned off
// (S6) — leaves it with a timer of its own: the one it had may have fired while the PQ one held the table, and done
// nothing. A key that must be PQ gets no classic one back; a confirmed PQ session takes its stale classic one along.
func TestPQClassicRestored(t *testing.T) {
	cases := []struct {
		name    string
		restore func(t *testing.T, n *pqNode, pq *sessionInfo)
		want    string // the table's: "classic", or "none"
	}{
		{"timer", func(t *testing.T, n *pqNode, pq *sessionInfo) {
			phony.Block(&n.pc.sessions, func() { n.pc.sessions._expire(pq) })
		}, "classic"},
		{"probe rollback", func(t *testing.T, n *pqNode, pq *sessionInfo) {
			phony.Block(&n.pc.sessions, func() {
				n.pc.pq.pendingTimeout = 0
				n.pc.sessions._probe(pq)
			})
		}, "classic"},
		{"evicted", func(t *testing.T, n *pqNode, pq *sessionInfo) {
			phony.Block(&n.pc.sessions, func() { n.pc.sessions.unconfirmedMax = 1 })
			time.Sleep(10 * time.Millisecond)
			other := newBarePC(t)
			k := edOf(other)
			n.pc.sessions.handleData(nil, &k, pqInitFrom(t, other, n.pc))
			phony.Block(&n.pc.sessions, func() {})
		}, "classic"},
		{"PQ off", func(t *testing.T, n *pqNode, pq *sessionInfo) {
			n.pc.SetPQ(PQConfig{})
		}, "classic"},
		{"timer, required", func(t *testing.T, n *pqNode, pq *sessionInfo) {
			n.pc.SetPQ(PQConfig{Enabled: true, Required: func(ed25519.PublicKey) bool { return true }})
			phony.Block(&n.pc.sessions, func() { n.pc.sessions._expire(pq) })
		}, "none"},
		{"PQ off, confirmed", func(t *testing.T, n *pqNode, pq *sessionInfo) {
			pq.confirmed.Store(true)
			n.pc.SetPQ(PQConfig{})
		}, "none"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var log logSink
			n := newPQNode(t, PQConfig{Enabled: true, Logf: log.f}) // no link: what it sends is only counted
			peer := newBarePC(t)
			k := edOf(peer)
			pq, classic := pqBeside(t, n, peer)
			if !timerLive(classic) {
				t.Fatal("the classic session had no timer at the start")
			}
			// its timer stopped: as one that fired while the PQ session held the table
			c.restore(t, n, pq)
			var now *sessionInfo
			var retry bool
			phony.Block(&n.pc.sessions, func() {
				now = n.pc.sessions.sessions[k]
				retry = n.pc.sessions.pqRetry[k]
			})
			switch {
			case c.want == "none" && now != nil:
				t.Fatalf("the table holds a session (classic %v) with a key that must not have one", now == classic)
			case c.want == "classic" && now != classic:
				t.Fatalf("the classic session did not take the PQ one's place (none %v)", now == nil)
			case c.want == "classic" && !timerLive(classic):
				t.Fatal("the classic session put back has no timer: it would never go")
			}
			if got, want := n.pc.PQSessionCount(), map[bool]int{true: 1}[c.name == "evicted"]; got != want {
				t.Fatalf("PQ sessions counted: %d, want %d", got, want)
			}
			switch c.name {
			case "timer", "probe rollback", "evicted":
				if !retry {
					t.Fatal("no upgrade tried again later")
				}
			}
			if c.name == "evicted" && log.count("the most kept: the oldest") != 1 {
				t.Fatalf("no line of the eviction in the log: %q", log.all())
			}
		})
	}
}

// R2-3 at full length: a PQ session with a classic one beside, nothing sent: once both are idle, the table holds
// neither (idleTimeout shortened).
func TestPQIdleClassicGoes(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, pqOn)
	n.pc.sessions.idleTimeout = 300 * time.Millisecond
	peer := newBarePC(t)
	k := edOf(peer)
	pqBeside(t, n, peer)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		var now *sessionInfo
		phony.Block(&n.pc.sessions, func() { now = n.pc.sessions.sessions[k] })
		if now == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after 5 s idle the table still holds a session (PQ %v)", now.pq)
		}
	}
}

// R2-5: A's PQ session confirmed (by B's probe) while the pointer to the classic session beside it is still set: it
// is cleared on A's next write, or on B's next classic packet, and here neither comes. PQ turned off at A drops the PQ
// session, and does not bring that stale classic one back.
func TestPQOffStaleFallback(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	classicThenPQ(t, a, b)
	b.dropType[sessionTypeTraffic].Store(true)
	bKey := b.key()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("A's PQ session not confirmed with the classic one beside it still set: A %s B %s", session(a, b), session(b, a))
		}
		b.pc.WriteTo([]byte("x"), types.Addr(a.pub))
		var stale bool
		phony.Block(&a.pc.sessions, func() {
			info := a.pc.sessions.sessions[bKey]
			stale = info != nil && info.pq && info.confirmed.Load() && info.fallback != nil
		})
		if stale {
			break
		}
	}
	a.pc.SetPQ(PQConfig{})
	if session(a, b) != "none" {
		t.Fatalf("A's session after PQ off: %s", session(a, b))
	}
}

/********
 * R2-4 *
 ********/

// R2-4: packets no one signed refill the LRU of the per-key reply limits; a full PQ init in reply to forged PQ
// traffic of a known key takes a token of the shared bucket, so that they stay bounded all the same.
func TestPQForgedTrafficBucket(t *testing.T) {
	n := newPQNode(t, pqOn) // no link: sends are only counted
	n.pc.pq.peersMax = 8
	var known []edPub
	for i := 0; i < 4; i++ {
		peer := newBarePC(t)
		knows(t, n.pc, peer)
		known = append(known, edOf(peer))
	}
	forged := make([]byte, pqTrafficOverheadMin)
	forged[0] = sessionTypePQTraffic
	classic := make([]byte, sessionTrafficOverheadMin)
	classic[0] = sessionTypeTraffic
	start := time.Now()
	rounds := 30
	for r := 0; r < rounds; r++ {
		for i := range known {
			n.pc.sessions.handleData(nil, &known[i], append(allocBytes(0), forged...))
		}
		// keys no one has: their limits push the known keys' out
		for i := 0; i <= n.pc.pq.peersMax; i++ {
			fake := newPeerEd(t)
			n.pc.sessions.handleData(nil, &fake, append(allocBytes(0), classic...))
		}
	}
	phony.Block(&n.pc.sessions, func() {})
	elapsed := time.Since(start)
	inits := n.sent[sessionTypePQInit].Load()
	most := int64(pqUnsolicitedRate*(1+elapsed.Seconds())) + 1
	t.Logf("%d PQ inits in reply to %d forged PQ packets of known keys in %v (the bucket allows %d)", inits, rounds*len(known), elapsed.Round(time.Millisecond), most)
	if inits == 0 {
		t.Fatal("no PQ init in reply at all")
	}
	if inits > most {
		t.Fatalf("%d PQ inits in reply to forged traffic in %v, the bucket allows %d", inits, elapsed, most)
	}
}

/*********
 * R2B-1 *
 *********/

// R2B-1: an empty message over a PQ session is not delivered (an empty PQ packet is the probe); over a classic one
// it is (PQConfig's doc).
func TestPQEmptyMessage(t *testing.T) {
	t.Parallel()
	for _, cfg := range []PQConfig{{}, pqOn} {
		a, b := newPQNode(t, cfg), newPQNode(t, cfg)
		linkPQ(t, a, b)
		if !hears(a, b, "hello", 3*time.Second) {
			t.Fatal("no session")
		}
		if cfg.Enabled {
			waitSessions(t, a, b, "pq", 10*time.Second)
			if !hears(a, b, "settled", 3*time.Second) {
				t.Fatal("no traffic over PQ")
			}
		}
		before := b.empty.Load()
		for i := 0; i < 5; i++ {
			a.pc.WriteTo(nil, types.Addr(b.pub))
		}
		hears(a, b, "after", 3*time.Second) // the empty ones went before it
		got := b.empty.Load() - before
		if want := map[bool]int64{false: 5, true: 0}[cfg.Enabled]; got != want {
			t.Fatalf("PQ %v: %d empty messages read of 5, want %d", cfg.Enabled, got, want)
		}
	}
}

/*********
 * R2B-3 *
 *********/

// R2B-3, R3-1, R3-3: a key is held to PQ until the end of the ML-KEM key it is marked under and the clock slack, and
// no more than pqKeyValidity from the mark; a newer key of it accepted moves the end on, a newer key in the table
// does not move a mark under an older one; an entry past its end is not sticky, and goes.
func TestPQStickyExpiry(t *testing.T) {
	pc := newBarePC(t)
	start := time.Now()
	clock := start
	pc.pq.now = func() time.Time { return clock }
	n := uint64(start.Unix())
	hour, validity, slack := uint64(3600), uint64(pqKeyValidity/time.Second), uint64(pqClockSlack/time.Second)
	until := func(k edPub) uint64 {
		if e := stickyFor(pc, k); e != nil {
			return e.until
		}
		return 0
	}
	// a fresh key: held for pqKeyValidity from the mark, then not, and the entry goes
	k := newPeerEd(t)
	pc.pq.markSticky(&k, n+validity, true)
	if until(k) != n+validity {
		t.Fatalf("held until %d, want %d", until(k), n+validity)
	}
	clock = start.Add(pqKeyValidity)
	if !pc.pq.required(&k) {
		t.Fatal("not held to PQ within its hold")
	}
	clock = start.Add(pqKeyValidity + time.Second)
	if pc.pq.required(&k) || stickyFor(pc, k) != nil {
		t.Fatal("held to PQ past its hold, or the entry stayed")
	}
	clock = start
	// a peer's clock a day behind: its key ended by ours, and held all the same (the clock slack)
	behind := newPeerEd(t)
	pc.pq.markSticky(&behind, n-24*hour, true)
	if !pc.pq.required(&behind) || until(behind) != n+48*hour {
		t.Fatalf("a key a day behind: held %v, until %d", pc.pq.required(&behind), until(behind))
	}
	// out of time past the slack: not held
	gone := newPeerEd(t)
	pc.pq.markSticky(&gone, n-slack-1, true)
	if pc.pq.required(&gone) {
		t.Fatal("held to PQ with a key past its end and the slack")
	}
	// a key valid far ahead (an attacker's): no hold past pqKeyValidity
	far := newPeerEd(t)
	pc.pq.markSticky(&far, n+5*24*hour, true)
	if until(far) != n+validity {
		t.Fatalf("a far notAfter held until %d, want %d", until(far), n+validity)
	}
	// a newer key of a sticky one accepted: held for it
	k2 := newPeerEd(t)
	pub1, pub2 := newPQKeyPub(t), newPQKeyPub(t)
	pc.pq.accept(&k2, &pub1, n-10, n-10+validity)
	pc.pq.markSticky(&k2, n-10+validity, true)
	clock = start.Add(40 * time.Hour)
	if ok, upd := pc.pq.accept(&k2, &pub2, n+40*hour, n+40*hour+validity); !ok || !upd {
		t.Fatal("the newer key not taken")
	}
	if until(k2) != n+88*hour {
		t.Fatalf("a newer key of a sticky one: held until %d, want %d", until(k2), n+88*hour)
	}
	// a newer key in the table does not move a mark under an older key (the session's)
	clock = start
	k3 := newPeerEd(t)
	pc.pq.accept(&k3, &pub1, n, n+validity)
	pc.pq.markSticky(&k3, n-60*hour, true)
	if until(k3) != n-60*hour+slack {
		t.Fatalf("held until %d by a newer key of the table, want %d (the session's key)", until(k3), n-60*hour+slack)
	}
}

// R2B-3: B holds A to PQ; A turns PQ off. Until the end of A's ML-KEM key (B's clock), B refuses A's classic, with a
// line in its log; past it, the two hear each other again (classic), B's PQ session with A replaced.
func TestPQStickyEndsAfterOff(t *testing.T) {
	t.Parallel()
	var logB logSink
	a, b := newPQNode(t, pqOn), newPQNode(t, PQConfig{Enabled: true, Logf: logB.f})
	clockB := testClock(b.pc)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic over PQ")
	}
	aKey, aEnd := a.key(), a.pc.pqOwn().notAfter
	e := stickyFor(b.pc, aKey)
	if e == nil || e.until < aEnd || e.until > uint64(time.Now().Add(pqKeyValidity).Unix()) {
		t.Fatalf("B's sticky entry for A: %+v, want its end from %d to now and pqKeyValidity", e, aEnd)
	}
	end := e.until
	time.Sleep(1100 * time.Millisecond) // A's classic init, made after, numbered after the PQ session's
	a.pc.SetPQ(PQConfig{})
	if hears(a, b, "off, held", 2*time.Second) || hears(b, a, "off, held back", time.Second) {
		t.Fatal("traffic went with a key held to PQ, its PQ sessions off")
	}
	if logB.count("a classic init from") != 1 {
		t.Fatalf("B's log: %q", logB.all())
	}
	clockB.Store(int64(time.Until(time.Unix(int64(end), 0)) + time.Minute))
	if !hears(a, b, "after its end", 5*time.Second) || !hears(b, a, "after its end, back", 5*time.Second) {
		t.Fatalf("no traffic past the end of A's key: A %s, B %s", session(a, b), session(b, a))
	}
	if session(b, a) != "classic" {
		t.Fatalf("B's session: %s", session(b, a))
	}
}

// R2B-3: A had a PQ session with B, and restarts with the same key and PQ off. Past the end of A's ML-KEM key (B's
// clock), the two hear each other.
func TestPQStickyEndsAfterRestart(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	clockB := testClock(b.pc)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	hears(a, b, "pq", 3*time.Second)
	hears(b, a, "pq back", 3*time.Second)
	e := stickyFor(b.pc, a.key())
	if e == nil {
		t.Fatal("B does not hold A to PQ")
	}
	end := e.until
	priv := a.pc.PacketConn.PrivateKey()
	time.Sleep(1100 * time.Millisecond)
	a.pc.Close()
	a2 := newPQNodeKey(t, priv, PQConfig{})
	linkPQ(t, a2, b)
	if hears(a2, b, "restarted, held", 2*time.Second) {
		t.Fatal("classic from a key held to PQ taken")
	}
	clockB.Store(int64(time.Until(time.Unix(int64(end), 0)) + time.Minute))
	if !hears(a2, b, "after its end", 10*time.Second) || !hears(b, a2, "after its end, back", 5*time.Second) {
		t.Fatalf("no traffic past the end of A's key: A %s, B %s", session(a2, b), session(b, a2))
	}
}

// newPQNodeKey: newPQNode with a given key
func newPQNodeKey(t *testing.T, priv ed25519.PrivateKey, cfg PQConfig) *pqNode {
	t.Helper()
	pc, err := NewPacketConn(priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	n := &pqNode{pc: pc, pub: append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...), heard: make(chan string, 64)}
	pc.testDrop = func(data []byte) bool {
		n.sent[data[0]].Add(1)
		return n.dropType[data[0]].Load()
	}
	pc.SetPQ(cfg)
	return n
}

// R2B-3: a classic init from a key held to PQ gives a line in the log, one a pqLogInterval; a forged init none, nor
// classic traffic (no one signed it).
func TestPQStickyAsksClassicLogged(t *testing.T) {
	var log logSink
	n := newPQNode(t, PQConfig{Enabled: true, Logf: log.f}) // no link
	clock := testClock(n.pc)
	peer, other := newBarePC(t), newBarePC(t)
	k := edOf(peer)
	n.pc.pq.markSticky(&k, peer.pqOwn().notAfter, true)
	deliver := func(data []byte) {
		n.pc.sessions.handleData(nil, &k, append(allocBytes(0), data...))
		phony.Block(&n.pc.sessions, func() {})
	}
	deliver(classicInitFrom(t, other, n.pc)) // signed by another key
	if got := log.count("from"); got != 0 {
		t.Fatalf("a forged classic init logged: %q", log.all())
	}
	deliver(classicInitFrom(t, peer, n.pc))
	deliver(classicInitFrom(t, peer, n.pc))
	if got := log.count("a classic init from"); got != 1 {
		t.Fatalf("%d lines for two classic inits at once, want 1: %q", got, log.all())
	}
	clock.Store(int64(pqLogInterval))
	traffic := make([]byte, sessionTrafficOverheadMin)
	traffic[0] = sessionTypeTraffic
	deliver(traffic)
	if got := len(log.all()); got != 1 {
		t.Fatalf("classic traffic no one signed logged: %q", log.all())
	}
	deliver(classicInitFrom(t, peer, n.pc))
	if got := log.count("a classic init from"); got != 2 {
		t.Fatalf("a classic init once the interval passed: %d lines in all: %q", got, log.all())
	}
	if n.sent[sessionTypeInit].Load()+n.sent[sessionTypeAck].Load() != 0 {
		t.Fatal("a classic init or ack went to a key held to PQ")
	}
}

/*********
 * R2B-4 *
 *********/

// R2B-4, S7: a peer with traffic over its PQ session is held to PQ with traffic (a key with a handshake alone goes
// first), and raised in the sticky LRU by its traffic again, at most once in pqStickyRefresh: keys with one packet
// each do not push it out.
func TestPQStickyRaisedByTraffic(t *testing.T) {
	t.Parallel()
	var logB logSink
	a, b := newPQNode(t, pqOn), newPQNode(t, PQConfig{Enabled: true, Logf: logB.f})
	b.pc.pq.stickyMax = 3
	clockB := testClock(b.pc)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic over PQ")
	}
	syncSessions(b)
	aKey := a.key()
	if e := stickyFor(b.pc, aKey); e == nil || !e.traffic {
		t.Fatalf("B's sticky entry for A after traffic: %+v, want one with traffic", e)
	}
	end := uint64(time.Now().Add(24 * time.Hour).Unix())
	mark := func(traffic bool) edPub {
		k := newPeerEd(t)
		b.pc.pq.markSticky(&k, end, traffic)
		return k
	}
	back := func() edPub {
		b.pc.pq.mu.Lock()
		defer b.pc.pq.mu.Unlock()
		return b.pc.pq.stickyLRU.Back().Value.(*stickyKey).ed
	}
	front := func() edPub {
		b.pc.pq.mu.Lock()
		defer b.pc.pq.mu.Unlock()
		return b.pc.pq.stickyLRU.Front().Value.(*stickyKey).ed
	}
	// three keys with a handshake alone: they go first, A (traffic) stays
	for i := 0; i < 3; i++ {
		mark(false)
	}
	if !sticky(b, a) {
		t.Fatal("A, with traffic, pushed out by keys with a handshake alone")
	}
	// keys with a packet each, until all are such: A at the back
	mark(true)
	mark(true)
	if back() != aKey {
		t.Fatal("setup: A is not the least recent")
	}
	// A's traffic within the minute: not raised
	if !hears(a, b, "within the minute", 3*time.Second) {
		t.Fatal("no traffic")
	}
	syncSessions(b)
	if back() != aKey {
		t.Fatal("raised again within pqStickyRefresh")
	}
	clockB.Store(int64(pqStickyRefresh + time.Second))
	if !hears(a, b, "a minute on", 3*time.Second) {
		t.Fatal("no traffic")
	}
	syncSessions(b)
	if front() != aKey {
		t.Fatal("A's traffic did not raise it once pqStickyRefresh passed")
	}
	mark(true)
	if !sticky(b, a) {
		t.Fatalf("A, with traffic all along, pushed out by a key with one packet: %q", logB.all())
	}
}

/*********
 * R2B-5 *
 *********/

// R2B-5, R3-2: past PQConfig.SessionMax PQ sessions, this node starts none with a key that may be classic (a line in
// the log; no PQ init or PQInfo from us either), and still takes one a peer starts. PQSessionCount tells how many
// are up.
func TestPQSessionMax(t *testing.T) {
	var log logSink
	n := newPQNode(t, PQConfig{Enabled: true, Logf: log.f, SessionMax: 1}) // no link
	p1, p2, p3 := lightPC(t), lightPC(t), lightPC(t)
	k1, k2, k3 := edOf(p1), edOf(p2), edOf(p3)
	deliver := func(k edPub, data []byte) {
		n.pc.sessions.handleData(nil, &k, data)
		phony.Block(&n.pc.sessions, func() {})
		syncSessions(n)
	}
	deliver(k1, pqInitFrom(t, p1, n.pc))
	if n.pc.PQSessionCount() != 1 || n.sent[sessionTypePQAck].Load() != 1 {
		t.Fatalf("the first PQ init: %d PQ sessions, %d acks", n.pc.PQSessionCount(), n.sent[sessionTypePQAck].Load())
	}
	// past SessionMax, a PQ init of the peer's: taken
	deliver(k2, pqInitFrom(t, p2, n.pc))
	if n.pc.PQSessionCount() != 2 || n.sent[sessionTypePQAck].Load() != 2 {
		t.Fatalf("a peer's PQ init past SessionMax: %d PQ sessions, %d acks", n.pc.PQSessionCount(), n.sent[sessionTypePQAck].Load())
	}
	// a classic handshake with p3, its ML-KEM key known: classic, and nothing of PQ from us
	knows(t, n.pc, p3)
	before := n.sent[sessionTypePQInfo].Load() + n.sent[sessionTypePQInit].Load()
	deliver(k3, classicInitFrom(t, p3, n.pc))
	if got := n.sent[sessionTypePQInfo].Load() + n.sent[sessionTypePQInit].Load(); got != before {
		t.Fatalf("%d PQInfos or PQ inits to a key past SessionMax", got-before)
	}
	if session(n, &pqNode{pub: p3.publicEd[:]}) != "classic" {
		t.Fatal("no classic session past SessionMax")
	}
	if log.count("(PQConfig.SessionMax): none started") != 1 {
		t.Fatalf("log: %q", log.all())
	}
	n.pc.SetPQ(PQConfig{})
	if n.pc.PQSessionCount() != 0 {
		t.Fatalf("PQ off: %d PQ sessions counted", n.pc.PQSessionCount())
	}
}

/********************************************
 * S1-S8 behaviours no test held (R2B-2) *
 ********************************************/

// S2: PQ traffic (0x13) dropped both ways, the acks carried: both ends have a PQ session with the classic one beside
// it, and no PQ packet opens. pendingTimeout after its start each end's probe puts the classic one back in its place,
// with a line in the log; traffic goes on all along.
func TestPQProbeRollsBack(t *testing.T) {
	t.Parallel()
	var logs [2]logSink
	x, y := newPQNode(t, PQConfig{Enabled: true, Logf: logs[0].f}), newPQNode(t, PQConfig{Enabled: true, Logf: logs[1].f})
	for _, n := range []*pqNode{x, y} {
		n.pc.pq.pendingTimeout, n.pc.pq.upgradeRetry = 2*time.Second, 10*time.Minute
		n.dropType[sessionTypePQTraffic].Store(true)
	}
	a, b := lowerFirst(x, y)
	classicThenPQ(t, a, b)
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if !hears(a, b, "A to B", 2*time.Second) || !hears(b, a, "B to A", 2*time.Second) {
			t.Fatalf("traffic stopped: A %s, B %s", session(a, b), session(b, a))
		}
	}
	waitSessions(t, a, b, "classic", 3*time.Second)
	for i := range logs {
		if logs[i].count("no PQ packet of its opened here") != 1 {
			t.Fatalf("log of %d: %q", i, logs[i].all())
		}
	}
}

// S2: one end only writes, the other only reads. The writer's probe confirms the reader's PQ session, the reader's
// probe in answer to its classic traffic the writer's: both PQ in a few seconds, no probe read as a message.
func TestPQProbeConfirms(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	classicThenPQ(t, a, b)
	for deadline := time.Now().Add(5 * time.Second); session(a, b) != "pq" || session(b, a) != "pq"; {
		if time.Now().After(deadline) {
			t.Fatalf("one-way traffic, not PQ in 5 s: A %s, B %s", session(a, b), session(b, a))
		}
		b.pc.WriteTo([]byte("one way"), types.Addr(a.pub))
		time.Sleep(50 * time.Millisecond)
	}
	if a.empty.Load()+b.empty.Load() != 0 {
		t.Fatalf("probes read as messages: %d at A, %d at B", a.empty.Load(), b.empty.Load())
	}
}

// S2: while the classic session beside carries the traffic, a probe goes at most once in pqProbeInterval.
func TestPQProbeInterval(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	a.dropType[sessionTypePQTraffic].Store(true) // B's session is never confirmed
	classicThenPQ(t, a, b)
	start, before := time.Now(), b.sent[sessionTypePQTraffic].Load()
	for time.Since(start) < 2*time.Second {
		b.pc.WriteTo([]byte("x"), types.Addr(a.pub))
		time.Sleep(20 * time.Millisecond)
	}
	probes := b.sent[sessionTypePQTraffic].Load() - before
	if most := int64(time.Since(start)/pqProbeInterval) + 2; probes > most || probes == 0 {
		t.Fatalf("%d probes in %v of writes every 20 ms, want 1 to %d", probes, time.Since(start).Round(time.Millisecond), most)
	}
}

// S2: the PQ ack is lost until the init it answers is given up: the end that sent the init is classic, the other has
// a PQ session. A probe of the latter has the former start a PQ init again at once (whatever the order of the keys),
// not after pqUpgradeRetry.
func TestPQNewInitOnPQTraffic(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	a.pc.pq.pendingTimeout = 2 * time.Second
	for _, n := range []*pqNode{a, b} {
		n.pc.pq.upgradeRetry = 10 * time.Minute
	}
	knows(t, a.pc, b.pc)
	b.dropType[sessionTypePQAck].Store(true)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	bKey := b.key()
	for deadline := time.Now().Add(8 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		var pending bool
		phony.Block(&a.pc.sessions, func() { pending = a.pc.sessions.pqPending[bKey] != nil })
		if !pending && session(a, b) == "classic" && session(b, a) == "pq, unconfirmed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("A's PQ init not given up in 8 s: A %s (pending %v), B %s", session(a, b), pending, session(b, a))
		}
	}
	b.dropType[sessionTypePQAck].Store(false)
	waitSessions(t, a, b, "pq", 6*time.Second)
}

// S1: a PQ init of ours pending under an ML-KEM key of the peer older than the one its PQInfo brings is sealed
// again to that one at once, not on its next retry.
func TestPQPendingResealedOnInfo(t *testing.T) {
	a := newPQNode(t, pqOn) // no link
	b := newBarePC(t)
	bKey, bOwn := edOf(b), b.pqOwn()
	var mu sync.Mutex
	var sealedTo []uint64
	tap := func(d []byte) bool {
		if d[0] == sessionTypePQInit {
			mu.Lock()
			sealedTo = append(sealedTo, binary.BigEndian.Uint64(d[1:9]))
			mu.Unlock()
		}
		return false
	}
	a.tap.Store(&tap)
	stale := newPQKeyPub(t)
	staleSeq := bOwn.seq - 100
	if ok, _ := a.pc.pq.accept(&bKey, &stale, staleSeq, staleSeq+uint64(pqKeyValidity/time.Second)); !ok {
		t.Fatal("the stale key not taken")
	}
	phony.Block(&a.pc.sessions, func() { a.pc.sessions._startPQ(&bKey, a.pc.pq.usableKey(&bKey), false) })
	a.pc.sessions.handleData(nil, &bKey, append(allocBytes(0), bOwn.info...))
	phony.Block(&a.pc.sessions, func() {})
	mu.Lock()
	defer mu.Unlock()
	if len(sealedTo) != 2 || sealedTo[0] != staleSeq || sealedTo[1] != bOwn.seq {
		t.Fatalf("PQ inits sealed to keys %v, want %d then %d", sealedTo, staleSeq, bOwn.seq)
	}
}

// S3: a packet too short for its type gets no answer, where one of its size would get one.
func TestPQShortPacketsUnanswered(t *testing.T) {
	required := map[string]bool{}
	n := newPQNode(t, PQConfig{Enabled: true, Required: func(k ed25519.PublicKey) bool { return required[string(k)] }})
	peerKey := func(mustPQ bool) edPub {
		p := newBarePC(t)
		knows(t, n.pc, p)
		k := edOf(p)
		if mustPQ {
			required[string(k[:])] = true
		}
		return k
	}
	packet := func(typ byte, size int) []byte {
		d := make([]byte, size)
		d[0] = typ
		for i := 1; i < size; i++ {
			d[i] = byte(i * 7)
		}
		return d
	}
	cases := []struct {
		name   string
		typ    byte
		size   int
		mustPQ bool // a key that must be PQ (its classic gets our PQInfo)
		known  bool // its ML-KEM key known here
	}{
		{"classic init", sessionTypeInit, sessionInitSize, true, true},
		{"classic ack", sessionTypeAck, sessionAckSize, true, true},
		{"classic traffic", sessionTypeTraffic, sessionTrafficOverheadMin, false, false},
		{"PQ traffic", sessionTypePQTraffic, pqTrafficOverheadMin, false, true},
		{"PQ init", sessionTypePQInit, sessionPQInitSize, false, true},
	}
	for _, c := range cases {
		for _, short := range []bool{true, false} {
			var k edPub
			if c.known {
				k = peerKey(c.mustPQ)
			} else {
				k = newPeerEd(t)
			}
			size := c.size
			if short {
				size--
			}
			before := sentAll(n)
			n.pc.sessions.handleData(nil, &k, packet(c.typ, size))
			phony.Block(&n.pc.sessions, func() {})
			answered := sentAll(n) != before
			if answered == short {
				t.Errorf("%s of %d bytes (%d its size): answered %v", c.name, size, c.size, answered)
			}
		}
	}
}

// S3: the table of keys, full, pushes out the least used key not held to PQ, not a sticky one.
func TestPQPeersSpareSticky(t *testing.T) {
	pc := newBarePC(t)
	pc.pq.peersMax = 3
	keys := []edPub{newPeerEd(t), newPeerEd(t), newPeerEd(t), newPeerEd(t)}
	now := uint64(time.Now().Unix())
	pc.pq.markSticky(&keys[0], now+3600, true)
	for i := range keys {
		pub := newPQKeyPub(t)
		pc.pq.accept(&keys[i], &pub, now, now+3600)
	}
	if pc.pq.usableKey(&keys[0]) == nil {
		t.Fatal("the sticky key was pushed out of the full table")
	}
	if pc.pq.usableKey(&keys[1]) != nil {
		t.Fatal("the least used key not held to PQ stayed")
	}
}

// S5: a PQ init whose sender's key is numbered further ahead than the clock slack, or valid longer than a key is made
// for, is neither taken nor answered.
func TestPQInitImplausibleRefused(t *testing.T) {
	for _, c := range []struct {
		name          string
		ahead, extend time.Duration
	}{
		{"ahead", pqClockSlack + 24*time.Hour, 0},
		{"too long", 0, 24 * time.Hour},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newPQNode(t, pqOn) // no link
			a := newBarePC(t)
			k := a.newPQOwnKey(uint64(time.Now().Add(c.ahead).Unix()))
			k.notAfter += uint64(c.extend / time.Second)
			a.pq.ownMu.Lock()
			a.pq.own = k
			a.pq.ownMu.Unlock()
			aKey := edOf(a)
			b.pc.sessions.handleData(nil, &aKey, pqInitFrom(t, a, b.pc))
			phony.Block(&b.pc.sessions, func() {})
			syncSessions(b)
			if b.sent[sessionTypePQAck].Load() != 0 || b.pc.PQSessionCount() != 0 || b.pc.pq.usableKey(&aKey) != nil {
				t.Fatalf("an implausible PQ init: %d acks, %d PQ sessions, key taken %v",
					b.sent[sessionTypePQAck].Load(), b.pc.PQSessionCount(), b.pc.pq.usableKey(&aKey) != nil)
			}
		})
	}
}

/*********
 * minor *
 *********/

// A classic session of a key held to PQ (the one beside a PQ session) sends no classic init to it.
func TestPQNoClassicInitToSticky(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	peer := newBarePC(t)
	k := edOf(peer)
	n.pc.sessions.handleData(nil, &k, classicInitFrom(t, peer, n.pc))
	phony.Block(&n.pc.sessions, func() {})
	var info *sessionInfo
	phony.Block(&n.pc.sessions, func() { info = n.pc.sessions.sessions[k] })
	syncSessions(n)
	n.pc.pq.markSticky(&k, peer.pqOwn().notAfter, true)
	before := n.sent[sessionTypeInit].Load() + n.sent[sessionTypeAck].Load()
	phony.Block(info, func() {
		info._sendInit()
		info._sendAck()
	})
	if n.sent[sessionTypeInit].Load()+n.sent[sessionTypeAck].Load() != before {
		t.Fatal("a classic init or ack went to a key held to PQ")
	}
}

// A PQInfo of the higher key lost on the way at first contact: the lower one never learns its ML-KEM key and starts
// no PQ init; the higher one, which knows the lower's, says so in its log.
func TestPQInfoStrippedLogged(t *testing.T) {
	t.Parallel()
	var logH logSink
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	lo, hi := lowerFirst(x, y)
	hi.pc.SetPQ(PQConfig{Enabled: true, Logf: logH.f})
	hi.pc.pq.pendingTimeout = time.Second
	hi.dropType[sessionTypePQInfo].Store(true)
	linkPQ(t, lo, hi)
	if !hears(lo, hi, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	for deadline := time.Now().Add(4 * time.Second); logH.count("no PQ init of it came to our PQInfo") == 0; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no line in the higher key's log: %q (sessions %s, %s)", logH.all(), session(lo, hi), session(hi, lo))
		}
	}
}

// A key that must be PQ, whose PQInfo does not come: no session, and a line in the log once pendingTimeout passed.
func TestPQRequiredNoInfoLogged(t *testing.T) {
	t.Parallel()
	var log logSink
	var b *pqNode
	a := newPQNode(t, PQConfig{Enabled: true, Logf: log.f, Required: func(k ed25519.PublicKey) bool { return string(k) == string(b.pub) }})
	b = newPQNode(t, pqOn)
	a.pc.pq.pendingTimeout = time.Second
	b.dropType[sessionTypePQInfo].Store(true)
	linkPQ(t, a, b)
	if hears(a, b, "must be PQ", 2*time.Second) {
		t.Fatal("traffic went with no PQInfo of a key that must be PQ")
	}
	if log.count("must be PQ, and no PQInfo of it came") != 1 {
		t.Fatalf("log: %q", log.all())
	}
}
