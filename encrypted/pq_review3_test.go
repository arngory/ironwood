package encrypted

import (
	"bytes"
	"container/list"
	"crypto/ed25519"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// The tests of the third review of the PQ sessions (R3).

// lightPC: a node's keys and PQ state with no network under them: it makes inits and acks, nothing more
func lightPC(t *testing.T) *PacketConn {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pc := new(PacketConn)
	copy(pc.secretEd[:], priv)
	pc.secretBox = *pc.secretEd.toBox()
	pc.publicEd = *pc.secretEd.pub()
	pc.pq.init()
	cfg := pqOn
	pc.pq.cfg.Store(&cfg)
	return pc
}

// classicInitSeq: a classic init of from's to `to`, its seq given
func classicInitSeq(t *testing.T, from, to *PacketConn, seq uint64) []byte {
	t.Helper()
	var toEd edPub
	copy(toEd[:], to.publicEd[:])
	cur, _ := newBoxKeys()
	nxt, _ := newBoxKeys()
	init := newSessionInit(&cur, &nxt, 0)
	init.seq = seq
	data, err := init.encrypt(&from.secretEd, &toEd, from.groupAuth)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// junk: a packet of typ and size no session can make sense of (key numbers no session has)
func junk(typ byte, size int) []byte {
	d := allocBytes(size)
	for i := range d {
		d[i] = byte(i*13 + 5)
	}
	d[0] = typ
	d[1], d[2], d[3] = 100, 100, 1
	return d
}

// deliverTo: data to n as from k, and n's actors done with it
func deliverTo(n *pqNode, k edPub, data []byte) {
	n.pc.sessions.handleData(nil, &k, data)
	phony.Block(&n.pc.sessions, func() {})
	syncSessions(n)
}

func sessionOf(n *pqNode, k edPub) (s *sessionInfo) {
	phony.Block(&n.pc.sessions, func() { s = n.pc.sessions.sessions[k] })
	return
}

/********
 * R3-1 *
 ********/

// R3-1 (and the rule of R2B-3): a signed classic init replaces a confirmed PQ session of a key not held to PQ only if
// it is newer than the PQ session, and nothing opened under the session within idleTimeout. An older (replayed) or
// same-second init does not; a newer one while PQ traffic opens (one held back on the way) does not either.
func TestPQClassicInitGuard(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	peer := lightPC(t)
	k := edOf(peer)
	old := classicInitSeq(t, peer, n.pc, uint64(time.Now().Unix())-10) // recorded before the PQ session
	deliverTo(n, k, pqInitFrom(t, peer, n.pc))
	pq := sessionOf(n, k)
	var initSeq uint64
	phony.Block(&n.pc.sessions, func() { initSeq = pq.initSeq })
	if pq == nil || !pq.pq || initSeq == 0 {
		t.Fatal("no PQ session")
	}
	pq.confirmed.Store(true) // confirmed, the key not held to PQ (as once its hold ended)
	if n.pc.pq.isSticky(&k) {
		t.Fatal("setup: sticky")
	}
	deliverTo(n, k, old)
	if sessionOf(n, k) != pq {
		t.Fatal("an older (replayed) classic init replaced the confirmed PQ session")
	}
	deliverTo(n, k, classicInitSeq(t, peer, n.pc, initSeq))
	if sessionOf(n, k) != pq {
		t.Fatal("a classic init of the PQ session's own seq replaced it")
	}
	pq.openedAt.Store(n.pc.pq.now().UnixNano())
	deliverTo(n, k, classicInitSeq(t, peer, n.pc, initSeq+1))
	if sessionOf(n, k) != pq {
		t.Fatal("a newer classic init replaced a PQ session with traffic opened just now")
	}
	pq.openedAt.Store(n.pc.pq.now().Add(-sessionTimeout - time.Second).UnixNano())
	deliverTo(n, k, classicInitSeq(t, peer, n.pc, initSeq+2))
	if s := sessionOf(n, k); s == nil || s.pq {
		t.Fatalf("a newer classic init, nothing opened in idleTimeout, did not replace the PQ session (now PQ %v)", s != nil && s.pq)
	}
}

// R3-1: a classic init A's classic session beside its unconfirmed PQ one signs (asked for by one forged packet) is
// held by a node on the path, and let go once B's clock is past the end of A's ML-KEM key and the slack (B holds A
// no longer), the PQ session up. It does not replace B's PQ session (traffic opened under it just now); nor with B
// past SessionMax, nor for a key under Required.
func TestPQHeldInitRefused(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"plain", "past SessionMax", "required"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			heldInitRefused(t, variant)
		})
	}
}

func heldInitRefused(t *testing.T, variant string) {
	var logB logSink
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	b.pc.SetPQ(PQConfig{Enabled: true, Logf: logB.f})
	clockB := testClock(b.pc)
	aKey, bKey := a.key(), b.key()
	classicThenPQ(t, a, b)
	// B's PQ packets lost: A stays unconfirmed; A's probe confirms B
	b.dropType[sessionTypePQTraffic].Store(true)
	for deadline := time.Now().Add(5 * time.Second); session(b, a) != "pq" || session(a, b) != "pq, unconfirmed"; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("setup: A %s, B %s", session(a, b), session(b, a))
		}
		a.pc.WriteTo([]byte("x"), types.Addr(b.pub))
	}
	if a.pc.pq.required(&bKey) {
		t.Fatal("setup: A holds B to PQ already")
	}
	time.Sleep(1100 * time.Millisecond)
	var mu sync.Mutex
	var held []byte
	tap := func(d []byte) bool {
		if d[0] != sessionTypeInit {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		if held == nil {
			held = append([]byte(nil), d...)
		}
		return true // the node on the path keeps it
	}
	a.tap.Store(&tap)
	for deadline := time.Now().Add(8 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		mu.Lock()
		got := held != nil
		mu.Unlock()
		if got {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A signed no classic init on forged classic traffic")
		}
		a.pc.sessions.handleData(nil, &bKey, junk(sessionTypeTraffic, 80))
	}
	a.tap.Store(nil)
	var heldInit sessionInit
	if !heldInit.decrypt(&b.pc.secretBox, &aKey, held, b.pc.groupAuth) {
		t.Fatal("the held init does not open at B")
	}
	var initSeq uint64
	phony.Block(&b.pc.sessions, func() { initSeq = b.pc.sessions.sessions[aKey].initSeq })
	if heldInit.seq <= initSeq {
		t.Fatalf("setup: the held init (seq %d) is not newer than B's PQ session (%d)", heldInit.seq, initSeq)
	}
	b.dropType[sessionTypePQTraffic].Store(false)
	waitSessions(t, a, b, "pq", 10*time.Second)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no PQ traffic")
	}
	release := func() {
		b.pc.sessions.handleData(nil, &aKey, append(allocBytes(0), held...))
		phony.Block(&b.pc.sessions, func() {})
		syncSessions(b)
	}
	release()
	if session(b, a) != "pq" {
		t.Fatalf("let go while B holds A to PQ: B %s", session(b, a))
	}
	// B's clock past the end of A's ML-KEM key and the clock slack: B's traffic holds A no longer, the PQ session still
	// up; only the time of the last packet opened guards it
	clockB.Store(int64(time.Until(time.Unix(int64(a.pc.pqOwn().notAfter), 0)) + pqClockSlack + time.Minute))
	if !hears(a, b, "still up", 3*time.Second) || !hears(b, a, "still up back", 3*time.Second) {
		t.Fatal("the PQ session not up")
	}
	syncSessions(b)
	switch variant {
	case "required":
		b.pc.SetPQ(PQConfig{Enabled: true, Logf: logB.f, Required: func(k ed25519.PublicKey) bool { return bytes.Equal(k, a.pub) }})
	case "past SessionMax":
		b.pc.SetPQ(PQConfig{Enabled: true, Logf: logB.f, SessionMax: 1})
		c := lightPC(t)
		c.pq.now = b.pc.pq.now // its key made by B's clock, not out of time there
		cKey := edOf(c)
		b.pc.pq.markSticky(&cKey, c.pqOwn().notAfter, true) // a filler, held to PQ: its session past SessionMax
		b.pc.sessions.handleData(nil, &cKey, pqInitFrom(t, c, b.pc))
		phony.Block(&b.pc.sessions, func() {})
		if b.pc.PQSessionCount() != 2 {
			t.Fatalf("setup: %d PQ sessions at B", b.pc.PQSessionCount())
		}
	}
	classic := b.sent[sessionTypeTraffic].Load()
	release()
	if session(b, a) != "pq" {
		t.Fatalf("let go past the end of A's key: B %s", session(b, a))
	}
	s, g := streamCount(b, a, "B after", 2*time.Second)
	s2, g2 := streamCount(a, b, "A after", 2*time.Second)
	if g < s*9/10 || g2 < s2*9/10 {
		t.Fatalf("after the held init: B to A %d/%d, A to B %d/%d; B %s, A %s", g, s, g2, s2, session(b, a), session(a, b))
	}
	if n := b.sent[sessionTypeTraffic].Load() - classic; n != 0 {
		t.Fatalf("%d classic packets of B's after the held init", n)
	}
}

/****************
 * R3-2, R3-3 *
 ****************/

// R3-2: B past SessionMax, A holds B to PQ, B does not hold A: A refuses classic, and B takes A's PQ init all the
// same (SessionMax limits the PQ sessions B starts): a session both ways.
func TestPQPeerStartsPastSessionMax(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, PQConfig{Enabled: true, SessionMax: 1})
	c := lightPC(t)
	cKey, bKey := edOf(c), b.key()
	b.pc.sessions.handleData(nil, &cKey, pqInitFrom(t, c, b.pc)) // a filler: B at SessionMax
	phony.Block(&b.pc.sessions, func() {})
	knows(t, a.pc, b.pc)
	a.pc.pq.markSticky(&bKey, b.pc.pqOwn().notAfter, true) // an earlier session
	linkPQ(t, a, b)
	if !hears(a, b, "A to B", 5*time.Second) || !hears(b, a, "B to A", 3*time.Second) {
		t.Fatalf("no session: A %s, B %s; B's PQ sessions %d", session(a, b), session(b, a), b.pc.PQSessionCount())
	}
	if session(a, b) != "pq" || b.pc.PQSessionCount() != 2 {
		t.Fatalf("A %s; B's PQ sessions %d", session(a, b), b.pc.PQSessionCount())
	}
}

// R3-3: the hard limit (SessionMax and a quarter, at least 64 more) holds every PQ session, those of keys held to PQ
// too. At it, a PQ session nothing opened under goes first, the oldest, one of a key held to PQ last, its classic
// session taking its place (and the upgrade tried again); with every one in use, the new one is refused.
func TestPQHardLimit(t *testing.T) {
	var log logSink
	n := newPQNode(t, PQConfig{Enabled: true, Logf: log.f, SessionMax: 1}) // no link
	hard := n.pc.pq.hardMax()
	if hard != 65 {
		t.Fatalf("hard limit %d with SessionMax 1, want 65", hard)
	}
	var keys []edPub
	for i := 0; i < hard; i++ {
		p := lightPC(t)
		keys = append(keys, edOf(p))
		switch i {
		case 0:
			n.pc.sessions.handleData(nil, &keys[0], classicInitFrom(t, p, n.pc)) // a classic session beside it
		case 2:
		default:
			n.pc.pq.markSticky(&keys[i], p.pqOwn().notAfter, true) // held to PQ; keys 0 and 2 may be classic
		}
		n.pc.sessions.handleData(nil, &keys[i], pqInitFrom(t, p, n.pc))
	}
	phony.Block(&n.pc.sessions, func() {})
	syncSessions(n)
	if got := n.pc.PQSessionCount(); got != hard {
		t.Fatalf("%d PQ sessions, want %d (the hard limit)", got, hard)
	}
	more := func() edPub {
		p := lightPC(t)
		k := edOf(p)
		deliverTo(n, k, pqInitFrom(t, p, n.pc))
		return k
	}
	pqWith := func(k edPub) bool {
		s := sessionOf(n, k)
		return s != nil && s.pq
	}
	// one more: the oldest that may be classic (key 0) goes, its classic session back, its own timer stopped (R4B-1)
	victim := sessionOf(n, keys[0])
	k1 := more()
	var running bool
	phony.Block(victim, func() { running = victim.timer != nil && victim.timer.Stop() })
	if running {
		t.Fatal("the PQ session pushed out still has its timer running: it is held for idleTimeout")
	}
	var retry bool
	phony.Block(&n.pc.sessions, func() { retry = n.pc.sessions.pqRetry[keys[0]] })
	if !pqWith(k1) || pqWith(keys[0]) || sessionOf(n, keys[0]) == nil || !retry || n.pc.PQSessionCount() != hard {
		t.Fatalf("past the hard limit: new one %v, oldest PQ %v classic %v, retry %v, %d PQ sessions", pqWith(k1), pqWith(keys[0]),
			sessionOf(n, keys[0]) != nil, retry, n.pc.PQSessionCount())
	}
	// one more: key 1, older, is held to PQ; key 2 goes
	more()
	if !pqWith(keys[1]) || pqWith(keys[2]) {
		t.Fatalf("a key held to PQ went before one that may be classic: key 1 PQ %v, key 2 PQ %v", pqWith(keys[1]), pqWith(keys[2]))
	}
	logSync(n.pc)
	if log.count("made room") == 0 {
		t.Fatalf("log: %q", log.all())
	}
	// every one in use: refused
	phony.Block(&n.pc.sessions, func() {
		now := n.pc.pq.now().UnixNano()
		for _, s := range n.pc.sessions.sessions {
			if s.pq {
				s.confirmed.Store(true)
				s.openedAt.Store(now)
			}
		}
	})
	acks := n.sent[sessionTypePQAck].Load()
	if k := more(); pqWith(k) || n.sent[sessionTypePQAck].Load() != acks || n.pc.PQSessionCount() != hard {
		t.Fatalf("every PQ session in use: a new one taken (%v), %d acks, %d PQ sessions", pqWith(k), n.sent[sessionTypePQAck].Load()-acks, n.pc.PQSessionCount())
	}
	logSync(n.pc)
	if log.count("each in use") != 1 {
		t.Fatalf("log: %q", log.all())
	}
}

/********
 * R3-4 *
 ********/

// R3-4: forged classic traffic claimed from a key held to PQ (no session, its ML-KEM key known) gets one PQ init, at
// most once in initReplyInterval, and not sent again on its own; the next packet after initReplyInterval gets it
// again, the same bytes.
func TestPQReplyInitOnce(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, pqOn)                   // no link
	n.pc.pq.pendingTimeout = 13 * time.Second // twice the time of the test's third packet
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true)
	var mu sync.Mutex
	var inits [][]byte
	tap := func(d []byte) bool {
		if d[0] == sessionTypePQInit {
			mu.Lock()
			inits = append(inits, append([]byte(nil), d...))
			mu.Unlock()
		}
		return false
	}
	n.tap.Store(&tap)
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(inits)
	}
	start := time.Now()
	deliverTo(n, k, junk(sessionTypeTraffic, sessionTrafficOverheadMin))
	deliverTo(n, k, junk(sessionTypeTraffic, sessionTrafficOverheadMin))
	if got := count(); got != 1 {
		t.Fatalf("two forged packets at once: %d PQ inits, want 1", got)
	}
	time.Sleep(2*pqInitRetry + 200*time.Millisecond)
	if got := count(); got != 1 {
		t.Fatalf("%d PQ inits in %v for one forged packet: sent again on its own", got, time.Since(start).Round(time.Millisecond))
	}
	time.Sleep(time.Until(start.Add(2*initReplyInterval + 100*time.Millisecond)))
	deliverTo(n, k, junk(sessionTypeTraffic, sessionTrafficOverheadMin))
	if got := count(); got != 2 {
		t.Fatalf("the next forged packet after initReplyInterval: %d PQ inits in all, want 2", got)
	}
	mu.Lock()
	same := bytes.Equal(inits[0], inits[1])
	mu.Unlock()
	if !same {
		t.Fatal("the PQ init sent again was sealed anew")
	}
	// given up after pendingTimeout, with no upgrade of ours scheduled for it
	time.Sleep(time.Until(start.Add(n.pc.pq.pendingTimeout)))
	for deadline := start.Add(2 * n.pc.pq.pendingTimeout); ; time.Sleep(100 * time.Millisecond) {
		var pending, retry bool
		phony.Block(&n.pc.sessions, func() {
			pending, retry = n.pc.sessions.pqPending[k] != nil, n.pc.sessions.pqRetry[k]
		})
		if retry {
			t.Fatal("an upgrade of ours scheduled for a forged packet")
		}
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still pending %v on", time.Since(start).Round(time.Second))
		}
	}
}

/********
 * R3-5 *
 ********/

// R3-5, R2-4: answers to packets no one signed, claimed from keys known here, take tokens of the shared bucket: our
// PQInfo to a forged classic init of a key held to PQ, our PQ init to forged classic traffic of one with no session,
// our PQ init to forged PQ traffic of one with a classic session. The per-key limits, flushed by other forged
// packets, do not let them past it.
func TestPQForgedAsksBucket(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	n.pc.pq.peersMax = 8
	var held, classic []edPub
	for i := 0; i < 2; i++ {
		p := lightPC(t)
		k := edOf(p)
		knows(t, n.pc, p)
		n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true)
		held = append(held, k)
		q := lightPC(t)
		qk := edOf(q)
		deliverTo(n, qk, classicInitFrom(t, q, n.pc)) // a classic session first, its ML-KEM key unknown yet
		knows(t, n.pc, q)
		classic = append(classic, qk)
	}
	sent := func() int64 { return n.sent[sessionTypePQInfo].Load() + n.sent[sessionTypePQInit].Load() }
	before := sent()
	start := time.Now()
	rounds := 30
	for r := 0; r < rounds; r++ {
		for i := range held {
			n.pc.sessions.handleData(nil, &held[i], junk(sessionTypeInit, sessionInitSize))
			n.pc.sessions.handleData(nil, &held[i], junk(sessionTypeTraffic, sessionTrafficOverheadMin))
			n.pc.sessions.handleData(nil, &classic[i], junk(sessionTypePQTraffic, pqTrafficOverheadMin))
		}
		for i := 0; i <= n.pc.pq.peersMax; i++ {
			fake := newPeerEd(t)
			n.pc.sessions.handleData(nil, &fake, junk(sessionTypeTraffic, sessionTrafficOverheadMin))
		}
	}
	phony.Block(&n.pc.sessions, func() {})
	elapsed := time.Since(start)
	got := sent() - before
	most := int64(pqUnsolicitedRate*(1+elapsed.Seconds())) + 1
	t.Logf("%d PQInfos and PQ inits for %d forged packets of known keys in %v (the bucket allows %d)", got, rounds*3*len(held), elapsed.Round(time.Millisecond), most)
	if got == 0 || got > most {
		t.Fatalf("%d answers to forged packets of known keys in %v, the bucket allows 1 to %d", got, elapsed, most)
	}
}

// R3-5: a PQInfo out of time (signed long ago, replayed) makes no entry in the table of keys: the key stays one with
// no entry, whose answers come from the bucket.
func TestPQStaleInfoNoEntry(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	stale := p.newPQOwnKey(uint64(time.Now().Add(-6 * 24 * time.Hour).Unix()))
	deliverTo(n, k, append(allocBytes(0), stale.info...))
	n.pc.pq.mu.Lock()
	_, entry := n.pc.pq.peers[k]
	n.pc.pq.unknownBucket = pqBucket{at: time.Now().Add(time.Hour)} // the bucket empty (for the next hour)
	n.pc.pq.limits = make(map[edPub]*list.Element)                  // the per-key limits flushed
	n.pc.pq.limitsLRU.Init()
	n.pc.pq.mu.Unlock()
	if entry {
		t.Fatal("a PQInfo out of time made an entry")
	}
	before := n.sent[sessionTypePQInfo].Load()
	deliverTo(n, k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	if got := n.sent[sessionTypePQInfo].Load() - before; got != 0 {
		t.Fatalf("%d PQInfos with the bucket empty to a key a stale PQInfo was replayed for", got)
	}
}

/********
 * R3-6 *
 ********/

// R3-6: A turns PQ off and only reads; B, its PQ session confirmed, writes. A answers B's PQ traffic with a classic
// init; once B holds A to PQ no longer, it takes it, and B's traffic reaches A (in a few seconds: the init has keys
// A forgets, and the two settle the session as upstream's do, by inits once in initReplyInterval).
func TestPQOffReceiveOnly(t *testing.T) {
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
	time.Sleep(1100 * time.Millisecond) // A's classic init numbered after the PQ session's
	a.pc.SetPQ(PQConfig{})
	clockB.Store(int64(time.Until(time.Unix(int64(e.until), 0)) + time.Minute))
	// settled once a second of B's traffic gets through (some 5 s; up to 12 s allowed)
	s0, g0 := 0, 0
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); {
		s, g := streamCount(b, a, "settling", time.Second)
		s0, g0 = s0+s, g0+g
		if g >= s*9/10 {
			break
		}
	}
	s, g := streamCount(b, a, "B to A", 2*time.Second)
	if g < s*9/10 {
		t.Fatalf("A with PQ off, only B writing: B to A %d/%d then %d/%d; B %s; A sent %d classic inits", g0, s0, g, s,
			session(b, a), a.sent[sessionTypeInit].Load())
	}
	if a.sent[sessionTypeInit].Load()+a.sent[sessionTypeAck].Load() == 0 {
		t.Fatal("A sent no classic init or ack")
	}
}

// R3-6: a PQ session nothing opens under goes after idleTimeout though this end keeps sending under it; a classic
// session is kept up by its sends, as upstream's.
func TestPQSilentSessionExpires(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, pqOn) // no link
	n.pc.sessions.idleTimeout = 500 * time.Millisecond
	p, q := lightPC(t), lightPC(t)
	pk, qk := edOf(p), edOf(q)
	deliverTo(n, pk, pqInitFrom(t, p, n.pc))
	deliverTo(n, qk, classicInitFrom(t, q, n.pc))
	pqInfo, classic := sessionOf(n, pk), sessionOf(n, qk)
	if pqInfo == nil || !pqInfo.pq || classic == nil || classic.pq {
		t.Fatal("setup: no PQ and classic sessions")
	}
	for start := time.Now(); time.Since(start) < 1500*time.Millisecond; time.Sleep(50 * time.Millisecond) {
		n.pc.WriteTo([]byte("p"), types.Addr(p.publicEd[:]))
		n.pc.WriteTo([]byte("q"), types.Addr(q.publicEd[:]))
	}
	if sessionOf(n, pk) == pqInfo {
		t.Fatal("a PQ session nothing opened under stayed up by our sends")
	}
	if sessionOf(n, qk) != classic {
		t.Fatal("a classic session went though our sends went on under it")
	}
}

/**********
 * R3B-2 *
 **********/

// An old timer of a session replaced since does not remove the one in its place.
func TestPQExpireKeepsSuccessor(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	deliverTo(n, k, classicInitFrom(t, p, n.pc))
	old := sessionOf(n, k)
	var now *sessionInfo
	phony.Block(&n.pc.sessions, func() {
		mgr := &n.pc.sessions
		next := newSession(&k, boxPub{}, boxPub{}, 5)
		next.mgr = mgr
		mgr._put(k, next)
		mgr._expire(old)
		now = mgr.sessions[k]
	})
	if now == nil || now == old {
		t.Fatalf("the old session's timer: the table holds %v (the old one %v)", now != nil, now == old)
	}
}

// Classic traffic to a PQ session gets one probe in reply in initReplyInterval, not one a packet.
func TestPQProbeReplyLimited(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	deliverTo(n, k, pqInitFrom(t, p, n.pc))
	sessionOf(n, k).confirmed.Store(true)
	for i := 0; i < 10; i++ {
		n.pc.sessions.handleData(nil, &k, junk(sessionTypeTraffic, sessionTrafficOverheadMin+20))
	}
	phony.Block(&n.pc.sessions, func() {})
	syncSessions(n)
	if got := n.sent[sessionTypePQTraffic].Load(); got != 1 {
		t.Fatalf("%d probes in reply to 10 classic packets at once, want 1", got)
	}
}

// DebugSessionInfo.PQConfirmed: false for a PQ session nothing opened under yet, true once a packet of the peer's did.
func TestPQDebugConfirmed(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	classicThenPQ(t, a, b)
	confirmed := func() (pq, conf bool) {
		for _, s := range a.pc.Debug.GetSessions() {
			if bytes.Equal(s.Key, b.pub) {
				return s.PQ, s.PQConfirmed
			}
		}
		return
	}
	if pq, conf := confirmed(); !pq || conf {
		t.Fatalf("before a packet opened: PQ %v, PQConfirmed %v", pq, conf)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if pq, conf := confirmed(); pq && conf {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PQConfirmed not set once B's packets opened")
		}
		b.pc.WriteTo([]byte("x"), types.Addr(a.pub))
	}
	if s := sessionOf(a, b.key()); s == nil || !a.pc.sessions._openedWithin(s, time.Minute) {
		t.Fatal("no time of the last packet opened kept (the guard of R3-1 and the hard limit go by it)")
	}
}

// R3-4: a PQ init of ours sent once in reply to a packet no one signed is sent again until its ack once data of
// ours waits for the session.
func TestPQReplyOnceThenData(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true)
	deliverTo(n, k, junk(sessionTypeTraffic, sessionTrafficOverheadMin))
	if got := n.sent[sessionTypePQInit].Load(); got != 1 {
		t.Fatalf("%d PQ inits in reply to a forged packet, want 1", got)
	}
	n.pc.WriteTo([]byte("data"), types.Addr(p.publicEd[:]))
	if got := n.sent[sessionTypePQInit].Load(); got != 2 {
		t.Fatalf("data waiting: %d PQ inits in all, want 2", got)
	}
	time.Sleep(2*pqInitRetry + 500*time.Millisecond)
	if got := n.sent[sessionTypePQInit].Load(); got < 3 {
		t.Fatalf("data waiting, twice pqInitRetry on: %d PQ inits in all, want 3 or more", got)
	}
}

// The embedder's Logf is called with no lock of ours held (it may call into the PacketConn).
func TestPQLogfOutsideLock(t *testing.T) {
	pc := newBarePC(t)
	var lines, under atomic.Int64
	cfg := pqOn
	cfg.Logf = func(string, ...any) {
		lines.Add(1)
		if pc.pq.mu.TryLock() {
			pc.pq.mu.Unlock()
		} else {
			under.Add(1)
		}
	}
	pc.SetPQ(cfg)
	pc.pq.stickyMax = 1
	now := uint64(time.Now().Unix())
	k1, k2, k3 := newPeerEd(t), newPeerEd(t), newPeerEd(t)
	// each line waited for: Logf runs from a goroutine of its own, and the test's calls take the lock meanwhile
	pc.pq.markSticky(&k1, now+3600, true)
	pc.pq.markSticky(&k2, now+3600, true) // past stickyMax: a line
	logSync(pc)
	pub1, pub2 := newPQKeyPub(t), newPQKeyPub(t)
	pc.pq.accept(&k3, &pub1, now-6*24*3600, now-4*24*3600) // out of time: a line
	logSync(pc)
	pc.pq.accept(&k3, &pub1, now, now+3600)
	pc.pq.accept(&k3, &pub2, now-10, now+1800) // kept aside
	pc.pq.takeRollback(&k3)                    // taken: a line
	logSync(pc)
	pc.pq.logStripped(&k3, "nothing", "a test")
	logSync(pc)
	if lines.Load() != 4 || under.Load() != 0 {
		t.Fatalf("%d lines, %d of them under the lock", lines.Load(), under.Load())
	}
}

// A confirmed PQ session, the peer back on classic (its probes went unanswered) re-raising PQ: our ack to its new PQ
// init goes with an empty packet that confirms its session at once, rather than its classic traffic being dropped
// until our next probe in reply (initReplyInterval).
func TestPQReRaiseConfirmedAtOnce(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	b.pc.pq.pendingTimeout, b.pc.pq.upgradeRetry = time.Second, 10*time.Minute
	a.dropType[sessionTypePQTraffic].Store(true) // B is never confirmed, and goes back to classic
	classicThenPQ(t, a, b)
	for deadline := time.Now().Add(5 * time.Second); session(b, a) != "classic" || session(a, b) != "pq"; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("setup: A %s, B %s", session(a, b), session(b, a))
		}
		b.pc.WriteTo([]byte("x"), types.Addr(a.pub))
	}
	a.dropType[sessionTypePQTraffic].Store(false)
	var sawPQ time.Time
	for deadline := time.Now().Add(8 * time.Second); session(b, a) != "pq"; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("B not PQ again in 8 s: A %s, B %s", session(a, b), session(b, a))
		}
		if session(b, a) == "pq, unconfirmed" && sawPQ.IsZero() {
			sawPQ = time.Now()
		}
		b.pc.WriteTo([]byte("x"), types.Addr(a.pub))
	}
	if !sawPQ.IsZero() && time.Since(sawPQ) > time.Second {
		t.Fatalf("B's new PQ session confirmed %v after it came up", time.Since(sawPQ).Round(time.Millisecond))
	}
}

// R3-1: the hold on a key moved on by traffic opened under its PQ session is by the ML-KEM key the session is under
// (its end and the slack), not a newer key of the peer's in the table; and it keeps the key held past the end of
// the hold it had, as long as traffic opens.
func TestPQRemarkBySessionKey(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	clockB := testClock(b.pc)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic over PQ")
	}
	aKey, aOwn := a.key(), a.pc.pqOwn()
	b.pc.pq.mu.Lock()
	b.pc.pq.stickyLRU.Remove(b.pc.pq.sticky[aKey])
	delete(b.pc.pq.sticky, aKey)
	b.pc.pq.mu.Unlock()
	// a newer key of A's in B's table, a day after the session's
	newer := newPQKeyPub(t)
	day, slack := uint64(24*3600), uint64(pqClockSlack/time.Second)
	if ok, _ := b.pc.pq.accept(&aKey, &newer, aOwn.seq+day, aOwn.notAfter+day); !ok {
		t.Fatal("the newer key not taken")
	}
	// B's clock an hour short of the end of the session's key and the slack
	clockB.Store(int64(time.Until(time.Unix(int64(aOwn.notAfter+slack), 0)) - time.Hour))
	if !hears(a, b, "an hour short", 3*time.Second) {
		t.Fatal("no traffic")
	}
	syncSessions(b)
	e := stickyFor(b.pc, aKey)
	if e == nil {
		t.Fatal("traffic opened under the PQ session did not hold A to PQ again")
	}
	if e.until != aOwn.notAfter+slack {
		t.Fatalf("held until %d, want %d (the session's key and the slack, not the newer key's)", e.until, aOwn.notAfter+slack)
	}
}

// R3-1, R4-3: a PQ packet replayed (it opened once) does not move the hold on its sender on, nor raise it in the
// sticky LRU, nor the time of the last packet opened. The packet is one of A's taken off the link and delivered by the
// test, so that it is known to have opened at B; its copy is the replay.
func TestPQReplayNoRemark(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	clockB := testClock(b.pc)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic over PQ")
	}
	time.Sleep(300 * time.Millisecond) // the copies hears sent while it waited, still on the way, arrive first
	for len(b.heard) > 0 {
		<-b.heard
	}
	var mu sync.Mutex
	var held []byte
	tap := func(d []byte) bool {
		mu.Lock()
		defer mu.Unlock()
		if d[0] != sessionTypePQTraffic || held != nil {
			return false
		}
		held = append([]byte(nil), d...)
		return true
	}
	a.tap.Store(&tap)
	a.pc.WriteTo([]byte("held back"), types.Addr(b.pub))
	syncSessions(a)
	a.tap.Store(nil)
	aKey := a.key()
	hearsOnce := func(msg string) bool {
		for timeout := time.After(time.Second); ; {
			select {
			case got := <-b.heard:
				if got == msg {
					return true
				}
			case <-timeout:
				return false
			}
		}
	}
	mu.Lock()
	packet := held
	mu.Unlock()
	if packet == nil {
		t.Fatal("no PQ packet of A's taken off the link")
	}
	deliverTo(b, aKey, append(allocBytes(0), packet...))
	if !hearsOnce("held back") {
		t.Fatal("the packet taken off the link did not open at B: the test proves nothing")
	}
	info := sessionOf(b, aKey)
	before, opened := stickyFor(b.pc, aKey).until, info.openedAt.Load()
	other := newPeerEd(t)
	clockB.Store(int64(pqStickyRefresh + time.Hour))
	b.pc.pq.markSticky(&other, uint64(time.Now().Add(24*time.Hour).Unix()), true) // the front of the LRU
	deliverTo(b, aKey, append(allocBytes(0), packet...))
	b.pc.pq.mu.Lock()
	front := b.pc.pq.stickyLRU.Front().Value.(*stickyKey).ed
	b.pc.pq.mu.Unlock()
	if after := stickyFor(b.pc, aKey).until; after != before || front == aKey || info.openedAt.Load() != opened || hearsOnce("held back") {
		t.Fatalf("a replayed packet: hold %d -> %d, raised %v, opened time moved %v", before, after, front == aKey, info.openedAt.Load() != opened)
	}
	// a new packet does
	if !hears(a, b, "new", 3*time.Second) {
		t.Fatal("no traffic")
	}
	syncSessions(b)
	if after := stickyFor(b.pc, aKey).until; after <= before || info.openedAt.Load() == opened {
		t.Fatalf("a new packet an hour on did not move the hold on (%d -> %d) or the opened time", before, after)
	}
}

// R3-4: a PQ init sent in reply to forged PQ traffic of a key with a classic session, given up unanswered, leaves no
// upgrade of ours scheduled (that one would be sent again and again for the one packet).
func TestPQReplyInitNoUpgradeLater(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, pqOn) // no link
	n.pc.pq.pendingTimeout = 500 * time.Millisecond
	q := lightPC(t)
	k := edOf(q)
	deliverTo(n, k, classicInitFrom(t, q, n.pc)) // a classic session, its ML-KEM key unknown yet
	knows(t, n.pc, q)
	deliverTo(n, k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	if got := n.sent[sessionTypePQInit].Load(); got != 1 {
		t.Fatalf("%d PQ inits in reply to forged PQ traffic, want 1", got)
	}
	time.Sleep(1200 * time.Millisecond)
	var pending, retry bool
	phony.Block(&n.pc.sessions, func() {
		pending, retry = n.pc.sessions.pqPending[k] != nil, n.pc.sessions.pqRetry[k]
	})
	if pending || retry {
		t.Fatalf("after pendingTimeout: still pending %v, an upgrade scheduled %v", pending, retry)
	}
}

// R3-6: a one-way PQ flow (we write, the peer only reads) past twice idleTimeout: the reader's empty packet, once it
// sent nothing for a quarter of idleTimeout, keeps our session up. No session goes, no handshake comes, nothing is lost.
func TestPQOneWayFlowKeptUp(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	for _, n := range []*pqNode{a, b} {
		n.pc.sessions.idleTimeout = time.Second
	}
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic over PQ")
	}
	handshakes := func() (n int64) {
		for _, x := range []*pqNode{a, b} {
			for _, typ := range []byte{sessionTypeInit, sessionTypeAck, sessionTypePQInit, sessionTypePQAck} {
				n += x.sent[typ].Load()
			}
		}
		return
	}
	bKey := b.key()
	before, hs := sessionOf(a, bKey), handshakes()
	s, g := streamCount(a, b, "one way", 3*time.Second)
	if g < s-1 {
		t.Fatalf("a one-way flow: %d of %d heard", g, s)
	}
	if sessionOf(a, bKey) != before || handshakes() != hs {
		t.Fatalf("a one-way flow of 3 s, idleTimeout 1 s: the writer's session replaced %v, %d handshake packets", sessionOf(a, bKey) != before, handshakes()-hs)
	}
}
