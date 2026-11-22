package encrypted

// Round-5 review: replays, buckets and costs

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// r5Counter drains n.heard into counts (a message heard twice: a replay opened)
type r5Counter struct {
	mu sync.Mutex
	m  map[string]int
}

func r5Count(n *pqNode, stop chan struct{}) *r5Counter {
	c := &r5Counter{m: map[string]int{}}
	go func() {
		for {
			select {
			case s := <-n.heard:
				c.mu.Lock()
				c.m[s]++
				c.mu.Unlock()
			case <-stop:
				return
			}
		}
	}()
	return c
}

func (c *r5Counter) dups(prefix string) (d, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.m {
		if strings.HasPrefix(k, prefix) {
			total++
			if v > 1 {
				d++
			}
		}
	}
	return
}

// R5-1: the ratchet step in doRecv (fromNext: _fixShared(nonce, 0)) resets the window of the key that becomes recv to
// {nonce}; packets accepted under that key while it was nextSend (strict mark, the step rate-limited to one a minute)
// open again as case 0 after the step. No re-init and no forged packet: plain two-way traffic for a minute. Each
// node's captured inbound packets are replayed to it right after each of its steps.
func rotationReplay(t *testing.T, cfg PQConfig, dur time.Duration) {
	a, b := newPQNode(t, cfg), newPQNode(t, cfg)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	traffic := byte(sessionTypeTraffic)
	if cfg.Enabled {
		waitSessions(t, a, b, "pq", 10*time.Second)
		traffic = sessionTypePQTraffic
	}
	stop := make(chan struct{})
	defer close(stop)
	type side struct {
		n, peer *pqNode
		cnt     *r5Counter
		mu      sync.Mutex
		caps    [][]byte // the peer's packets to n
		last    time.Time
		steps   int
		dups    int
	}
	sides := []*side{{n: a, peer: b}, {n: b, peer: a}}
	for _, sd := range sides {
		sd := sd
		sd.cnt = r5Count(sd.n, stop)
		tap := func(d []byte) bool {
			if d[0] == traffic {
				sd.mu.Lock()
				sd.caps = append(sd.caps, append([]byte(nil), d...))
				sd.mu.Unlock()
			}
			return false
		}
		sd.peer.tap.Store(&tap)
	}
	rotatedOf := func(sd *side) (r time.Time, ok bool) {
		s := sessionOf(sd.n, sd.peer.key())
		if s == nil {
			return
		}
		phony.Block(s, func() { r = s.rotated })
		return r, true
	}
	for _, sd := range sides {
		sd.last, _ = rotatedOf(sd)
	}
	inits0 := handshakePackets(a, b)
	begin := time.Now()
	for i := 0; time.Since(begin) < dur; i++ {
		a.pc.WriteTo([]byte(fmt.Sprintf("m %d", i)), types.Addr(b.pub))
		b.pc.WriteTo([]byte(fmt.Sprintf("m %d", i)), types.Addr(a.pub))
		time.Sleep(20 * time.Millisecond)
		for _, sd := range sides {
			r, ok := rotatedOf(sd)
			if !ok || r.Equal(sd.last) {
				continue
			}
			sd.last = r
			sd.steps++
			time.Sleep(50 * time.Millisecond)
			d0, _ := sd.cnt.dups("m ")
			hs := handshakePackets(a, b) - inits0
			sd.mu.Lock()
			rp := sd.caps
			sd.mu.Unlock()
			k := sd.peer.key()
			for _, d := range rp {
				sd.n.pc.sessions.handleData(nil, &k, append(allocBytes(0), d...))
			}
			phony.Block(&sd.n.pc.sessions, func() {})
			syncSessions(sd.n)
			time.Sleep(200 * time.Millisecond)
			d1, _ := sd.cnt.dups("m ")
			sd.dups += d1 - d0
			t.Logf("+%s: a step of %s's; %d captured packets replayed to it, %d messages delivered a second time (handshake packets so far %d)",
				time.Since(begin).Round(time.Second), map[bool]string{true: "A", false: "B"}[sd.n == a], len(rp), d1-d0, hs)
		}
	}
	for _, sd := range sides {
		if sd.dups > 0 {
			t.Errorf("R5-1 (pq %v): %d messages opened again at %s after its ratchet steps (%d)", cfg.Enabled, sd.dups,
				map[bool]string{true: "A", false: "B"}[sd.n == a], sd.steps)
		}
	}
}

func TestR5RotationReplayClassic(t *testing.T) {
	t.Parallel()
	rotationReplay(t, PQConfig{}, 65*time.Second)
}
func TestR5RotationReplayPQ(t *testing.T) { t.Parallel(); rotationReplay(t, pqOn, 65*time.Second) }

// R5-2: two PQ inits of the peer's in one second with other keys (both signed, captured): replayed in turn, each is
// "new" against the other, and is taken, again and again: the session's keys flip back, an ack (HPKE seal, 2.5 KB)
// goes for each, and traffic under the peer's real keys stops opening.
func TestR5SameSecondFlip(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	seq := uint64(time.Now().Unix())
	i1 := pqInitSeq(t, p, n.pc, seq)
	i2 := pqInitSeq(t, p, n.pc, seq)
	deliverTo(n, k, append(allocBytes(0), i1...))
	s := sessionOf(n, k)
	phony.Block(s, func() { s.rx = 1 }) // traffic came
	deliverTo(n, k, append(allocBytes(0), i2...))
	acks := n.sent[sessionTypePQAck].Load()
	var ls0 uint64
	phony.Block(s, func() { ls0 = s.localKeySeq })
	for i := 0; i < 50; i++ {
		deliverTo(n, k, append(allocBytes(0), i1...))
		deliverTo(n, k, append(allocBytes(0), i2...))
	}
	var ls1 uint64
	phony.Block(s, func() { ls1 = s.localKeySeq })
	got := n.sent[sessionTypePQAck].Load() - acks
	t.Logf("100 replays of two same-second inits: %d PQ acks sent, the session's key seq moved %d", got, ls1-ls0)
	if got > 0 {
		t.Errorf("R5-2: replayed same-second inits taken %d times", got)
	}
}

// R5-2 for acks: two acks of the peer's of one second with other keys flip the session the same way.
func TestR5SameSecondAckFlip(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), false) })
	seq := uint64(time.Now().Unix())
	cur1, _ := newBoxKeys()
	cur2, _ := newBoxKeys()
	a1, a2 := pqAckSeq(t, p, n.pc, seq, cur1), pqAckSeq(t, p, n.pc, seq, cur2)
	deliverTo(n, k, append(allocBytes(0), a1...))
	s := sessionOf(n, k)
	deliverTo(n, k, append(allocBytes(0), a2...))
	flips := 0
	for i := 0; i < 50; i++ {
		for _, a := range [][]byte{a1, a2} {
			var before, after uint64
			phony.Block(s, func() { before = s.localKeySeq })
			deliverTo(n, k, append(allocBytes(0), a...))
			phony.Block(s, func() { after = s.localKeySeq })
			if after != before {
				flips++
			}
		}
	}
	t.Logf("100 replays of two same-second acks: the session updated %d times", flips)
	if flips > 0 {
		t.Errorf("R5-2: replayed same-second acks taken %d times", flips)
	}
}

// R5-3: the "signed contacts" bucket is drained by packets no one signed, claimed from keys with an entry in peers
// (any key that once sent a signed PQInfo: the attacker's own, or real peers'): forged 0x13 from 150 such keys,
// then a new contact's signed classic init gets no PQInfo.
func TestR5KnownBucketDrain(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	var keys []edPub
	for i := 0; i < 150; i++ {
		p := lightPC(t)
		knows(t, n.pc, p) // one signed PQInfo each, once
		keys = append(keys, edOf(p))
	}
	inits0 := n.sent[sessionTypePQInit].Load()
	for round := 0; round < 3; round++ {
		for _, k := range keys {
			kk := k
			n.pc.sessions.handleData(nil, &kk, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
		}
		phony.Block(&n.pc.sessions, func() {})
	}
	p := lightPC(t)
	before := n.sent[sessionTypePQInfo].Load()
	deliverTo(n, edOf(p), classicInitFrom(t, p, n.pc))
	var retry bool
	k := edOf(p)
	phony.Block(&n.pc.sessions, func() { retry = n.pc.sessions.pqRetry[k] })
	got := n.sent[sessionTypePQInfo].Load() - before
	t.Logf("450 forged 53-B packets from 150 known keys: %d PQ inits (2.5 KB) out; then a new contact's signed classic init: %d PQInfos, retried later %v",
		n.sent[sessionTypePQInit].Load()-inits0, got, retry)
	if got != 1 {
		t.Errorf("R5-3: the known bucket drained by unsigned packets: a signed new contact got %d PQInfos", got)
	}
}

// The scan at the hard limit (2560 at the defaults), every PQ session in use: the cost of _pqRoom alone per refused
// init, with Required nil, cheap, and 1 µs, against the whole refused init (HPKE open, verify, scan).
func TestR5ScanCost(t *testing.T) {
	var slow atomic.Int64
	n := newPQNode(t, PQConfig{Enabled: true, Required: func(ed25519.PublicKey) bool {
		if d := slow.Load(); d != 0 {
			for s := time.Now(); time.Since(s) < time.Duration(d); {
			}
		}
		return false
	}})
	hard := n.pc.pq.hardMax()
	n.pc.sessions.unconfirmedMax = hard + 10
	// the sessions' idle timer (wall clock, set at each session's start, not reset by inUse): fill takes some 30 ms
	// an init under -race, and past idleTimeout (a minute) the first sessions would go while the last are made, the
	// count stuck short of hard (R7-S). Set before any session, as unconfirmedMax
	n.pc.sessions.idleTimeout = time.Hour
	keys := fill(t, n, hard)
	inUse(n, keys)
	p := lightPC(t)
	k := edOf(p)
	for _, d := range []time.Duration{0, time.Microsecond} {
		slow.Store(int64(d))
		const m = 200
		var took time.Duration
		var ok bool
		phony.Block(&n.pc.sessions, func() {
			t0 := time.Now()
			for i := 0; i < m; i++ {
				ok = n.pc.sessions._pqRoom(&k)
			}
			took = time.Since(t0) / m
		})
		ds := make([][]byte, 50)
		for i := range ds {
			ds[i] = pqInitFrom(t, p, n.pc)
		}
		t0 := time.Now()
		for _, d := range ds {
			n.pc.sessions.handleData(nil, &k, d)
		}
		phony.Block(&n.pc.sessions, func() {})
		whole := time.Since(t0) / time.Duration(len(ds))
		t.Logf("hard %d, all in use, Required %v: _pqRoom %v per call (room %v); a whole refused PQ init %v", hard, d, took, ok, whole)
	}
}

// N-R5-2 (named R5-4 by the reviewer): one forged 0x13 claimed from a known peer with no session here makes a
// once-pending PQ init (_replyPQInit); lost (the peer unreachable then), it blocks our upgrade of the classic session
// the peer then makes with us (we are the lower key, nothing of ours buffered: _maybeStartPQ returns on any pending),
// and its expiry schedules no upgrade (R3-4): a pin that the session still comes up PQ (the peer's upgrade).
func TestR5OncePendingBlocksUpgrade(t *testing.T) {
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	n, p := lowerFirst(x, y) // n has the lower key: n starts the upgrade
	n.pc.pq.pendingTimeout = 3 * time.Second
	knows(t, n.pc, p.pc) // a PQInfo of p's came once; p not held here
	pKey := p.key()
	n.dropType[sessionTypePQInit].Store(true) // our once-init is lost (p not reachable yet)
	deliverTo(n, pKey, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	var pending bool
	phony.Block(&n.pc.sessions, func() { pending = n.pc.sessions.pqPending[pKey] != nil })
	n.dropType[sessionTypePQInit].Store(false)
	linkPQ(t, n, p)
	// p writes (only p), n only reads
	deadline := time.Now().Add(4 * n.pc.pq.pendingTimeout)
	for time.Now().Before(deadline) {
		p.pc.WriteTo([]byte("p"), types.Addr(n.pub))
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("once-pending made by the forged packet %v; after %s of p writing: n %s, p %s",
		pending, 4*n.pc.pq.pendingTimeout, session(n, p), session(p, n))
	if session(n, p) != "pq" {
		t.Errorf("N-R5-2: the session stayed %s", session(n, p))
	}
}

// The parse at each seal (pqPeerKey.hpkeKey), against the seal (pqInit.encrypt) and the open
func TestR5ParseCost(t *testing.T) {
	n := lightPC(t)
	p := lightPC(t)
	pk := ownAsPeer(t, p)
	const m = 300
	t0 := time.Now()
	for i := 0; i < m; i++ {
		if _, err := pk.hpkeKey(); err != nil {
			t.Fatal(err)
		}
	}
	parse := time.Since(t0) / m
	t1 := time.Now()
	for i := 0; i < m; i++ {
		_ = pqInitFrom(t, n, p)
	}
	seal := time.Since(t1) / m
	t.Logf("hpkeKey (parse) %v; a whole PQ init sealed (parse, sign, HPKE seal) %v", parse, seal)
}
