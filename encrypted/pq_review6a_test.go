package encrypted

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// The tests of review pq-r6a.

// keepWriting: a and b write to each other every 50 ms for d
func keepWriting(a, b *pqNode, d time.Duration) {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		a.pc.WriteTo([]byte("a"), types.Addr(b.pub))
		b.pc.WriteTo([]byte("b"), types.Addr(a.pub))
	}
}

func pendingOf(n *pqNode, k edPub) (p *pqPending, once, retry bool) {
	phony.Block(&n.pc.sessions, func() {
		p = n.pc.sessions.pqPending[k]
		if p != nil {
			once = p.once
		}
		retry = n.pc.sessions.pqRetry[k]
	})
	return
}

// R6A-1: a classic session made while this node is at SessionMax is never upgraded once the table drains ("PQ again
// once it stops", PQConfig.SessionMax): _maybeStartPQ returns on _pqStartFull with no _upgradeLater, and nothing else
// brings the upgrade back while the classic session carries traffic.
func TestR6FullClassicNeverUpgrades(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y) // a, at SessionMax, has the lower key: it is the one to start (the other end answers
	// its PQInfo with its own, and a peer that starts PQ with us still gets it)
	a.pc.SetPQ(PQConfig{Enabled: true, SessionMax: 1})
	for _, n := range []*pqNode{a, b} {
		n.pc.pq.upgradeRetry = time.Second
		n.pc.pq.pendingTimeout = 2 * time.Second
	}
	keys := fill(t, a, 1) // a at SessionMax (a Sybil's session, say)
	linkPQ(t, a, b)
	if !hears(a, b, "a", 3*time.Second) || !hears(b, a, "b", 3*time.Second) {
		t.Fatal("no session")
	}
	keepWriting(a, b, time.Second)
	if session(a, b) != "classic" || session(b, a) != "classic" {
		t.Fatalf("precondition: a %s, b %s", session(a, b), session(b, a))
	}
	// the table drains: the filler's session goes
	phony.Block(&a.pc.sessions, func() { a.pc.sessions._put(keys[0], nil) })
	keepWriting(a, b, 6*time.Second) // six times upgradeRetry
	_, _, retry := pendingOf(a, b.key())
	t.Logf("a lower %v; after 6 s (upgradeRetry 1 s) at %d PQ sessions of SessionMax 1: a %s, b %s; a's upgrade scheduled %v; PQ inits a %d b %d",
		lowerKey(a, b), a.pc.PQSessionCount(), session(a, b), session(b, a), retry, a.sent[sessionTypePQInit].Load(), b.sent[sessionTypePQInit].Load())
	if session(a, b) != "pq" || session(b, a) != "pq" {
		t.Errorf("R6A-1: the classic session made at SessionMax stays classic after the table drained")
	}
}

func lowerKey(a, b *pqNode) bool {
	x, _ := lowerFirst(a, b)
	return x == a
}

// R6A-2 (N-R5-2, the scenario asked for): our upgrade failed (PQ packets dropped on the way for a while), and its
// retry (_upgradeLater) is due. One forged 0x13 claimed from the peer makes a once-pending; its single send is lost
// as the first ones were. The retry meets the once-pending and returns (_maybeStartPQ); the once-pending expires with
// no retry (R3-4). The path is fine again, and the session stays classic with no retry scheduled, for as long as its
// traffic keeps it up. The control (no forged packet) is upgraded by the retry.
func TestR6OnceSwallowsRetry(t *testing.T) {
	for _, forged := range []bool{false, true} {
		name := "control"
		if forged {
			name = "forged"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
			n, p := lowerFirst(x, y) // n starts the upgrade
			n.pc.pq.pendingTimeout = 3 * time.Second
			n.pc.pq.upgradeRetry = time.Second
			knows(t, n.pc, p.pc)
			pKey := p.key()
			n.dropPQ.Store(true) // the path drops n's PQ packets for now
			linkPQ(t, n, p)
			if !hears(n, p, "n", 3*time.Second) || !hears(p, n, "p", 3*time.Second) {
				t.Fatal("no session")
			}
			// n's PQ init goes unanswered; its expiry schedules the retry
			deadline := time.Now().Add(10 * time.Second)
			for {
				pend, _, retry := pendingOf(n, pKey)
				if pend == nil && retry {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no retry scheduled: pending %v, retry %v, n %s", pend != nil, retry, session(n, p))
				}
				n.pc.WriteTo([]byte("n"), types.Addr(p.pub))
				p.pc.WriteTo([]byte("p"), types.Addr(n.pub))
				time.Sleep(20 * time.Millisecond)
			}
			if forged {
				deliverTo(n, pKey, junk(sessionTypePQTraffic, pqTrafficOverheadMin)) // its one send dropped too
			}
			_, once, _ := pendingOf(n, pKey)
			n.dropPQ.Store(false) // the path is fine again
			keepWriting(n, p, 6*time.Second)
			pend, _, retry := pendingOf(n, pKey)
			t.Logf("forged %v (once-pending %v): after 6 s, n %s, p %s; pending %v, retry scheduled %v", forged, once, session(n, p), session(p, n), pend != nil, retry)
			if session(n, p) != "pq" {
				t.Errorf("R6A-2: the session stays %s, no upgrade scheduled %v", session(n, p), !retry)
			}
		})
	}
}

// R6A-4 probe: two once-pendings cross (forged 0x13 to each end, claimed from the other, both with a classic
// session and the other's ML-KEM key): both give way, both answer. Do the ends end up with a working PQ session?
func TestR6BothOnceCross(t *testing.T) {
	t.Skip("R6A-4: crossed once-inits lose some 2.5 s a->b, then heal; its optional fix breaks N-R4-1 (TestPQOnceYieldsUnit) and is not taken")
	t.Parallel()
	a, b := newPQNode(t, PQConfig{}), newPQNode(t, PQConfig{})
	linkPQ(t, a, b)
	if !hears(a, b, "a", 3*time.Second) || !hears(b, a, "b", 3*time.Second) {
		t.Fatal("no session")
	}
	a.pc.SetPQ(pqOn)
	b.pc.SetPQ(pqOn)
	knows(t, a.pc, b.pc)
	knows(t, b.pc, a.pc)
	a.pc.sessions.handleData(nil, ptr(b.key()), junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	b.pc.sessions.handleData(nil, ptr(a.key()), junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	time.Sleep(300 * time.Millisecond)
	t.Logf("after the crossing: a %s, b %s; PQ inits a %d b %d, acks a %d b %d", session(a, b), session(b, a),
		a.sent[sessionTypePQInit].Load(), b.sent[sessionTypePQInit].Load(), a.sent[sessionTypePQAck].Load(), b.sent[sessionTypePQAck].Load())
	if !hears(a, b, "a2", 3*time.Second) || !hears(b, a, "b2", 3*time.Second) {
		t.Fatalf("no traffic after the crossing: a %s, b %s", session(a, b), session(b, a))
	}
	var trace []string
	lostSecs := 0
	for i := 0; i < 8; i++ {
		sab, gab := streamCount(a, b, fmt.Sprintf("a->b%d", i), 500*time.Millisecond)
		sba, gba := streamCount(b, a, fmt.Sprintf("b->a%d", i), 500*time.Millisecond)
		trace = append(trace, fmt.Sprintf("%d/%d %d/%d", gab, sab, gba, sba))
		if gab < sab-1 || gba < sba-1 {
			lostSecs++
		}
	}
	t.Logf("8 x (0.5 s a->b, 0.5 s b->a), heard/sent: %v; inits a %d b %d, PQ inits a %d b %d, acks a %d b %d; a %s, b %s", trace,
		a.sent[sessionTypeInit].Load(), b.sent[sessionTypeInit].Load(), a.sent[sessionTypePQInit].Load(), b.sent[sessionTypePQInit].Load(),
		a.sent[sessionTypePQAck].Load(), b.sent[sessionTypePQAck].Load(), session(a, b), session(b, a))
	if lostSecs > 0 {
		t.Errorf("R6A-4: %d of 8 slots with losses after crossed once-inits", lostSecs)
	}
	keepWriting(a, b, 3*time.Second)
	t.Logf("after 3 s more: a %s, b %s", session(a, b), session(b, a))
	if session(a, b) != "pq" || session(b, a) != "pq" {
		t.Errorf("crossed once-inits: a %s, b %s", session(a, b), session(b, a))
	}
}

func ptr(k edPub) *edPub { return &k }

// R6A-3: A restarts (same ed25519 key, a new ML-KEM key); B held A to PQ and only B writes. B's PQ traffic and its
// PQ inits (sealed to A's old ML-KEM key) get A's PQInfo from the unknown bucket alone (A knows nothing of B now).
// An off-path forger keeps that bucket empty with 0x13 junk from random keys, 1000 a second (some 60 KB/s): B never learns A's new key,
// refuses classic (it holds A), and nothing B writes reaches A while the flood lasts. Control: no flood.
func TestR6RestartFloodNoRecovery(t *testing.T) {
	for _, flood := range []bool{false, true} {
		name := "control"
		if flood {
			name = "flood"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
			b.pc.sessions.idleTimeout = 2 * time.Second
			b.pc.pq.pendingTimeout = 3 * time.Second
			linkPQ(t, a, b)
			if !hears(a, b, "hello", 3*time.Second) {
				t.Fatal("no session")
			}
			waitSessions(t, a, b, "pq", 10*time.Second)
			hears(a, b, "pq", 3*time.Second)
			hears(b, a, "pq back", 3*time.Second)
			if !sticky(b, a) {
				t.Fatal("B does not hold A")
			}
			priv := a.pc.PacketConn.PrivateKey()
			time.Sleep(1100 * time.Millisecond) // A's new ML-KEM key gets another number
			a.pc.Close()
			a2 := newPQNodeKey(t, priv, pqOn)
			stop := make(chan struct{})
			done := make(chan struct{})
			var forged int
			if flood {
				go func() {
					defer close(done)
					tick := time.NewTicker(time.Millisecond)
					defer tick.Stop()
					for {
						select {
						case <-stop:
							return
						case <-tick.C:
							var k edPub
							rand.Read(k[:])
							a2.pc.sessions.handleData(nil, &k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
							forged++
						}
					}
				}()
			} else {
				close(done)
			}
			time.Sleep(100 * time.Millisecond) // the bucket emptied first
			linkPQ(t, a2, b)
			s, g := streamCount(b, a2, "b only", 10*time.Second)
			close(stop)
			<-done
			t.Logf("flood %v (%d forged 0x13, 1000/s): B->A2 %d of %d heard in 10 s; A2 sent PQInfo %d; B sent PQ init %d, classic init %d; A2 %s, B %s",
				flood, forged, g, s, a2.sent[sessionTypePQInfo].Load(), b.sent[sessionTypePQInit].Load(), b.sent[sessionTypeInit].Load(), session(a2, b), session(b, a2))
			if g == 0 {
				t.Errorf("R6A-3: nothing B wrote reached the restarted A")
			}
		})
	}
}

// R6A-5: a PQ ack replayed (captured on the way) to a PQ session with no classic one beside renews the hold on its
// sender (markSticky in _handlePQInit runs whether handleAck took the ack or not): as a replayed PQ packet must not
// (R3-1, TestPQReplayNoRemark). The ack is old (its seq below the session's), and changes nothing else.
func TestR6ReplayedAckRenewsHold(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	clock := testClock(n.pc)
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), false) })
	ack := pqAckFrom(t, p, n.pc) // p's answer to it
	deliverTo(n, k, append(allocBytes(0), ack...))
	s := sessionOf(n, k)
	if s == nil || !s.pq || s.fallback != nil || stickyFor(n.pc, k) == nil {
		t.Fatal("setup: no PQ session from the ack, or not held")
	}
	before := stickyFor(n.pc, k).until
	clock.Store(int64(10 * time.Hour)) // ten hours on, nothing of p's since
	deliverTo(n, k, append(allocBytes(0), ack...))
	after := stickyFor(n.pc, k).until
	t.Logf("hold until %d, after the replay 10 h on %d (+%d s)", before, after, int64(after)-int64(before))
	if after != before {
		t.Errorf("R6A-5: a replayed PQ ack moved the hold on by %d s", int64(after)-int64(before))
	}
	// the session gone (its timeout), the same replay 20 h on: a session is made from it, and the hold moves again
	dropSessions(n)
	clock.Store(int64(20 * time.Hour))
	acks := n.sent[sessionTypePQAck].Load()
	deliverTo(n, k, append(allocBytes(0), ack...))
	again := stickyFor(n.pc, k).until
	t.Logf("no session, replay 20 h on: hold until %d (+%d s), a session made %v, PQ acks sent %d", again, int64(again)-int64(after), sessionOf(n, k) != nil, n.sent[sessionTypePQAck].Load()-acks)
	if again != after {
		t.Errorf("R6A-5: a replayed PQ ack with no session moved the hold on by %d s", int64(again)-int64(after))
	}
}

// R6A-5, the other way in: an ack is not bound to the init it answers, so "an ack to a pending init of ours" does not
// tell a replay either, when the pending one is the once-init anyone has us make with a forged 0x13. No session with
// p, its key known: forged 0x13 claimed from p (a once-pending), then p's captured ack replayed: the hold moves on.
func TestR6ReplayedAckOnceHold(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	clock := testClock(n.pc)
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), false) })
	ack := pqAckFrom(t, p, n.pc)
	deliverTo(n, k, append(allocBytes(0), ack...))
	if stickyFor(n.pc, k) == nil {
		t.Fatal("setup: not held")
	}
	before := stickyFor(n.pc, k).until
	dropSessions(n)
	clock.Store(int64(20 * time.Hour))                                // twenty hours on, nothing of p's since
	deliverTo(n, k, junk(sessionTypePQTraffic, pqTrafficOverheadMin)) // forged: a once-pending to p
	_, once, _ := pendingOf(n, k)
	deliverTo(n, k, append(allocBytes(0), ack...)) // the captured ack again
	after := stickyFor(n.pc, k).until
	t.Logf("once-pending %v; hold until %d, after the forged 0x13 and the replayed ack 20 h on %d (+%d s)", once, before, after, int64(after)-int64(before))
	if !once {
		t.Fatal("setup: no once-pending")
	}
	if after != before {
		t.Errorf("R6A-5: a forged 0x13 and a replayed PQ ack moved the hold on by %d s", int64(after)-int64(before))
	}
}

// R6A-3, measured: how long B's writes take to reach the restarted A (B holds A to PQ, only B writes), with a flood
// of forged 0x13 from random keys at the rate given, up to 40 s.
func TestR6RestartFloodRecoveryTime(t *testing.T) {
	for _, rate := range []int{0, 40, 100, 1000} {
		rate := rate
		t.Run(fmt.Sprint(rate), func(t *testing.T) {
			t.Parallel()
			a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
			b.pc.sessions.idleTimeout = 2 * time.Second
			b.pc.pq.pendingTimeout = 3 * time.Second
			linkPQ(t, a, b)
			if !hears(a, b, "hello", 3*time.Second) {
				t.Fatal("no session")
			}
			waitSessions(t, a, b, "pq", 10*time.Second)
			hears(a, b, "pq", 3*time.Second)
			hears(b, a, "pq back", 3*time.Second)
			if !sticky(b, a) {
				t.Fatal("B does not hold A")
			}
			priv := a.pc.PacketConn.PrivateKey()
			time.Sleep(1100 * time.Millisecond)
			a.pc.Close()
			a2 := newPQNodeKey(t, priv, pqOn)
			stop := make(chan struct{})
			defer close(stop)
			if rate > 0 {
				go func() {
					tick := time.NewTicker(time.Second / time.Duration(rate))
					defer tick.Stop()
					for {
						select {
						case <-stop:
							return
						case <-tick.C:
							var k edPub
							rand.Read(k[:])
							a2.pc.sessions.handleData(nil, &k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
						}
					}
				}()
				time.Sleep(100 * time.Millisecond)
			}
			linkPQ(t, a2, b)
			start := time.Now()
			got := false
			for i := 0; time.Since(start) < 40*time.Second && !got; i++ {
				b.pc.WriteTo([]byte(fmt.Sprint("b", i)), types.Addr(a2.pub))
				select {
				case <-a2.heard:
					got = true
				case <-time.After(50 * time.Millisecond):
				}
			}
			t.Logf("flood %d/s: B->A2 first heard after %v (got %v); A2 PQInfos %d, B PQ inits %d", rate, time.Since(start).Round(100*time.Millisecond), got,
				a2.sent[sessionTypePQInfo].Load(), b.sent[sessionTypePQInit].Load())
			if !got {
				t.Errorf("R6A-3: nothing of B's reached the restarted A in 40 s at %d forged 0x13 a second", rate)
			}
		})
	}
}

// Classic (as upstream, not of the PQ feature; r5a's open hypothesis): our own packets reflected back to us open as
// the peer's. A re-init of the peer's that keeps its current key (its _sendInit on a packet it cannot open, which
// anyone can have it send with a forged packet claimed from us) makes our new receive key our old send key (box
// keys are the same both ways), with a fresh window: a packet of ours captured on the way, sent back to us as from
// the peer, is read as the peer's message. PQ sessions bind the direction (pqTrafficKey: from, to): not affected.
func TestR6ClassicReflection(t *testing.T) {
	t.Skip("P-1: classic reflection as upstream 0712ecc has it, not of the PQ feature; left for the owner")
	for _, v := range []struct{ pq, reinit bool }{{false, false}, {false, true}, {true, true}} {
		pq, reinit := v.pq, v.reinit
		t.Run(fmt.Sprint("pq=", pq, ",reinit=", reinit), func(t *testing.T) {
			t.Parallel()
			cfg := PQConfig{}
			if pq {
				cfg = pqOn
			}
			a, b := newPQNode(t, cfg), newPQNode(t, cfg)
			linkPQ(t, a, b)
			if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "hello back", 3*time.Second) {
				t.Fatal("no session")
			}
			if pq {
				waitSessions(t, a, b, "pq", 10*time.Second)
				hears(a, b, "pq", 3*time.Second)
				hears(b, a, "pq back", 3*time.Second)
			}
			var captured atomic.Pointer[[]byte]
			tap := func(data []byte) bool {
				if (data[0] == sessionTypeTraffic || data[0] == sessionTypePQTraffic) && len(data) > 60 && captured.Load() == nil {
					c := append([]byte(nil), data...)
					captured.Store(&c)
				}
				return false
			}
			a.tap.Store(&tap)
			a.pc.WriteTo([]byte("a's own words, to b"), types.Addr(b.pub))
			for deadline := time.Now().Add(3 * time.Second); captured.Load() == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			}
			a.tap.Store(nil)
			if captured.Load() == nil {
				t.Fatal("nothing captured")
			}
			drain := func(n *pqNode) {
				for {
					select {
					case <-n.heard:
					case <-time.After(300 * time.Millisecond):
						return
					}
				}
			}
			drain(b)
			drain(a)
			time.Sleep(1100 * time.Millisecond) // the re-init of another second (a same-second classic one is a repeat)
			bs := sessionOf(b, a.key())
			if reinit {
				phony.Block(bs, func() { bs._sendInit() })
			} // b's re-init, its current kept (as on a packet it cannot open)
			time.Sleep(300 * time.Millisecond)
			drain(a)
			pkt := append(allocBytes(0), (*captured.Load())...)
			a.pc.sessions.handleData(nil, ptr(b.key()), pkt) // a's own packet, back to a as from b
			var got []string
			for done := time.After(time.Second); ; {
				select {
				case m := <-a.heard:
					got = append(got, m)
					continue
				case <-done:
				}
				break
			}
			t.Logf("pq %v, re-init %v: a read, after its own packet came back as from b: %q", pq, reinit, got)
			for _, m := range got {
				if m == "a's own words, to b" {
					t.Errorf("reflection: a read its own message as b's")
				}
			}
		})
	}
}
