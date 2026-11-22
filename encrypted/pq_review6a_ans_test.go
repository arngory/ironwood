package encrypted

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// The tests of review pq-r6a for answer only (d036fb6).

func ansPending(n *pqNode, k edPub) (p *pqPending, once bool) {
	phony.Block(&n.pc.sessions, func() {
		if p = n.pc.sessions.pqPending[k]; p != nil {
			once = p.once
		}
	})
	return
}

// Answer only, the gate opened by a replay (R6A-5): p's PQ ack, captured once, replayed with no session and no init of
// ours pending, makes a session and holds p to PQ (markSticky). From then on n starts PQ with p itself (initiates:
// required) and sends p no classic init: a key that may be classic, never PQ-started by n, now refused classic.
func TestR6AnsReplayedAckOpensGate(t *testing.T) {
	n := newPQNode(t, pqAnswer) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	ack := pqAckFrom(t, p, n.pc) // captured on the way (an answer of p's to some init of ours, earlier)
	if n.pc.pq.initiates(&k) {
		t.Fatal("setup: answer only initiates")
	}
	deliverTo(n, k, append(allocBytes(0), ack...))
	held, initiates := stickyFor(n.pc, k) != nil, n.pc.pq.initiates(&k)
	dropSessions(n)
	inits, pqInits := n.sent[sessionTypeInit].Load(), n.sent[sessionTypePQInit].Load()
	n.pc.WriteTo([]byte("x"), types.Addr(k[:]))
	time.Sleep(100 * time.Millisecond)
	t.Logf("after a replayed PQ ack: held %v, initiates %v; n's write: classic inits %d, PQ inits %d",
		held, initiates, n.sent[sessionTypeInit].Load()-inits, n.sent[sessionTypePQInit].Load()-pqInits)
	if held || initiates {
		t.Errorf("R6A-5 in answer only: a replayed ack held p to PQ, and n starts PQ with it")
	}
}

// Answer only, a forged 0x13 then our own data: the once-pending it made is resent until its ack (the client keeps
// this: "once-pending resends when our data waits"), so n starts a retried PQ init to a key it never held, on one
// packet no one signed. Measured: how many PQ inits n sends to an unreachable p in 7 s.
func TestR6AnsForgedThenDataRetries(t *testing.T) {
	n := newPQNode(t, pqAnswer) // no link: p never answers
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	deliverTo(n, k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	_, once := ansPending(n, k)
	n.pc.WriteTo([]byte("x"), types.Addr(k[:]))
	time.Sleep(7 * time.Second)
	t.Logf("once-pending %v; PQ inits of n in 7 s: %d (1 for the forged packet alone)", once, n.sent[sessionTypePQInit].Load())
}

// Answer only → on, many classic sessions: upgradeClassic schedules one upgrade each, spread over pqUpgradeRetry
// (A-1: all from the same moment they fired together, a burst of PQ inits sealed in the manager's actor). 400 classic
// sessions, upgradeRetry 1 s: the sends must spread over more than half of it.
func TestR6AnsBackOnBurst(t *testing.T) {
	const m = 400
	n := newPQNode(t, pqAnswer)
	n.pc.pq.upgradeRetry = time.Second
	var mu sync.Mutex
	var at []time.Duration
	var start time.Time
	tap := func(data []byte) bool {
		if data[0] == sessionTypePQInit || data[0] == sessionTypePQInfo {
			mu.Lock()
			at = append(at, time.Since(start))
			mu.Unlock()
		}
		return true // dropped: no network
	}
	n.tap.Store(&tap)
	n.pc.pq.mu.Lock()
	n.pc.pq.peersMax = 2 * m
	n.pc.pq.mu.Unlock()
	for i := 0; i < m; i++ {
		q := lightPC(t)
		knows(t, n.pc, q)
		deliverTo(n, edOf(q), classicInitFrom(t, q, n.pc))
	}
	var classic, timers int
	start = time.Now()
	n.pc.SetPQ(pqOn)
	phony.Block(&n.pc.sessions, func() {
		for _, s := range n.pc.sessions.sessions {
			if !s.pq {
				classic++
			}
		}
		timers = len(n.pc.sessions.pqRetry)
	})
	time.Sleep(2500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	sort.Slice(at, func(i, j int) bool { return at[i] < at[j] })
	if len(at) == 0 {
		t.Fatalf("%d classic sessions, %d upgrades scheduled, nothing sent", classic, timers)
	}
	spread := at[len(at)-1] - at[0]
	t.Logf("%d classic sessions, %d upgrades scheduled; %d PQ inits/PQInfos sent, first at %v, last at %v (spread %v)",
		classic, timers, len(at), at[0].Round(time.Millisecond), at[len(at)-1].Round(time.Millisecond), spread.Round(time.Millisecond))
	if spread < n.pc.pq.upgradeRetry/2 {
		t.Errorf("A-1: the upgrades back on went out within %v, not spread over upgradeRetry %v", spread, n.pc.pq.upgradeRetry)
	}
}

// The R6A-2 fix and the gate: in answer only a once-pending beside a classic session stays once on a trigger of ours
// (a signed classic handshake here), or a forged 0x13 would have n retry a PQ init it may not start.
func TestR6AnsOnceNotPromoted(t *testing.T) {
	n := newPQNode(t, pqAnswer) // no link
	p := lightPC(t)
	k := edOf(p)
	deliverTo(n, k, classicInitFrom(t, p, n.pc)) // a classic session
	knows(t, n.pc, p)
	deliverTo(n, k, junk(sessionTypePQTraffic, pqTrafficOverheadMin)) // forged: our once-init in reply
	time.Sleep(1100 * time.Millisecond)
	deliverTo(n, k, classicInitFrom(t, p, n.pc)) // p's re-init: _maybeStartPQ
	_, once := ansPending(n, k)
	time.Sleep(4500 * time.Millisecond)
	t.Logf("still once %v; PQ inits of n in 5.6 s: %d", once, n.sent[sessionTypePQInit].Load())
	if !once || n.sent[sessionTypePQInit].Load() != 1 {
		t.Errorf("answer only: the once-init promoted on a classic handshake (%d PQ inits)", n.sent[sessionTypePQInit].Load())
	}
}

// Pre-existing (not of answer only): _handlePQInfo answers every PQInfo with ours, at most once in pqInfoInterval
// (3 s) per key. With a one-way delay d of 1.5 s or more, each end's answer comes after its own limit ran out, and
// the two ends answer each other's PQInfos for good: 1.3 KB each way every 2d. Two nodes with no link, PQInfos
// relayed by hand after d; one PQInfo of a's starts it.
func TestR6PQInfoPingPongSlowPath(t *testing.T) {
	for _, d := range []time.Duration{500 * time.Millisecond, 1600 * time.Millisecond} {
		d := d
		t.Run(d.String(), func(t *testing.T) {
			t.Parallel()
			a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
			relay := func(from, to *pqNode) {
				tap := func(data []byte) bool {
					if data[0] == sessionTypePQInfo {
						c := append(allocBytes(0), data...)
						time.AfterFunc(d, func() { to.pc.sessions.handleData(nil, ptr(from.key()), c) })
					}
					return true
				}
				from.tap.Store(&tap)
			}
			relay(a, b)
			relay(b, a)
			phony.Block(&a.pc.sessions, func() { a.pc.sessions.sendPQInfo(ptr(b.key())) })
			time.Sleep(12 * time.Second)
			t.Logf("one-way delay %v: PQInfos in 12 s, a %d, b %d", d, a.sent[sessionTypePQInfo].Load(), b.sent[sessionTypePQInfo].Load())
			if a.sent[sessionTypePQInfo].Load() > 2 {
				t.Errorf("PQInfo ping-pong with a one-way delay of %v", d)
			}
		})
	}
}
