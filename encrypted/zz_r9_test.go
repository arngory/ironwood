package encrypted

import (
	"testing"
	"time"

	"github.com/Arceliar/phony"
)

// Round 9: a peer whose PQInfos never come (it has no PQ, or they are all lost): after pqAskTries asks, no more until
// its next handshake, no new round every upgradeRetry.
func TestR9AsksStopUnanswered(t *testing.T) {
	t.Parallel()
	// y in answer only starts nothing, and its PQInfos are lost: x lacks its key
	x, y := newPQNode(t, pqOn), newPQNode(t, pqAnswer)
	y.dropType[sessionTypePQInfo].Store(true)
	x.pc.pq.upgradeRetry = 2 * time.Second // a new round would come quickly
	linkPQ(t, x, y)
	if !hears(x, y, "hello", 3*time.Second) || !hears(y, x, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	exhausted := func() (e bool) {
		phony.Block(&x.pc.sessions, func() {
			a := x.pc.sessions.pqAsk[y.key()]
			e = a != nil && a.exhausted
		})
		return
	}
	// 3, 6 and 12 s
	for deadline := time.Now().Add(30 * time.Second); !exhausted(); time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("x's asks not done in 30 s (PQInfos of x %d)", x.sent[sessionTypePQInfo].Load())
		}
	}
	before := x.sent[sessionTypePQInfo].Load()
	time.Sleep(3 * x.pc.pq.upgradeRetry)
	if after := x.sent[sessionTypePQInfo].Load(); after != before {
		t.Errorf("x sent %d PQInfos more after its asks went unanswered", after-before)
	}
}

// Round 9: asks that went unanswered start again at the peer's next handshake. The peer had no PQ (or lost every
// answer), then has it: its new Init sets the asks going, its answer comes, and the session goes PQ.
func TestR9HandshakeAsksAgain(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqAnswer)
	y.dropType[sessionTypePQInfo].Store(true)
	x.pc.pq.upgradeRetry = 2 * time.Second
	linkPQ(t, x, y)
	if !hears(x, y, "hello", 3*time.Second) || !hears(y, x, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	exhausted := func() (e bool) {
		phony.Block(&x.pc.sessions, func() {
			a := x.pc.sessions.pqAsk[y.key()]
			e = a != nil && a.exhausted
		})
		return
	}
	for deadline := time.Now().Add(30 * time.Second); !exhausted(); time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("x's asks not done in 30 s (PQInfos of x %d)", x.sent[sessionTypePQInfo].Load())
		}
	}
	// y answers now, and starts a session again: its Init reaches x
	y.dropType[sessionTypePQInfo].Store(false)
	phony.Block(&y.pc.sessions, func() { y.pc.sessions._put(x.key(), nil) })
	if !hears(y, x, "again", 3*time.Second) {
		t.Fatal("no session after y's new Init")
	}
	waitSessions(t, x, y, "pq", 20*time.Second)
}
