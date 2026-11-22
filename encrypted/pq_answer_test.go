package encrypted

import (
	"crypto/ed25519"
	"testing"
	"time"
)

var pqAnswer = PQConfig{Enabled: true, AnswerOnly: true}

// answerSetup: a in answer only with the lower key, b with PQ on; a classic session between them, a's writes first
func answerSetup(t *testing.T) (a, b *pqNode) {
	a, b = lowerFirst(newPQNode(t, pqOn), newPQNode(t, pqOn))
	a.pc.SetPQ(pqAnswer) // the lower key answers only
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	return
}

// Answer only, a new peer: a starts nothing of PQ itself. With the lower key it is the one an upgrade waits for, so
// the session stays classic: no PQ init of a's, whatever b's PQInfo says.
func TestPQAnswerOnlyStartsNothing(t *testing.T) {
	t.Parallel()
	a, b := answerSetup(t)
	time.Sleep(3 * time.Second)
	if s := session(a, b); s != "classic" {
		t.Errorf("a's session %s, want classic", s)
	}
	if n := a.sent[sessionTypePQInit].Load(); n != 0 {
		t.Errorf("a sent %d PQ inits in answer only", n)
	}
}

// Answer only, a plain classic peer: not one PQ packet of a's.
func TestPQAnswerOnlyClassicPeerNothing(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqAnswer), newPQNode(t, PQConfig{})
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	time.Sleep(time.Second)
	for _, typ := range []byte{sessionTypePQInfo, sessionTypePQInit, sessionTypePQAck, sessionTypePQTraffic} {
		if n := a.sent[typ].Load(); n != 0 {
			t.Errorf("a sent %d packets of type %#x in answer only to a classic peer", n, typ)
		}
	}
}

// Answer only, the peer starts PQ (it has the lower key and PQ on): the session is PQ.
func TestPQAnswerOnlyPeerStarts(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	starter, answerer := lowerFirst(x, y)
	answerer.pc.SetPQ(pqAnswer)
	linkPQ(t, starter, answerer)
	if !hears(starter, answerer, "hello", 3*time.Second) || !hears(answerer, starter, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, starter, answerer, "pq", 10*time.Second)
	if !hears(starter, answerer, "pq", 3*time.Second) || !hears(answerer, starter, "pq back", 3*time.Second) {
		t.Fatal("no traffic on the PQ session")
	}
}

// PQ on, a PQ session up, then answer only: the session stays, nothing lost, no handshake.
func TestPQAnswerOnlyKeepsSession(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	hs := handshakePackets(a, b)
	before := sessionOf(a, b.key())
	a.pc.SetPQ(pqAnswer)
	s, g := streamCount(a, b, "kept", 3*time.Second)
	s2, g2 := streamCount(b, a, "kept back", 3*time.Second)
	if session(a, b) != "pq" || session(b, a) != "pq" || sessionOf(a, b.key()) != before {
		t.Errorf("after answer only: a %s, b %s, a's session replaced %v", session(a, b), session(b, a), sessionOf(a, b.key()) != before)
	}
	if n := handshakePackets(a, b) - hs; n != 0 {
		t.Errorf("%d handshake packets after answer only", n)
	}
	if g < s-1 || g2 < s2-1 {
		t.Errorf("lost: a to b %d of %d, b to a %d of %d", g, s, g2, s2)
	}
}

// on → answer only → on: in answer only the classic session stays classic; back on, it is upgraded (later, as after
// a lost init of ours).
func TestPQAnswerOnlyBackOn(t *testing.T) {
	t.Parallel()
	a, b := answerSetup(t)
	a.pc.pq.upgradeRetry = time.Second
	time.Sleep(2 * time.Second)
	if s := session(a, b); s != "classic" {
		t.Fatalf("in answer only a's session %s, want classic", s)
	}
	a.pc.SetPQ(pqOn)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (session(a, b) != "pq" || session(b, a) != "pq") {
		hears(a, b, "on", 200*time.Millisecond)
	}
	if session(a, b) != "pq" || session(b, a) != "pq" {
		t.Errorf("back on: a %s, b %s, want pq", session(a, b), session(b, a))
	}
}

// Answer only, a key held to PQ (Required): a starts PQ itself, or there would be no session.
func TestPQAnswerOnlyRequiredStarts(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a, b := lowerFirst(x, y)
	bKey := b.key()
	cfg := pqAnswer
	cfg.Required = func(k ed25519.PublicKey) bool { return string(k) == string(bKey[:]) }
	a.pc.SetPQ(cfg)
	b.pc.SetPQ(PQConfig{Enabled: true, AnswerOnly: true}) // b starts nothing either
	linkPQ(t, a, b)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && session(a, b) != "pq" {
		hears(a, b, "required", 300*time.Millisecond)
	}
	if session(a, b) != "pq" {
		t.Errorf("a key held to PQ in answer only: a's session %s, want pq", session(a, b))
	}
	if a.sent[sessionTypePQInit].Load() == 0 {
		t.Error("a sent no PQ init to a key held to PQ")
	}
}

// Answer only holds no key anew (the owner's choice): a peer that starts PQ and writes is not held, and the node
// starts nothing with it after; a hold made before stays as it was, not moved on, and runs out.
func TestPQAnswerOnlyNoNewHold(t *testing.T) {
	t.Parallel()
	x, y := newPQNode(t, pqOn), newPQNode(t, pqOn)
	starter, answerer := lowerFirst(x, y)
	answerer.pc.SetPQ(pqAnswer)
	linkPQ(t, starter, answerer)
	if !hears(starter, answerer, "hello", 3*time.Second) || !hears(answerer, starter, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, starter, answerer, "pq", 10*time.Second)
	keepWriting(starter, answerer, time.Second)
	if sticky(answerer, starter) {
		t.Errorf("answer only held the peer that started PQ")
	}
	if !sticky(starter, answerer) {
		t.Errorf("the PQ-on starter does not hold the answering node")
	}
	sKey := starter.key()
	if answerer.pc.pq.initiates(&sKey) {
		t.Errorf("answer only starts PQ with a peer it does not hold")
	}
}

// A hold made with PQ on is kept in answer only, but PQ traffic moves it on no more.
func TestPQAnswerOnlyOldHoldNotMoved(t *testing.T) {
	t.Parallel()
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	keepWriting(a, b, time.Second)
	bKey := b.key()
	if stickyFor(a.pc, bKey) == nil {
		t.Fatal("setup: a does not hold b")
	}
	clock := testClock(a.pc)
	a.pc.SetPQ(pqAnswer)
	before := stickyFor(a.pc, bKey).until
	clock.Store(int64(time.Hour)) // an hour on: a hold moved on would move by it
	keepWriting(a, b, time.Second)
	k := stickyFor(a.pc, bKey)
	if k == nil {
		t.Fatal("the hold made before answer only went at once")
	}
	if k.until != before {
		t.Errorf("answer only moved the old hold on by %d s", int64(k.until)-int64(before))
	}
}
