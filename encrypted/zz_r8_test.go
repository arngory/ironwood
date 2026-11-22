package encrypted

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arceliar/ironwood/types"
	"github.com/Arceliar/phony"
)

// Round 8 (neko): a node in answer only with the lower key and a client with PQ on, the classic session up before
// any PQ: the client, which waits for the lower key's PQ init, sends its own after awaitStart, and the session is PQ.
// Before, it stayed classic for good: the answer-only node never starts one.
func TestR8AnswerOnlyLowerKeyUpgrades(t *testing.T) {
	t.Parallel()
	a, b := lowerFirst(newPQNode(t, pqAnswer), newPQNode(t, pqOn))
	a.pc.SetPQ(pqAnswer)
	b.pc.SetPQ(pqOn)
	b.pc.pq.awaitStart = time.Second
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	if n := a.sent[sessionTypePQInit].Load(); n != 0 {
		t.Errorf("the answer-only node sent %d PQ inits", n)
	}
	if !hears(a, b, "pq", 3*time.Second) || !hears(b, a, "pq back", 3*time.Second) {
		t.Fatal("no traffic on the PQ session")
	}
}

// Both with PQ on, the higher key's wait short: whether the lower's init or the higher's goes first, one PQ session
// comes up and carries traffic both ways.
func TestR8BothOnShortAwait(t *testing.T) {
	t.Parallel()
	for i := 0; i < 5; i++ {
		lo, hi := lowerFirst(newPQNode(t, pqOn), newPQNode(t, pqOn))
		hi.pc.pq.awaitStart = 10 * time.Millisecond
		linkPQ(t, lo, hi)
		if !hears(lo, hi, "hello", 3*time.Second) || !hears(hi, lo, "hello back", 3*time.Second) {
			t.Fatal("no session")
		}
		waitSessions(t, lo, hi, "pq", 10*time.Second)
		if !hears(lo, hi, "pq", 3*time.Second) || !hears(hi, lo, "pq back", 3*time.Second) {
			t.Fatal("no traffic on the PQ session")
		}
	}
}

// Round 8b: the answer-only node's first PQInfo lost on the way (one packet held for the client while a path is
// found): the client, with a classic session and no key of the node's, asks again, the node answers again, and the
// session is PQ, whichever end has the lower key.
func TestR8bLostAnswerAsksAgain(t *testing.T) {
	t.Parallel()
	for _, clientLower := range []bool{true, false} {
		t.Run(map[bool]string{true: "client lower", false: "client higher"}[clientLower], func(t *testing.T) {
			t.Parallel()
			lo, hi := lowerFirst(newPQNode(t, pqOn), newPQNode(t, pqOn))
			client, node := hi, lo
			if clientLower {
				client, node = lo, hi
			}
			node.pc.SetPQ(pqAnswer)
			var dropped atomic.Bool
			drop := func(data []byte) bool {
				return data[0] == sessionTypePQInfo && dropped.CompareAndSwap(false, true)
			}
			node.tap.Store(&drop)
			linkPQ(t, client, node)
			if !hears(client, node, "hello", 3*time.Second) || !hears(node, client, "hello back", 3*time.Second) {
				t.Fatal("no session")
			}
			waitSessions(t, client, node, "pq", 15*time.Second)
			if !dropped.Load() {
				t.Fatal("the node's PQInfo was not dropped: the test tests nothing")
			}
			if n := node.sent[sessionTypePQInit].Load(); n != 0 {
				t.Errorf("the answer-only node sent %d PQ inits", n)
			}
		})
	}
}

// Round 8b: a node with PQ on answers a key's PQInfos once in pqInfoAnswerEvery (a path slow enough that each answer
// comes after the other's interval cannot have two such ends answer each other for good, P-2); one in answer only, a
// burst of pqInfoAnswerBurst.
func TestR8bAnswerBurstBounded(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		cfg  PQConfig
		want int
	}{{pqOn, 1}, {pqAnswer, pqInfoAnswerBurst}} {
		n := newPQNode(t, c.cfg)
		var k edPub
		k[0] = 1
		got := 0
		for i := 0; i < 10; i++ {
			if n.pc.pq.answerDue(&k) {
				got++
			}
		}
		if got != c.want {
			t.Errorf("answer only %v: %d answers in a row, want %d", c.cfg.AnswerOnly, got, c.want)
		}
	}
}

// Round 8c: the PQ session confirmed at y, not yet at x (y's PQ packets held on the way): x sends by the classic
// session still, and y takes that traffic for pqStaleGrace instead of dropping it. Before, a window of data in
// flight at the switch was lost, and a TCP flow over it stalled on its backoff.
func TestR8cClassicTakenAtTheSwitch(t *testing.T) {
	t.Parallel()
	var x, y *pqNode
	var hold atomic.Bool
	// a classic session first, then the PQ one: where the first packet waited for a session, the PQ one comes up
	// directly with no classic one beside, and the test is set up again
	for try := 0; ; try++ {
		if try == 8 {
			t.Fatal("no classic session first in 8 tries")
		}
		x, y = newPQNode(t, pqOn), newPQNode(t, pqOn)
		hold.Store(true)
		dropPQ := func(data []byte) bool { return hold.Load() && data[0] == sessionTypePQTraffic }
		y.tap.Store(&dropPQ)
		linkPQ(t, x, y)
		if !hears(x, y, "hello", 3*time.Second) {
			continue
		}
		ok := false
		for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if session(y, x) == "pq" && session(x, y) == "pq, unconfirmed" {
				ok = true
				break
			}
			x.pc.WriteTo([]byte("keep"), types.Addr(y.pub))
		}
		if ok {
			break
		}
	}
	// drain what came so far
	for len(y.heard) > 0 {
		<-y.heard
	}
	const n = 100
	got := make(chan int, 1)
	go func() {
		c := 0
		for deadline := time.After(2 * time.Second); ; {
			select {
			case m := <-y.heard:
				if len(m) > 4 && m[:4] == "seq:" {
					c++
				}
			case <-deadline:
				got <- c
				return
			}
		}
	}()
	for i := 0; i < n; i++ {
		x.pc.WriteTo([]byte(fmt.Sprintf("seq:%03d", i)), types.Addr(y.pub))
		time.Sleep(2 * time.Millisecond)
	}
	if c := <-got; c != n {
		t.Fatalf("y took %d of %d packets x sent by the classic session at the switch", c, n)
	}
	hold.Store(false)
	waitSessions(t, x, y, "pq", 10*time.Second)
}

// Round 8d (review): the window of round 8c ends. y has the PQ session confirmed, x not (y's PQ packets held), and x
// keeps sending by the classic session: taken at the switch, refused once pqStaleGrace passed, though x's PQ probes
// go on opening at y all along (an end of the window that each PQ packet moved on would take them).
func TestR8dGraceEnds(t *testing.T) {
	t.Parallel()
	var x, y *pqNode
	var hold atomic.Bool
	for try := 0; ; try++ {
		if try == 8 {
			t.Fatal("no classic session first in 8 tries")
		}
		x, y = newPQNode(t, pqOn), newPQNode(t, pqOn)
		hold.Store(true)
		dropPQ := func(data []byte) bool { return hold.Load() && data[0] == sessionTypePQTraffic }
		y.tap.Store(&dropPQ)
		linkPQ(t, x, y)
		if !hears(x, y, "hello", 3*time.Second) {
			continue
		}
		ok := false
		for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if session(y, x) == "pq" && session(x, y) == "pq, unconfirmed" {
				ok = true
				break
			}
			x.pc.WriteTo([]byte("keep"), types.Addr(y.pub))
		}
		if ok {
			break
		}
	}
	count := func(prefix string, n int, gap time.Duration) int {
		for len(y.heard) > 0 {
			<-y.heard
		}
		got := make(chan int, 1)
		go func() {
			c := 0
			for deadline := time.After(time.Duration(n)*gap + time.Second); ; {
				select {
				case m := <-y.heard:
					if len(m) > len(prefix) && m[:len(prefix)] == prefix {
						c++
					}
				case <-deadline:
					got <- c
					return
				}
			}
		}()
		for i := 0; i < n; i++ {
			x.pc.WriteTo([]byte(fmt.Sprintf("%s%03d", prefix, i)), types.Addr(y.pub))
			time.Sleep(gap)
		}
		return <-got
	}
	if c := count("seq:", 100, 2*time.Millisecond); c != 100 {
		t.Fatalf("y took %d of 100 packets x sent by the classic session at the switch", c)
	}
	// x keeps writing past the window: its PQ probes (one a pqProbeInterval) open at y all along
	for end := time.Now().Add(pqStaleGrace + 500*time.Millisecond); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		x.pc.WriteTo([]byte("keep"), types.Addr(y.pub))
	}
	if session(x, y) != "pq, unconfirmed" {
		t.Fatalf("x's session %s: the test wants x still unconfirmed", session(x, y))
	}
	if late := count("late:", 20, 5*time.Millisecond); late != 0 {
		t.Errorf("y took %d of 20 classic packets past pqStaleGrace", late)
	}
	hold.Store(false)
	waitSessions(t, x, y, "pq", 10*time.Second)
}

// Round 8d (review B1): an ask of ours that _maybeStartPQ follows with no next one (PQ in answer only now) leaves no
// entry behind.
func TestR8dAskEntryGoes(t *testing.T) {
	t.Parallel()
	// y in answer only starts nothing, and its PQInfos are lost: x lacks its key and asks again
	x, y := newPQNode(t, pqOn), newPQNode(t, pqAnswer)
	y.dropType[sessionTypePQInfo].Store(true)
	linkPQ(t, x, y)
	if !hears(x, y, "hello", 3*time.Second) || !hears(y, x, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	asks := func() (n int) {
		phony.Block(&x.pc.sessions, func() { n = len(x.pc.sessions.pqAsk) })
		return
	}
	for deadline := time.Now().Add(10 * time.Second); asks() == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("x asks nothing again of a peer whose key it lacks (sessions x %s, y %s; PQInfos of x %d)",
				session(x, y), session(y, x), x.sent[sessionTypePQInfo].Load())
		}
		x.pc.WriteTo([]byte("keep"), types.Addr(y.pub))
	}
	x.pc.SetPQ(pqAnswer)
	time.Sleep(pqInfoInterval + time.Second)
	if n := asks(); n != 0 {
		t.Fatalf("%d ask entries left once x went to answer only", n)
	}
}

// Round 8d (review N1): a once-init of the higher key's (sent in reply to a packet no one signed) lost on the way,
// before awaitStart: the fallback start sends it again, and the session with the answer-only lower key is PQ.
func TestR8dOnceInitAtAwaitStart(t *testing.T) {
	t.Parallel()
	lo, hi := lowerFirst(newPQNode(t, pqOn), newPQNode(t, pqOn))
	lo.pc.SetPQ(pqAnswer)
	hi.pc.pq.awaitStart = 2 * time.Second
	var dropped atomic.Bool
	dropFirstInit := func(data []byte) bool {
		return data[0] == sessionTypePQInit && dropped.CompareAndSwap(false, true)
	}
	hi.tap.Store(&dropFirstInit)
	linkPQ(t, lo, hi)
	if !hears(lo, hi, "hello", 3*time.Second) || !hears(hi, lo, "hello back", 3*time.Second) {
		t.Fatal("no session")
	}
	for deadline := time.Now().Add(time.Second); hi.pc.pq.usableKey(ptr(lo.key())) == nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("hi has no ML-KEM key of lo's")
		}
	}
	// a packet no one signed, claimed from lo: hi's once-init in reply (lost)
	phony.Block(&hi.pc.sessions, func() {
		hi.pc.sessions.handleData(nil, ptr(lo.key()), junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	})
	var once bool
	phony.Block(&hi.pc.sessions, func() {
		p := hi.pc.sessions.pqPending[lo.key()]
		once = p != nil && p.once
	})
	if !once || !dropped.Load() {
		t.Skipf("no once-init lost before awaitStart (once %v, dropped %v): the case is not set up", once, dropped.Load())
	}
	waitSessions(t, lo, hi, "pq", 10*time.Second)
}
