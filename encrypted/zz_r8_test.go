package encrypted

import (
	"sync/atomic"
	"testing"
	"time"
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
