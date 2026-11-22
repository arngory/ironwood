package encrypted

import (
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
