package encrypted

import (
	"testing"
	"time"

	"github.com/Arceliar/phony"
)

// R7-1: answer only moves no hold on (PQConfig.AnswerOnly: "nor is a hold moved on: the holds there run out"). A held
// peer's newer ML-KEM key (its daily rotation, a restart; by PQInfo or as the sender of a PQ init) moves it on in
// accept all the same, so a held peer that stays in touch is held for good.
func TestR7AnswerOnlyNewKeyNoMove(t *testing.T) {
	pc := lightPC(t)
	clock := testClock(pc) // before any read
	k := newPeerEd(t)
	now := uint64(pc.pq.now().Unix())
	if ok, _ := pc.pq.accept(&k, ptr2(newPQKeyPub(t)), now, now+uint64(pqKeyValidity/time.Second)); !ok {
		t.Fatal("setup: key not taken")
	}
	pc.pq.markSticky(&k, now+uint64(pqKeyValidity/time.Second), true) // held with PQ on
	before := stickyFor(pc, k).until
	cfg := PQConfig{Enabled: true, AnswerOnly: true}
	pc.pq.cfg.Store(&cfg)
	for day := 1; day <= 3; day++ {
		clock.Store(int64(time.Duration(day) * 24 * time.Hour))
		seq := uint64(pc.pq.now().Unix())
		if ok, _ := pc.pq.accept(&k, ptr2(newPQKeyPub(t)), seq, seq+uint64(pqKeyValidity/time.Second)); !ok {
			t.Fatalf("day %d: the peer's newer key not taken", day)
		}
		if stickyFor(pc, k) == nil {
			if day < 2 {
				t.Fatalf("day %d: the hold went before its end", day)
			}
			return // ran out: as the doc says
		}
		if got := stickyFor(pc, k).until; got != before {
			t.Fatalf("day %d in answer only: the hold moved on by %d s by a newer key of the peer's (held for good while it rotates its keys)", day, int64(got)-int64(before))
		}
	}
}

func ptr2(p pqPub) *pqPub { return &p }

// R7-2: one forged 0x13 per PQ session, claimed from its peer (key numbers no session has: doRecv's default case),
// makes a PQ re-init of ours to each peer: 2529 B sealed (HPKE) out for 53 B in (48x), once in 3 s per key, outside
// the 20/s bucket every other PQ-sized answer to a packet no one signed takes from; and the peer seals a PQ ack back.
// The sessions here are in use (a packet of the peer's opened under each just now): they are in step, and the forged
// packets should get nothing.
func TestR7ForgedReinitAmplify(t *testing.T) {
	n := newPQNode(t, pqOn) // no link: what it sends is counted, not delivered
	const count = 300
	keys := fill(t, n, count)
	for _, k := range keys {
		s := sessionOf(n, k)
		phony.Block(s, func() { s.lastOpened = time.Now() }) // in use: the peer's traffic opens
	}
	inits := n.sent[sessionTypePQInit].Load()
	for _, k := range keys {
		n.pc.sessions.handleData(nil, &k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	}
	phony.Block(&n.pc.sessions, func() {})
	syncSessions(n)
	got := n.sent[sessionTypePQInit].Load() - inits
	t.Logf("%d forged 0x13 of %d B (%d B in) to sessions in use: %d PQ re-inits of %d B out (%d B)", count, pqTrafficOverheadMin,
		count*pqTrafficOverheadMin, got, sessionPQInitSize, got*sessionPQInitSize)
	if got != 0 {
		t.Errorf("R7-2: %d PQ re-inits (%d B) for %d forged packets of %d B to sessions in use", got, got*sessionPQInitSize, count, pqTrafficOverheadMin)
	}
}
