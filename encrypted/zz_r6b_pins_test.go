package encrypted

// Round-6 reviewer (pq-r6b): pins for the survivors of the round-6 mutants (R5-2's seqCurrents). Needs only the
// committed helpers of 8fdb8ba.

import (
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// keySeqOf: the session's localKeySeq (moves on each init or ack taken)
func keySeqOf(s *sessionInfo) (ls uint64) {
	phony.Block(s, func() { ls = s.localKeySeq })
	return
}

// R5-2: the inits of one seq with other keys are taken once each, up to 8; past 8 any is taken for a repeat (the
// bound of seqCurrents). Kills S6 (no cap), S8 (past the cap taken as new), S11 (cap 2).
func TestR6bSameSeqCap(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	seq := uint64(time.Now().Unix())
	var inits [][]byte
	for i := 0; i < 10; i++ {
		inits = append(inits, pqInitSeq(t, p, n.pc, seq))
	}
	deliverTo(n, k, append(allocBytes(0), inits[0]...))
	s := sessionOf(n, k)
	if s == nil || !s.pq {
		t.Fatal("no PQ session")
	}
	phony.Block(s, func() { s.rx = 1 }) // traffic came: no re-ack for a repeat
	taken := 0
	for i := 1; i < 10; i++ {
		before := keySeqOf(s)
		deliverTo(n, k, append(allocBytes(0), inits[i]...))
		if keySeqOf(s) != before {
			taken++
		}
	}
	var held int
	phony.Block(s, func() { held = len(s.seqCurrents) })
	t.Logf("9 more inits of one seq, other keys each: %d taken; %d currents held", taken, held)
	if taken != 7 || held != 8 {
		t.Fatalf("R5-2: of 9 more same-seq inits with other keys %d were taken (want 7: 8 in all, then a repeat), %d currents held", taken, held)
	}
}

// R5-2: the currents of a seq are forgotten on the next seq: a session re-inited 8 times (8 seconds) still takes a
// same-second new init of the peer's. Kills S4 (seqCurrents not reset on a new seq).
func TestR6bSameSeqResetOnNewSeq(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	base := uint64(time.Now().Unix()) - 20
	deliverTo(n, k, pqInitSeq(t, p, n.pc, base))
	s := sessionOf(n, k)
	if s == nil || !s.pq {
		t.Fatal("no PQ session")
	}
	phony.Block(s, func() { s.rx = 1 })
	for i := uint64(1); i < 8; i++ {
		before := keySeqOf(s)
		deliverTo(n, k, pqInitSeq(t, p, n.pc, base+i))
		if keySeqOf(s) == before {
			t.Fatalf("the re-init of seq +%d not taken", i)
		}
	}
	before := keySeqOf(s)
	deliverTo(n, k, pqInitSeq(t, p, n.pc, base+7)) // the same second as the last, other keys: new
	if keySeqOf(s) == before {
		t.Fatal("R5-2: after 8 re-inits of 8 seqs, a same-second init with other keys was taken for a repeat")
	}
}

// N-R5-3 on the _restoreClassic path: an unconfirmed PQ session with a classic one beside it that times out leaves
// pqUnconfirmed when the classic one takes its place (the entry would hold the PQ session, some 12 KB, until the lazy
// prune at unconfirmedMax). Kills P12 (the entry kept when a session replaces the PQ one) and S1.
func TestR6bRestoreClassicLeavesUnconfirmed(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	peer := lightPC(t)
	k := edOf(peer)
	pq, classic := pqBeside(t, n, peer)
	var before bool
	phony.Block(&n.pc.sessions, func() { before = n.pc.sessions.pqUnconfirmed[k] == pq })
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._expire(pq) })
	var now *sessionInfo
	var entry bool
	phony.Block(&n.pc.sessions, func() {
		now = n.pc.sessions.sessions[k]
		_, entry = n.pc.sessions.pqUnconfirmed[k]
	})
	if !before || now != classic {
		t.Fatalf("setup: counted unconfirmed %v, classic restored %v", before, now == classic)
	}
	if entry {
		t.Fatal("N-R5-3: the PQ session the classic one replaced is still in pqUnconfirmed")
	}
}

// R5-4: the in-use skip of the room scan reads pq.now, the clock openedAt is stored by (a node whose pq.now runs a
// minute ahead: every PQ session idle 30 s by it is evictable). Kills S20 (the skip by the wall clock). In production
// pq.now is time.Now, so S20 is equivalent there; this pins the clock's consistency for the tests that move it.
func TestR6bScanSkipByPQClock(t *testing.T) {
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 64})
	testClock(n.pc).Store(int64(time.Minute))
	hard := n.pc.pq.hardMax()
	n.pc.sessions.unconfirmedMax = hard + 10
	keys := fill(t, n, hard)
	phony.Block(&n.pc.sessions, func() {
		at := n.pc.pq.now().Add(-30 * time.Second).UnixNano()
		for _, k := range keys {
			if s := n.pc.sessions.sessions[k]; s != nil && s.pq {
				s.confirmed.Store(true)
				s.openedAt.Store(at)
			}
		}
	})
	p := lightPC(t)
	k := edOf(p)
	deliverTo(n, k, pqInitFrom(t, p, n.pc))
	if s := sessionOf(n, k); s == nil || !s.pq {
		t.Fatalf("at the hard limit (%d), every PQ session idle 30 s by pq.now: no room made for a new one", hard)
	}
}

// R5-3 moved signed asks of keys with no entry to the signed bucket; TestPQOwnDataNoToken empties only the known and
// unknown ones, so a PQInfo for our own data that took a token (askSigned) passed it (R25 survived at 8fdb8ba). With
// all three empty, our data waiting still gets its PQInfo out. Kills R25.
func TestR6bOwnDataNoTokenAllBuckets(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	n.pc.pq.mu.Lock()
	empty := pqBucket{at: time.Now().Add(time.Hour)}
	n.pc.pq.knownBucket, n.pc.pq.unknownBucket, n.pc.pq.signedBucket = empty, empty, empty
	n.pc.pq.mu.Unlock()
	p := lightPC(t)
	n.pc.WriteTo([]byte("data"), types.Addr(p.publicEd[:]))
	phony.Block(&n.pc.sessions, func() {})
	if got := n.sent[sessionTypePQInfo].Load(); got != 1 {
		t.Fatalf("data waiting, all three buckets empty: %d PQInfos, want 1", got)
	}
}
