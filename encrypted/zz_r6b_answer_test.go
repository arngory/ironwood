package encrypted

// Round-6 reviewer (pq-r6b), d036fb6 (PQConfig.AnswerOnly) and e938161: pins for the survivors of the round-6
// mutants of answer only.

import (
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// d036fb6: answer only -> on puts each classic session, and only those, up for an upgrade later (pqRetry), and sends
// nothing at once; on -> on puts nothing up. Kills D4, D5 (no upgrade), D6 (at once), D7 (on every SetPQ on), D13 (PQ
// sessions too).
func TestR6dBackOnUpgradeLaterOnly(t *testing.T) {
	a := newPQNode(t, pqAnswer)
	a.pc.pq.upgradeRetry = time.Hour
	drop := func([]byte) bool { return true }
	a.tap.Store(&drop)
	c, q := lightPC(t), lightPC(t)
	ck, qk := edOf(c), edOf(q)
	a.pc.sessions.handleData(nil, &ck, classicInitFrom(t, c, a.pc))
	knows(t, a.pc, c) // its ML-KEM key known: an upgrade at once would send a PQ init or a PQInfo
	a.pc.sessions.handleData(nil, &qk, pqInitFrom(t, q, a.pc))
	syncSessions(a)
	if s := sessionOf(a, ck); s == nil || s.pq {
		t.Fatal("setup: no classic session")
	}
	if s := sessionOf(a, qk); s == nil || !s.pq {
		t.Fatal("setup: no PQ session")
	}
	retry := func() (cr, qr bool, n int) {
		phony.Block(&a.pc.sessions, func() {
			cr, qr, n = a.pc.sessions.pqRetry[ck], a.pc.sessions.pqRetry[qk], len(a.pc.sessions.pqRetry)
		})
		return
	}
	if _, _, n := retry(); n != 0 {
		t.Fatalf("setup: %d upgrades waiting in answer only", n)
	}
	inits, infos := a.sent[sessionTypePQInit].Load(), a.sent[sessionTypePQInfo].Load()
	a.pc.SetPQ(pqOn)
	time.Sleep(300 * time.Millisecond)
	syncSessions(a)
	cr, qr, _ := retry()
	if !cr || qr {
		t.Errorf("back on: the classic session's upgrade waiting %v (want true), the PQ session's %v (want false)", cr, qr)
	}
	if di, dn := a.sent[sessionTypePQInit].Load()-inits, a.sent[sessionTypePQInfo].Load()-infos; di != 0 || dn != 0 {
		t.Errorf("back on: %d PQ inits and %d PQInfos at once, want none before upgradeRetry", di, dn)
	}
	// on -> on: nothing more put up
	phony.Block(&a.pc.sessions, func() { clear(a.pc.sessions.pqRetry) })
	a.pc.SetPQ(pqOn)
	syncSessions(a)
	if _, _, n := retry(); n != 0 {
		t.Errorf("on -> on: %d upgrades put up", n)
	}
}

// Answer only, a 0x13 claimed from p with no session (our once-init in reply), then data of ours to p: the once-init
// is promoted to one retried until its ack (the client's choice, measured but not asserted by
// TestR6AnsForgedThenDataRetries). Kills D12 (the gate before the pending check: never promoted in answer only).
func TestR6dAnswerDataPromotesOnce(t *testing.T) {
	n := newPQNode(t, pqAnswer) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	deliverTo(n, k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	var made, once bool
	phony.Block(&n.pc.sessions, func() {
		if q := n.pc.sessions.pqPending[k]; q != nil {
			made, once = true, q.once
		}
	})
	if !made || !once {
		t.Fatalf("setup: once-pending made %v, once %v", made, once)
	}
	n.pc.WriteTo([]byte("x"), types.Addr(k[:]))
	phony.Block(&n.pc.sessions, func() {
		q := n.pc.sessions.pqPending[k]
		once = q != nil && q.once
	})
	if once {
		t.Error("answer only: our data waits, and the once-init in reply is not promoted to a retried one")
	}
}

// pqAckSeqR6: a PQ ack of from's to `to` (not bound to any init of to's), its seq given
func pqAckSeqR6(t *testing.T, from, to *PacketConn, seq uint64) []byte {
	t.Helper()
	toEd := edOf(to)
	own := to.pqOwn()
	key := newPQPeerKey(&toEd, &own.pub, own.seq, own.notAfter)
	cur, _ := newBoxKeys()
	nxt, _ := newBoxKeys()
	secret := newRatchetSecret()
	ack := newPQInit(&cur, &nxt, 0, &secret, from.pq.nextSecretNo())
	ack.seq = seq
	data, err := ack.encrypt(from, sessionTypePQAck, &toEd, key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// R6A-5, the other half: a fresh ack (seq newer than the session's) to a PQ session up, with no PQ init of ours
// pending (the peer's answer to a re-init inside the session), still moves the hold on. Kills F12 (only acks to a
// pending init of ours count).
func TestR6dFreshAckOldSessionHolds(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	clock := testClock(n.pc)
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), false) })
	seq := uint64(time.Now().Unix())
	deliverTo(n, k, pqAckSeqR6(t, p, n.pc, seq))
	s := sessionOf(n, k)
	if s == nil || !s.pq || s.fallback != nil || stickyFor(n.pc, k) == nil {
		t.Fatal("setup: no PQ session from the ack, or not held")
	}
	var pending bool
	phony.Block(&n.pc.sessions, func() { pending = n.pc.sessions.pqPending[k] != nil })
	before := stickyFor(n.pc, k).until
	clock.Store(int64(10 * time.Hour))
	deliverTo(n, k, pqAckSeqR6(t, p, n.pc, seq+1)) // fresh, to the session up, nothing of ours pending
	after := stickyFor(n.pc, k).until
	t.Logf("pending before the fresh ack %v; hold until %d, after it 10 h on %d (+%d s)", pending, before, after, int64(after)-int64(before))
	if pending || after <= before {
		t.Errorf("R6A-5: a fresh ack to the PQ session up (nothing of ours pending %v) did not move the hold on (+%d s)", !pending, int64(after)-int64(before))
	}
}

// e938161: answer only holds no key anew, by an ack either. A PQ init of ours (here started by hand, as a promoted
// once-init or a Required key's would be) and the peer's ack: a PQ session, no classic one beside, the ack fresh and
// to ours, and still no hold. Kills G2 (the guard only for traffic).
func TestR6dAnswerAckNoHold(t *testing.T) {
	n := newPQNode(t, pqAnswer) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&k, n.pc.pq.usableKey(&k), false) })
	deliverTo(n, k, pqAckFrom(t, p, n.pc))
	if s := sessionOf(n, k); s == nil || !s.pq || s.fallback != nil {
		t.Fatal("setup: no PQ session from the ack")
	}
	if stickyFor(n.pc, k) != nil {
		t.Error("answer only: the ack to a PQ init of ours held the peer to PQ")
	}
}
