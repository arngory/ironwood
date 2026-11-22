package encrypted

// Round-5 reviewer (pq-r5b) tests: minimal pins for the round-4 survivors P34, P43, P57, P58.

import (
	"bytes"
	"container/list"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Arceliar/phony"
)

// pqAckFrom: a PQ ack of from's to to, sealed to to's ML-KEM key (an answer to whatever PQ init of to's is pending)
func pqAckFrom(t *testing.T, from, to *PacketConn) []byte {
	t.Helper()
	var toEd edPub
	copy(toEd[:], to.publicEd[:])
	own := to.pqOwn()
	key := newPQPeerKey(&toEd, &own.pub, own.seq, own.notAfter)
	cur, _ := newBoxKeys()
	nxt, _ := newBoxKeys()
	secret := newRatchetSecret()
	ack := newPQInit(&cur, &nxt, 0, &secret, from.pq.nextSecretNo())
	data, err := ack.encrypt(from, sessionTypePQAck, &toEd, key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// requireKey: n holds k to PQ from now on (PQConfig.Required)
func requireKey(n *pqNode, k edPub) {
	n.pc.SetPQ(PQConfig{Enabled: true, Required: func(key ed25519.PublicKey) bool { return bytes.Equal(key, k[:]) }})
}

// P34: at the hard limit with every PQ session in use, the ack to a PQ init of ours is refused (_pqRoom), and our
// pending init goes with it: kept, it would be sent again every pqInitRetry for nothing until pendingTimeout.
func TestR5bRefusedAckDropsPending(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1}) // hard limit 65
	drop := func([]byte) bool { return true }
	n.tap.Store(&drop)
	inUse(n, fill(t, n, n.pc.pq.hardMax()))
	x := lightPC(t)
	xk := edOf(x)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._startPQ(&xk, ownAsPeer(t, x), false) })
	deliverTo(n, xk, pqAckFrom(t, x, n.pc))
	var pending bool
	phony.Block(&n.pc.sessions, func() { pending = n.pc.sessions.pqPending[xk] != nil })
	if s := sessionOf(n, xk); s != nil {
		t.Fatalf("a session made at the hard limit with every one in use (pq %v)", s.pq)
	}
	if pending {
		t.Fatal("the ack was refused, and our PQ init stays pending")
	}
}

// P43: the classic-init rule (a newer signed classic init replaces a PQ session) is for confirmed PQ sessions only.
// To one nothing opened under yet, a classic init goes to the classic session beside it, and the PQ one stays.
func TestR5bClassicInitUnconfirmedKeepsPQ(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, pqOn)
	x := lightPC(t)
	xk := edOf(x)
	pq, classic := pqBeside(t, n, x)
	var seq uint64
	phony.Block(&n.pc.sessions, func() { seq = pq.initSeq })
	time.Sleep(1100 * time.Millisecond) // the new init's seq (whole seconds) after the PQ one's, and not in the future
	deliverTo(n, xk, classicInitSeq(t, x, n.pc, seq+1))
	s := sessionOf(n, xk)
	if s != pq {
		t.Fatalf("the unconfirmed PQ session replaced by a classic init (now pq %v)", s != nil && s.pq)
	}
	var fb *sessionInfo
	phony.Block(&n.pc.sessions, func() { fb = pq.fallback })
	if fb != classic {
		t.Fatal("the classic session beside it not the one the init went to")
	}
}

// P57: a PQ session pushed out (here by the unconfirmed limit) of a key held to PQ since it was made gets no classic
// session back: the key may not be classic, as for _expire (P14).
func TestR5bEvictRequiredNoClassic(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, pqOn)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions.unconfirmedMax = 1 })
	x := lightPC(t)
	xk := edOf(x)
	pqBeside(t, n, x)
	requireKey(n, xk)
	y := lightPC(t)
	deliverTo(n, edOf(y), pqInitFrom(t, y, n.pc)) // a second unconfirmed one: x's, the oldest, goes
	if s := sessionOf(n, xk); s != nil {
		t.Fatalf("a key held to PQ has a session after its PQ one was pushed out (pq %v)", s.pq)
	}
}

// P58: a classic session of a key held to PQ since it was made goes on the key's classic traffic (as on our next
// write), not only on ours.
func TestR5bRequiredClassicGoesOnTraffic(t *testing.T) {
	t.Parallel()
	n := newPQNode(t, pqOn)
	drop := func([]byte) bool { return true }
	n.tap.Store(&drop)
	x := lightPC(t)
	xk := edOf(x)
	deliverTo(n, xk, classicInitFrom(t, x, n.pc))
	if s := sessionOf(n, xk); s == nil || s.pq {
		t.Fatal("no classic session")
	}
	requireKey(n, xk)
	deliverTo(n, xk, junk(sessionTypeTraffic, 200))
	if s := sessionOf(n, xk); s != nil {
		t.Fatalf("a key held to PQ keeps a classic session on its classic traffic (pq %v)", s.pq)
	}
}

// Q46: a PQ session nothing opened under, its classic one beside, expires (_expire): the classic one stays, and a
// line in the log says so.
func TestR5bExpireRestoreLogged(t *testing.T) {
	t.Parallel()
	var log logSink
	n := newPQNode(t, PQConfig{Enabled: true, Logf: log.f})
	x := lightPC(t)
	pq, _ := pqBeside(t, n, x)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._expire(pq) })
	logSync(n.pc)
	if log.count("no PQ packet of its opened here") != 1 {
		t.Fatalf("no line for the PQ session gone back to classic: %q", log.all())
	}
}

// P52: data to a key held to PQ (Required), its ML-KEM key known, our PQ init unanswered until pendingTimeout: no
// session, and a line in the log says so.
func TestR5bRequiredUnansweredLogged(t *testing.T) {
	t.Parallel()
	var log logSink
	x := lightPC(t)
	xk := edOf(x)
	n := newPQNode(t, PQConfig{Enabled: true, Logf: log.f, Required: func(k ed25519.PublicKey) bool { return bytes.Equal(k, xk[:]) }})
	drop := func([]byte) bool { return true }
	n.tap.Store(&drop)
	n.pc.pq.pendingTimeout = 500 * time.Millisecond
	knows(t, n.pc, x)
	phony.Block(&n.pc.sessions, func() { n.pc.sessions._bufferAndInit(xk, []byte("data")) })
	time.Sleep(pqInitRetry + time.Second) // the retry timer finds the init past pendingTimeout
	logSync(n.pc)
	if log.count("no session, it must be PQ") != 1 {
		t.Fatalf("no line for the key held to PQ left with no session: %q", log.all())
	}
}

// P6, P7 (round 5): our PQ init in reply to forged PQ traffic claimed from a known key takes a token of the known
// bucket, with no session and with a classic one: with the bucket empty, none goes.
func TestR5bPQTrafficReplyToken(t *testing.T) {
	for _, withClassic := range []bool{false, true} {
		n := newPQNode(t, pqOn) // no link
		p := lightPC(t)
		k := edOf(p)
		if withClassic {
			deliverTo(n, k, classicInitFrom(t, p, n.pc)) // its ML-KEM key unknown yet: no PQ init of ours under way
		}
		knows(t, n.pc, p)
		n.pc.pq.mu.Lock()
		n.pc.pq.knownBucket = pqBucket{at: time.Now().Add(time.Hour)} // empty, for the next hour
		n.pc.pq.mu.Unlock()
		before := n.sent[sessionTypePQInit].Load()
		deliverTo(n, k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
		if got := n.sent[sessionTypePQInit].Load() - before; got != 0 {
			t.Fatalf("classic session %v, the known bucket empty: %d PQ inits in reply to forged PQ traffic", withClassic, got)
		}
	}
}

// R5 (round 5): at the hard limit a session nothing opened under goes first, even one of a key held to PQ, before a
// confirmed one idle past evictIdle of a key that may be classic (PQConfig.SessionMax: "one nothing opened under yet
// first").
func TestR5bEvictUnconfirmedHeldFirst(t *testing.T) {
	n := newPQNode(t, PQConfig{Enabled: true, SessionMax: 1})
	hard := n.pc.pq.hardMax()
	keys := fill(t, n, hard)
	now := n.pc.pq.now()
	set := func(k edPub, confirmed bool, ago time.Duration) {
		phony.Block(&n.pc.sessions, func() {
			s := n.pc.sessions.sessions[k]
			s.confirmed.Store(confirmed)
			s.openedAt.Store(now.Add(-ago).UnixNano())
		})
	}
	for i, k := range keys {
		switch i {
		case 0:
			set(k, true, 30*time.Second) // confirmed, idle past evictIdle, may be classic
		case 1:
			set(k, false, 0) // nothing opened under it, held below
		default:
			set(k, true, 0)
		}
	}
	held := keys[1]
	n.pc.pq.markSticky(&held, uint64(time.Now().Add(time.Hour).Unix()), false)
	p := lightPC(t)
	deliverTo(n, edOf(p), pqInitFrom(t, p, n.pc))
	pqWith := func(k edPub) bool { s := sessionOf(n, k); return s != nil && s.pq }
	if pqWith(held) || !pqWith(keys[0]) {
		t.Fatalf("the unconfirmed session of a held key not first to go: held kept %v, confirmed idle kept %v", pqWith(held), pqWith(keys[0]))
	}
}

// Q27 (round 5): a forged classic init claimed from a key held to PQ, answered by our PQInfo (its ML-KEM key unknown,
// or a session up), takes a token: of the unknown bucket, or of the known one; with it empty, none goes.
func TestR5bHeldClassicInitInfoToken(t *testing.T) {
	for _, known := range []bool{false, true} {
		n := newPQNode(t, pqOn) // no link
		p := lightPC(t)
		k := edOf(p)
		if known {
			deliverTo(n, k, pqInitFrom(t, p, n.pc)) // a PQ session up, its key known
		}
		n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true)
		n.pc.pq.mu.Lock()
		n.pc.pq.knownBucket = pqBucket{at: time.Now().Add(time.Hour)}
		n.pc.pq.unknownBucket = pqBucket{at: time.Now().Add(time.Hour)}
		n.pc.pq.limits = make(map[edPub]*list.Element)
		n.pc.pq.limitsLRU.Init()
		n.pc.pq.mu.Unlock()
		before := n.sent[sessionTypePQInfo].Load() + n.sent[sessionTypePQInit].Load()
		deliverTo(n, k, junk(sessionTypeInit, sessionInitSize))
		if got := n.sent[sessionTypePQInfo].Load() + n.sent[sessionTypePQInit].Load() - before; got != 0 {
			t.Fatalf("key known %v, buckets empty: %d answers to a forged classic init of a held key", known, got)
		}
	}
}

// R3 (round 5): forged PQ traffic of a known key with no session gets a PQ init that stays pending with its keys
// (once): the peer's ack makes a session under them at once, our secret in it.
func TestR5bPQTrafficReplyPending(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	knows(t, n.pc, p)
	deliverTo(n, k, junk(sessionTypePQTraffic, pqTrafficOverheadMin))
	var once bool
	var cur boxPub
	var secret ratchetSecret
	phony.Block(&n.pc.sessions, func() {
		if pd := n.pc.sessions.pqPending[k]; pd != nil {
			once, cur, secret = pd.once, pd.init.current, pd.init.secret
		}
	})
	if !once {
		t.Fatal("no PQ init of ours pending (sent once) in reply to PQ traffic with no session")
	}
	deliverTo(n, k, pqAckFrom(t, p, n.pc))
	s := sessionOf(n, k)
	if s == nil || !s.pq {
		t.Fatal("no PQ session from the ack")
	}
	var ours bool
	var recv boxPub
	phony.Block(s, func() {
		recv = s.recvPub // the pending init's current key, moved on by the ack (_handleUpdate)
		for _, o := range s.own {
			ours = ours || o.secret == secret
		}
	})
	if !ours || recv != cur {
		t.Fatalf("the session from the ack not under our pending init's keys and secret: secret kept %v, keys %v", ours, recv == cur)
	}
}

// R38, R39 (round 5): classic sessions as upstream: a classic init, or ack, of the same second as the last one taken
// is a repeat, whatever its keys (only PQ ones with other keys are new).
func TestR5bClassicSameSecondAsUpstream(t *testing.T) {
	for _, ack := range []bool{false, true} {
		n := newPQNode(t, PQConfig{}) // PQ off: classic, as upstream
		drop := func([]byte) bool { return true }
		n.tap.Store(&drop)
		p := lightPC(t)
		k := edOf(p)
		seq := uint64(time.Now().Unix())
		deliverTo(n, k, classicInitSeq(t, p, n.pc, seq))
		s := sessionOf(n, k)
		if s == nil {
			t.Fatal("no session")
		}
		current := func() (c boxPub) { phony.Block(s, func() { c = s.current }); return }
		before := current()
		data := classicInitSeq(t, p, n.pc, seq) // other keys, the same second
		if ack {
			data[0] = sessionTypeAck // an ack's bytes are an init's, its type apart (sessionAck.encrypt)
		}
		deliverTo(n, k, data)
		if sessionOf(n, k) != s || current() != before {
			t.Fatalf("classic %s of the same second with other keys taken (upstream: a repeat)", map[bool]string{false: "init", true: "ack"}[ack])
		}
	}
}

// R42 (round 5): a forged classic init claimed from a key held to PQ with a PQ session up gets no PQ init (our PQInfo
// at most): the PQ init is for a key with no session.
func TestR5bHeldClassicInitWithSessionNoPQInit(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	p := lightPC(t)
	k := edOf(p)
	deliverTo(n, k, pqInitFrom(t, p, n.pc))
	n.pc.pq.markSticky(&k, p.pqOwn().notAfter, true)
	before := n.sent[sessionTypePQInit].Load()
	deliverTo(n, k, junk(sessionTypeInit, sessionInitSize))
	if got := n.sent[sessionTypePQInit].Load() - before; got != 0 {
		t.Fatalf("a PQ session up: %d PQ inits to a forged classic init of a held key", got)
	}
}

// R45 (round 5): our answer to a signed PQInfo we do not take (out of time), its key with no entry, takes a token of
// the signed bucket (R5-3): with it empty, none goes.
func TestR5bStaleInfoAnswerToken(t *testing.T) {
	n := newPQNode(t, pqOn) // no link
	n.pc.pq.mu.Lock()
	n.pc.pq.signedBucket = pqBucket{at: time.Now().Add(time.Hour)}
	n.pc.pq.mu.Unlock()
	p := lightPC(t)
	k := edOf(p)
	stale := p.newPQOwnKey(uint64(time.Now().Add(-6 * 24 * time.Hour).Unix()))
	deliverTo(n, k, append(allocBytes(0), stale.info...))
	if got := n.sent[sessionTypePQInfo].Load(); got != 0 {
		t.Fatalf("the known bucket empty: %d PQInfos in answer to a stale PQInfo of a key with no entry", got)
	}
}
