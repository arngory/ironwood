package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/network"
	"github.com/Arceliar/ironwood/types"
)

// The tests of the review of the PQ sessions (S1-S9).

// lowerFirst: the two nodes, the one with the lower key first (its init goes on when two cross)
func lowerFirst(x, y *pqNode) (*pqNode, *pqNode) {
	if bytes.Compare(x.pub, y.pub) < 0 {
		return x, y
	}
	return y, x
}

// requiredBoth: two nodes, each holding the other's key to PQ
func requiredBoth(t *testing.T, logf func(string, ...any)) (*pqNode, *pqNode) {
	var x, y *pqNode
	req := func(k ed25519.PublicKey) bool { return bytes.Equal(k, x.pub) || bytes.Equal(k, y.pub) }
	cfg := PQConfig{Enabled: true, Required: req, Logf: logf}
	x, y = newPQNode(t, cfg), newPQNode(t, cfg)
	return x, y
}

func syncSessions(n *pqNode) {
	var infos []*sessionInfo
	phony.Block(&n.pc.sessions, func() {
		for _, s := range n.pc.sessions.sessions {
			infos = append(infos, s)
		}
	})
	for _, s := range infos {
		phony.Block(s, func() {})
	}
}

// pqInitFrom: a PQ init of from's to to, sealed to to's ML-KEM key
func pqInitFrom(t *testing.T, from, to *PacketConn) []byte {
	t.Helper()
	var toEd edPub
	copy(toEd[:], to.publicEd[:])
	own := to.pqOwn()
	key := newPQPeerKey(&toEd, &own.pub, own.seq, own.notAfter)
	cur, _ := newBoxKeys()
	nxt, _ := newBoxKeys()
	secret := newRatchetSecret()
	init := newPQInit(&cur, &nxt, 0, &secret, from.pq.nextSecretNo())
	data, err := init.encrypt(from, sessionTypePQInit, &toEd, key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// S1: two PQ inits cross, and the lower key's is sealed to an ML-KEM key of its peer older than the one the peer's
// init came with: it is sealed again to that one at once, not after the init expires (60 s).
func TestPQCrossedInitsStaleKey(t *testing.T) {
	a, b := lowerFirst(requiredBoth(t, nil))
	// no PQInfo either way: the keys travel in the inits alone
	a.dropType[sessionTypePQInfo].Store(true)
	b.dropType[sessionTypePQInfo].Store(true)
	aKey, bKey := a.key(), b.key()
	aOwn, bOwn := a.pc.pqOwn(), b.pc.pqOwn()
	b.pc.pq.accept(&aKey, &aOwn.pub, aOwn.seq, aOwn.notAfter)
	stale := newPQKeyPub(t)
	staleSeq := bOwn.seq - 100
	if ok, _ := a.pc.pq.accept(&bKey, &stale, staleSeq, staleSeq+uint64(pqKeyValidity/time.Second)); !ok {
		t.Fatal("the stale key not taken")
	}
	// B's init held back until A's is under way, so that the two cross at A
	b.dropType[sessionTypePQInit].Store(true)
	linkPQ(t, a, b)
	start := time.Now()
	a.pc.WriteTo([]byte("first of A"), types.Addr(b.pub))
	b.pc.WriteTo([]byte("first of B"), types.Addr(a.pub))
	time.Sleep(300 * time.Millisecond)
	b.dropType[sessionTypePQInit].Store(false)
	if !hears(a, b, "after the crossing", 10*time.Second) {
		t.Fatalf("nothing over the crossed inits in 10 s: A %s, B %s", session(a, b), session(b, a))
	}
	t.Logf("the first packet after %v", time.Since(start).Round(10*time.Millisecond))
	if !hears(b, a, "and back", 3*time.Second) {
		t.Fatal("nothing back")
	}
	if session(a, b) != "pq" || session(b, a) != "pq" {
		t.Fatalf("sessions: A %s, B %s", session(a, b), session(b, a))
	}
}

// S2: the PQ acks are lost (their type is in the clear), past the time the init waiting for one is given up. The end
// that answered has a PQ session, the other the classic one: traffic goes by the classic session kept beside the PQ
// one all the while, both ways. Once the acks go through, the sessions are PQ.
func TestPQAckLostUntilExpiry(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	for _, n := range []*pqNode{a, b} {
		n.pc.pq.pendingTimeout, n.pc.pq.upgradeRetry = 3*time.Second, 2*time.Second
		n.dropType[sessionTypePQAck].Store(true)
	}
	linkPQ(t, a, b)
	counts := func(n *pqNode) string {
		return fmt.Sprintf("init %d ack %d info %d pqinit %d pqack %d pq %d", n.sent[sessionTypeInit].Load(), n.sent[sessionTypeAck].Load(),
			n.sent[sessionTypePQInfo].Load(), n.sent[sessionTypePQInit].Load(), n.sent[sessionTypePQAck].Load(), n.sent[sessionTypePQTraffic].Load())
	}
	for i, deadline := 0, time.Now().Add(6*time.Second); time.Now().Before(deadline); i++ {
		if !hears(a, b, fmt.Sprint("A to B ", i), 2*time.Second) {
			t.Fatalf("A to B stopped while PQ acks are lost (%d): A %s, B %s; A sent %s; B sent %s", i, session(a, b), session(b, a), counts(a), counts(b))
		}
		if !hears(b, a, fmt.Sprint("B to A ", i), 2*time.Second) {
			t.Fatalf("B to A stopped while PQ acks are lost (%d): A %s, B %s; A sent %s; B sent %s", i, session(a, b), session(b, a), counts(a), counts(b))
		}
	}
	t.Logf("while acks are lost: A %s, B %s", session(a, b), session(b, a))
	if a.sent[sessionTypePQAck].Load()+b.sent[sessionTypePQAck].Load() == 0 {
		t.Fatal("no PQ ack was sent: the upgrade the test is for did not start")
	}
	if a.sent[sessionTypePQTraffic].Load()+b.sent[sessionTypePQTraffic].Load() == 0 {
		t.Fatal("no probe went beside the classic traffic")
	}
	a.dropType[sessionTypePQAck].Store(false)
	b.dropType[sessionTypePQAck].Store(false)
	waitSessions(t, a, b, "pq", 15*time.Second)
	for !hears(a, b, "settled", time.Second) {
	}
	if !hears(a, b, "A to B over PQ", 3*time.Second) || !hears(b, a, "B to A over PQ", 3*time.Second) {
		t.Fatal("no traffic over the PQ sessions")
	}
	if a.empty.Load()+b.empty.Load() != 0 {
		t.Fatalf("probes read as messages: %d at A, %d at B", a.empty.Load(), b.empty.Load())
	}
}

// S2: a link that drops PQ traffic (0x13) and carries the rest: for a key that may be classic, traffic goes on by
// the classic session, and the PQ one gives way to it once nothing of it opened in the time an init is waited for.
func TestPQTrafficDropped(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	for _, n := range []*pqNode{a, b} {
		n.pc.pq.pendingTimeout = 3 * time.Second
		n.dropType[sessionTypePQTraffic].Store(true)
		n.dropType[sessionTypePQAck].Store(true) // no verified ack either: a verified ack holds the key to PQ
	}
	linkPQ(t, a, b)
	for i, deadline := 0, time.Now().Add(8*time.Second); time.Now().Before(deadline); i++ {
		if !hears(a, b, fmt.Sprint("A to B ", i), 2*time.Second) || !hears(b, a, fmt.Sprint("B to A ", i), 2*time.Second) {
			t.Fatalf("traffic stopped while PQ traffic is dropped: A %s, B %s", session(a, b), session(b, a))
		}
	}
	if session(a, b) != "classic" && session(b, a) != "classic" {
		t.Fatalf("no end back to classic: A %s, B %s", session(a, b), session(b, a))
	}
}

// S3: packets no one signed make no entry in the table of keys, packets too short for their type get no answer, and
// the PQInfos to keys with no entry come from one bucket for all of them.
func TestPQUnauthenticated(t *testing.T) {
	n := newPQNode(t, PQConfig{Enabled: true, Required: func(ed25519.PublicKey) bool { return true }})
	short := [][]byte{{sessionTypeTraffic}, {sessionTypePQTraffic}, {sessionTypeInit}, {sessionTypeAck}, {sessionTypePQInit}}
	pqTraffic := make([]byte, pqTrafficOverheadMin)
	pqTraffic[0] = sessionTypePQTraffic
	start := time.Now()
	for i := 0; i < 300; i++ {
		fake := newPeerEd(t)
		for _, data := range short {
			n.pc.sessions.handleData(nil, &fake, append(allocBytes(0), data...))
		}
		other := newPeerEd(t)
		n.pc.sessions.handleData(nil, &other, append(allocBytes(0), pqTraffic...))
	}
	phony.Block(&n.pc.sessions, func() {})
	elapsed := time.Since(start)
	n.pc.pq.mu.Lock()
	entries := len(n.pc.pq.peers)
	n.pc.pq.mu.Unlock()
	if entries != 0 {
		t.Fatalf("%d entries in the table of keys from packets no one signed", entries)
	}
	if inits := n.sent[sessionTypeInit].Load() + n.sent[sessionTypePQInit].Load(); inits != 0 {
		t.Fatalf("%d inits in answer to packets too short or from keys with no ML-KEM key here", inits)
	}
	most := int64(pqUnsolicitedRate*(1+elapsed.Seconds())) + 1
	if infos := n.sent[sessionTypePQInfo].Load(); infos > most {
		t.Fatalf("%d PQInfos to unknown keys in %v, the bucket allows %d", infos, elapsed, most)
	} else {
		t.Logf("%d PQInfos to 300 unknown keys in %v (300 short packets of each type unanswered)", infos, elapsed.Round(time.Millisecond))
	}
}

// S4: an init repeated is answered at most once in half the sender's retry, with the bytes of the first ack.
func TestPQRepeatInitLimited(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn) // no link: what B sends is only counted
	aKey := a.key()
	data := pqInitFrom(t, a.pc, b.pc)
	var mu sync.Mutex
	var acks [][]byte
	tap := func(d []byte) bool {
		if d[0] == sessionTypePQAck {
			mu.Lock()
			acks = append(acks, append([]byte(nil), d...))
			mu.Unlock()
		}
		return false
	}
	b.tap.Store(&tap)
	repeat := func(times int) int {
		for i := 0; i < times; i++ {
			b.pc.sessions.handleData(nil, &aKey, append(allocBytes(0), data...))
		}
		phony.Block(&b.pc.sessions, func() {})
		syncSessions(b)
		mu.Lock()
		defer mu.Unlock()
		return len(acks)
	}
	if got := repeat(50); got != 1 {
		t.Fatalf("an init and 49 repeats at once: %d acks, want 1", got)
	}
	time.Sleep(pqInitRetry/2 + 100*time.Millisecond)
	if got := repeat(50); got != 2 {
		t.Fatalf("50 more after %v: %d acks in all, want 2", pqInitRetry/2, got)
	}
	if !bytes.Equal(acks[0], acks[1]) {
		t.Fatal("the repeat was answered with an ack sealed anew")
	}
}

// S6: PQ turned off drops the PQ sessions: no 0x13 goes out after it, and the next packet starts a classic session.
func TestPQOffDropsSessions(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, PQConfig{Enabled: true})
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	a.pc.SetPQ(PQConfig{})
	if session(a, b) != "none" {
		t.Fatalf("A's session with B after PQ off: %s", session(a, b))
	}
	sent := a.sent[sessionTypePQTraffic].Load()
	for i := 0; i < 10; i++ {
		a.pc.WriteTo([]byte("after"), types.Addr(b.pub))
	}
	time.Sleep(500 * time.Millisecond)
	if a.sent[sessionTypePQTraffic].Load() != sent {
		t.Fatal("PQ traffic went out after PQ was turned off")
	}
	if a.sent[sessionTypeInit].Load() == 0 {
		t.Fatal("no classic init after PQ was turned off")
	}
}

// S7: past the most sticky keys, the least recently marked one with a handshake alone goes, with a line in the log;
// one with traffic stays.
func TestPQStickyEviction(t *testing.T) {
	pc := newBarePC(t)
	var logged []string
	cfg := pqOn
	cfg.Logf = func(f string, args ...any) { logged = append(logged, f) }
	pc.SetPQ(cfg)
	pc.pq.stickyMax = 3
	k1, k2, k3, k4 := newPeerEd(t), newPeerEd(t), newPeerEd(t), newPeerEd(t)
	pc.pq.markSticky(&k1, true)
	pc.pq.markSticky(&k2, false)
	pc.pq.markSticky(&k3, false)
	pc.pq.markSticky(&k4, false)
	if !pc.pq.required(&k1) || pc.pq.required(&k2) || !pc.pq.required(&k3) || !pc.pq.required(&k4) {
		t.Fatalf("held to PQ: k1 (traffic) %v, k2 (oldest handshake) %v, k3 %v, k4 %v",
			pc.pq.required(&k1), pc.pq.required(&k2), pc.pq.required(&k3), pc.pq.required(&k4))
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "no longer held") {
		t.Fatalf("log: %q", logged)
	}
}

// S8: the PQ sessions no traffic opened under yet are held to a limit; past it the oldest goes.
func TestPQUnconfirmedLimit(t *testing.T) {
	b := newPQNode(t, pqOn)
	phony.Block(&b.pc.sessions, func() { b.pc.sessions.unconfirmedMax = 2 })
	var senders []*PacketConn
	for i := 0; i < 3; i++ {
		a := newBarePC(t)
		a.SetPQ(pqOn)
		senders = append(senders, a)
		var aKey edPub
		copy(aKey[:], a.publicEd[:])
		b.pc.sessions.handleData(nil, &aKey, pqInitFrom(t, a, b.pc))
		phony.Block(&b.pc.sessions, func() {})
		time.Sleep(10 * time.Millisecond)
	}
	var have []bool
	phony.Block(&b.pc.sessions, func() {
		for _, a := range senders {
			var k edPub
			copy(k[:], a.publicEd[:])
			have = append(have, b.pc.sessions.sessions[k] != nil)
		}
	})
	if have[0] || !have[1] || !have[2] {
		t.Fatalf("sessions of the three senders, oldest first: %v; want the oldest gone", have)
	}
}

// S9: a PQInfo with its signature or its key changed, signed without its context, or taken as another key's, does
// not decode.
func TestPQInfoForged(t *testing.T) {
	a, c := newBarePC(t), newBarePC(t)
	a.SetPQ(pqOn)
	var aKey, cKey edPub
	copy(aKey[:], a.publicEd[:])
	copy(cKey[:], c.publicEd[:])
	info := a.pqOwn().info
	var pq sessionPQInfo
	if !pq.decode(&aKey, info, a.groupAuth) {
		t.Fatal("a real PQInfo did not decode")
	}
	for _, at := range []int{1, 1 + pqPubSize, 1 + pqPubSize + 8, len(info) - 1} {
		bad := append([]byte(nil), info...)
		bad[at] ^= 1
		if pq.decode(&aKey, bad, a.groupAuth) {
			t.Fatalf("a PQInfo with byte %d changed decoded", at)
		}
	}
	if pq.decode(&cKey, info, a.groupAuth) {
		t.Fatal("A's PQInfo decoded as C's")
	}
	// the same fields signed without the context (as an init's signature would be, over other bytes)
	own := a.pqOwn()
	fields := (&sessionPQInfo{pub: own.pub, seq: own.seq, notAfter: own.notAfter}).sigBytes()[len(pqInfoSigCtx):]
	sig := edSign(fields, &a.secretEd, a.groupAuth.preimage())
	noCtx := append(append([]byte(nil), info[:len(info)-edSigSize]...), sig[:]...)
	if pq.decode(&aKey, noCtx, a.groupAuth) {
		t.Fatal("a PQInfo signed without its context decoded")
	}
}

// S9: a node restarted with its clock behind: its peer holds a key of it numbered higher than its own, and its
// inits under that one go unanswered. After pqRollbackTries, the lower-numbered key it announced is taken.
func TestPQRollbackTaken(t *testing.T) {
	var mu sync.Mutex
	var logged []string
	logf := func(f string, args ...any) { mu.Lock(); logged = append(logged, f); mu.Unlock() }
	a, b := requiredBoth(t, logf)
	aKey := a.key()
	aOwn := a.pc.pqOwn()
	ahead := newPQKeyPub(t)
	if ok, _ := b.pc.pq.accept(&aKey, &ahead, aOwn.seq+100, aOwn.seq+100+uint64(pqKeyValidity/time.Second)); !ok {
		t.Fatal("the key ahead not taken")
	}
	linkPQ(t, a, b)
	start := time.Now()
	if !hears(b, a, "after the rollback", 20*time.Second) {
		t.Fatalf("nothing in 20 s: B %s, A %s", session(b, a), session(a, b))
	}
	t.Logf("the first packet after %v", time.Since(start).Round(10*time.Millisecond))
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, line := range logged {
		found = found || strings.Contains(line, "a lower one, taken")
	}
	if !found {
		t.Fatalf("no line of the rollback in the log: %q", logged)
	}
}

// S9: the epoch byte and the ratchet secret take part in a PQ packet: the epoch changed, or the receiver's secret,
// the packet does not open; the same packet unchanged, to the secret as it was, does.
func TestPQTrafficTampered(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	for !hears(a, b, "settled", time.Second) {
	}
	captured := make(chan []byte, 2)
	tap := func(d []byte) bool {
		if d[0] != sessionTypePQTraffic {
			return false
		}
		select {
		case captured <- append([]byte(nil), d...):
		default:
		}
		return true
	}
	a.tap.Store(&tap)
	a.pc.WriteTo([]byte("one"), types.Addr(b.pub))
	a.pc.WriteTo([]byte("two"), types.Addr(b.pub))
	one, two := <-captured, <-captured
	a.tap.Store(nil)
	// no re-init of B's on a failure: it would change the keys under the packets held back
	b.dropType[sessionTypePQInit].Store(true)
	aKey := a.key()
	deliver := func(data []byte) bool {
		b.pc.sessions.handleData(nil, &aKey, append(allocBytes(0), data...))
		select {
		case <-b.heard:
			return true
		case <-time.After(300 * time.Millisecond):
			return false
		}
	}
	epochAt := 1
	for i := 0; i < 3; i++ {
		_, n := binary.Uvarint(one[epochAt:])
		epochAt += n
	}
	bad := append([]byte(nil), one...)
	bad[epochAt] ^= 0x55
	if deliver(bad) {
		t.Fatal("a packet with its epoch changed was delivered")
	}
	if !deliver(one) {
		t.Fatal("the packet unchanged was not delivered")
	}
	var info *sessionInfo
	phony.Block(&b.pc.sessions, func() { info = b.pc.sessions.sessions[aKey] })
	flip := func() {
		phony.Block(info, func() {
			for i := range info.own {
				info.own[i].secret[0] ^= 1
				info.own[i].gen = 0 // the keys made from it go
			}
		})
	}
	flip()
	if deliver(two) {
		t.Fatal("a packet opened under another secret of the receiver's")
	}
	flip()
	if !deliver(two) {
		t.Fatal("the packet did not open under the secret as it was")
	}
}

// S9: a message of MTU() bytes goes through a PQ session whole, with the peers' message size of Yggdrasil.
func TestPQMessageOfMTU(t *testing.T) {
	size := network.WithPeerMaxMessageSize(65535)
	a, b := newPQNode(t, pqOn, size), newPQNode(t, pqOn, size)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no session")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	msg := strings.Repeat("m", int(a.pc.MTU()))
	if !hears(a, b, msg, 3*time.Second) {
		t.Fatalf("a message of %d bytes (MTU) did not arrive whole", len(msg))
	}
}
