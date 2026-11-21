package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

/***************************
 * two nodes over one link *
 ***************************/

type pqNode struct {
	pc    *PacketConn
	pub   ed25519.PublicKey
	heard chan string
	// dropPQ: the packets of types 0x10-0x13 this node sends are lost (a link that drops them)
	dropPQ atomic.Bool
	sent   [256]atomic.Int64 // session packets sent, by type
}

func (n *pqNode) key() (k edPub) {
	copy(k[:], n.pub)
	return
}

func newPQNode(t *testing.T, cfg PQConfig) *pqNode {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	pc, err := NewPacketConn(priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	n := &pqNode{pc: pc, pub: pub, heard: make(chan string, 64)}
	pc.testDrop = func(data []byte) bool {
		n.sent[data[0]].Add(1)
		return n.dropPQ.Load() && data[0] >= sessionTypePQInfo && data[0] <= sessionTypePQTraffic
	}
	pc.SetPQ(cfg)
	return n
}

// linkPQ links a and b and starts their readers.
func linkPQ(t *testing.T, a, b *pqNode) {
	t.Helper()
	cA, cB := newLossyLink(nil)
	t.Cleanup(func() { cA.Close() })
	go a.pc.HandleConn(b.pub, cA, 0)
	go b.pc.HandleConn(a.pub, cB, 0)
	warmPaths(t, a.pc, b.pc, a.pub, b.pub)
	for _, n := range []*pqNode{a, b} {
		go func(n *pqNode) {
			buf := make([]byte, 128)
			for {
				m, _, err := n.pc.ReadFrom(buf)
				if err != nil {
					return
				}
				select {
				case n.heard <- string(buf[:m]):
				default:
				}
			}
		}(n)
	}
}

// hears: to hears msg from from within d, from sending it again every 100 ms
func hears(from, to *pqNode, msg string, d time.Duration) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); {
		from.pc.WriteTo([]byte(msg), types.Addr(to.pub))
		select {
		case got := <-to.heard:
			if got == msg {
				return true
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	return false
}

// session: n's session with peer: none, classic or PQ
func session(n, peer *pqNode) string {
	for _, s := range n.pc.Debug.GetSessions() {
		if bytes.Equal(s.Key, peer.pub) {
			if s.PQ {
				return "pq"
			}
			return "classic"
		}
	}
	return "none"
}

func waitSessions(t *testing.T, a, b *pqNode, want string, d time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(d); session(a, b) != want || session(b, a) != want; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("sessions not %s in %s: A %s, B %s", want, d, session(a, b), session(b, a))
		}
		a.pc.WriteTo([]byte("keep"), types.Addr(b.pub))
		b.pc.WriteTo([]byte("keep"), types.Addr(a.pub))
	}
}

func sticky(n, peer *pqNode) bool {
	k := peer.key()
	n.pc.pq.mu.Lock()
	defer n.pc.pq.mu.Unlock()
	_, ok := n.pc.pq.sticky[k]
	return ok
}

// dropSessions forgets n's sessions, as their timeout would
func dropSessions(n *pqNode) {
	phony.Block(&n.pc.sessions, func() {
		for k, s := range n.pc.sessions.sessions {
			s.timer.Stop()
			delete(n.pc.sessions.sessions, k)
		}
	})
}

var pqOn = PQConfig{Enabled: true}

// TestPQBetweenTwoNodes: both with PQ sessions: the first packet goes at once (classic), the PQ session takes the
// classic one's place, traffic goes on (type 0x13 only, from then on), and each end holds the other as sticky.
func TestPQBetweenTwoNodes(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("the first packet did not arrive in 3 s")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	classicA, classicB := a.sent[sessionTypeTraffic].Load(), b.sent[sessionTypeTraffic].Load()
	for i := 0; i < 5; i++ {
		if !hears(a, b, "over pq", 3*time.Second) || !hears(b, a, "back over pq", 3*time.Second) {
			t.Fatal("traffic stopped after the PQ session took over")
		}
	}
	if a.sent[sessionTypeTraffic].Load() != classicA || b.sent[sessionTypeTraffic].Load() != classicB {
		t.Fatal("classic traffic went after the PQ session took over")
	}
	if a.sent[sessionTypePQTraffic].Load() == 0 || b.sent[sessionTypePQTraffic].Load() == 0 {
		t.Fatal("no PQ traffic sent")
	}
	if !sticky(a, b) || !sticky(b, a) {
		t.Fatalf("not sticky after a PQ session: A %v, B %v", sticky(a, b), sticky(b, a))
	}
}

// TestPQWithClassicNode: a node without PQ sessions (off here; the same as one without them) gets classic at once,
// and the key is not sticky.
func TestPQWithClassicNode(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, PQConfig{})
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 2*time.Second) || !hears(b, a, "back", 2*time.Second) {
		t.Fatal("no classic session with a node without PQ in 2 s")
	}
	time.Sleep(time.Second)
	if session(a, b) != "classic" || session(b, a) != "classic" {
		t.Fatalf("sessions: A %s, B %s", session(a, b), session(b, a))
	}
	if sticky(a, b) {
		t.Fatal("a classic node became sticky")
	}
	if b.sent[sessionTypePQInfo].Load()+b.sent[sessionTypePQInit].Load() != 0 {
		t.Fatal("the node with PQ off sent PQ packets")
	}
}

// TestPQDowngradeRequired: a link that drops the PQ types. A key that must be PQ gets no session at all, not a
// classic one.
func TestPQDowngradeRequired(t *testing.T) {
	var b *pqNode
	a := newPQNode(t, PQConfig{Enabled: true, Required: func(k ed25519.PublicKey) bool { return bytes.Equal(k, b.pub) }})
	b = newPQNode(t, pqOn)
	a.dropPQ.Store(true)
	b.dropPQ.Store(true)
	linkPQ(t, a, b)
	if hears(a, b, "hello", 3*time.Second) || hears(b, a, "hello", 2*time.Second) {
		t.Fatal("traffic went with a key that must be PQ while PQ packets are lost")
	}
	if session(a, b) != "none" {
		t.Fatalf("A has a %s session with a key that must be PQ", session(a, b))
	}
	if a.sent[sessionTypeInit].Load()+a.sent[sessionTypeAck].Load() != 0 {
		t.Fatal("A sent a classic init or ack to a key that must be PQ")
	}
	// the link mends: PQ comes up
	a.dropPQ.Store(false)
	b.dropPQ.Store(false)
	if !hears(a, b, "hello", 10*time.Second) {
		t.Fatal("no PQ session once the link carried PQ packets")
	}
	if session(a, b) != "pq" {
		t.Fatalf("A's session: %s", session(a, b))
	}
}

// TestPQDowngradePossible: the same link, keys "where possible": classic, and not sticky.
func TestPQDowngradePossible(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	a.dropPQ.Store(true)
	b.dropPQ.Store(true)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) || !hears(b, a, "back", 3*time.Second) {
		t.Fatal("no classic session while PQ packets are lost")
	}
	if session(a, b) != "classic" || sticky(a, b) || sticky(b, a) {
		t.Fatalf("A's session %s, sticky A %v B %v", session(a, b), sticky(a, b), sticky(b, a))
	}
}

// TestPQStickyRefusesClassic: after a PQ session, losing the PQ packets does not bring classic back.
func TestPQStickyRefusesClassic(t *testing.T) {
	a, b := newPQNode(t, pqOn), newPQNode(t, pqOn)
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 3*time.Second) {
		t.Fatal("no first packet")
	}
	waitSessions(t, a, b, "pq", 10*time.Second)
	hears(a, b, "confirm", 3*time.Second)
	hears(b, a, "confirm", 3*time.Second)
	dropSessions(a)
	dropSessions(b)
	a.dropPQ.Store(true)
	b.dropPQ.Store(true)
	if hears(a, b, "again", 3*time.Second) {
		t.Fatal("classic came back with a sticky key")
	}
	if s := session(a, b); s == "classic" {
		t.Fatal("A took a classic session with a sticky key")
	}
}

// TestPQRequiredBothWays: a key that must be PQ, PQ packets carried: a PQ session from the start, no classic packet.
func TestPQRequiredBothWays(t *testing.T) {
	var a, b *pqNode
	a = newPQNode(t, PQConfig{Enabled: true, Required: func(k ed25519.PublicKey) bool { return bytes.Equal(k, b.pub) }})
	b = newPQNode(t, PQConfig{Enabled: true, Required: func(k ed25519.PublicKey) bool { return bytes.Equal(k, a.pub) }})
	linkPQ(t, a, b)
	if !hears(a, b, "hello", 5*time.Second) || !hears(b, a, "back", 5*time.Second) {
		t.Fatal("no PQ session between keys that must be PQ")
	}
	for _, n := range []*pqNode{a, b} {
		if n.sent[sessionTypeInit].Load()+n.sent[sessionTypeAck].Load()+n.sent[sessionTypeTraffic].Load() != 0 {
			t.Fatal("a classic packet went between keys that must be PQ")
		}
	}
}

/*******************
 * the parts alone *
 *******************/

func newBarePC(t *testing.T) *PacketConn {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	pc, err := NewPacketConn(priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	pc.SetPQ(pqOn)
	return pc
}

func ownAsPeer(t *testing.T, pc *PacketConn) *pqPeerKey {
	own := pc.pqOwn()
	k := newPQPeerKey(&pc.publicEd, &own.pub, own.seq, own.notAfter)
	if k == nil {
		t.Fatal("no peer key")
	}
	return k
}

// TestPQInitOpens: an init sealed to B opens at B with its fields, and an ack is not taken as an init (the type is
// bound).
func TestPQInitOpens(t *testing.T) {
	a, b := newBarePC(t), newBarePC(t)
	secret := newRatchetSecret()
	cur, _ := newBoxKeys()
	next, _ := newBoxKeys()
	init := newPQInit(&cur, &next, 7, &secret, 42)
	data, err := init.encrypt(a, sessionTypePQInit, &b.publicEd, ownAsPeer(t, b))
	if err != nil {
		t.Fatal(err)
	}
	var got pqInit
	if ok, _ := got.decrypt(b, &a.publicEd, data); !ok {
		t.Fatal("the init did not open")
	}
	if got.secret != secret || got.secretNo != 42 || got.current != cur || got.next != next || got.keySeq != 7 || got.senderPQ != a.pqOwn().pub {
		t.Fatal("the fields came out different")
	}
	data[0] = sessionTypePQAck
	if ok, _ := got.decrypt(b, &a.publicEd, data); ok {
		t.Fatal("an init opened as an ack")
	}
}

// TestPQInitResealedFails: B opens A's init and seals its payload, A's signature in it, to C: C refuses it (the
// signature names B as the recipient).
func TestPQInitResealedFails(t *testing.T) {
	a, b, c := newBarePC(t), newBarePC(t), newBarePC(t)
	secret := newRatchetSecret()
	cur, _ := newBoxKeys()
	next, _ := newBoxKeys()
	init := newPQInit(&cur, &next, 0, &secret, 1)
	toB := ownAsPeer(t, b)
	data, _ := init.encrypt(a, sessionTypePQInit, &b.publicEd, toB)
	ownB := b.pqOwn()
	payload, err := hpke.Open(ownB.hpke, pqKDF, pqAEAD, pqBinding(pqHPKEInfo, sessionTypePQInit, &a.publicEd, &b.publicEd, ownB.seq, &ownB.hash), data[9:])
	if err != nil {
		t.Fatal(err)
	}
	toC := ownAsPeer(t, c)
	sealed, err := hpke.Seal(toC.hpke, pqKDF, pqAEAD, pqBinding(pqHPKEInfo, sessionTypePQInit, &a.publicEd, &c.publicEd, toC.seq, &toC.hash), payload)
	if err != nil {
		t.Fatal(err)
	}
	resealed := append(binary.BigEndian.AppendUint64([]byte{sessionTypePQInit}, toC.seq), sealed...)
	var got pqInit
	if ok, _ := got.decrypt(c, &a.publicEd, resealed); ok {
		t.Fatal("C took A's init resealed by B")
	}
}

// TestPQOldKeyOverlap: an init sealed to the process's key before the last rotation is taken within the overlap, and
// not after it; one sealed to a key never ours asks for our PQInfo.
func TestPQOldKeyOverlap(t *testing.T) {
	a, b := newBarePC(t), newBarePC(t)
	start := time.Now()
	clock := start
	b.pq.now = func() time.Time { return clock }
	old := ownAsPeer(t, b)
	clock = start.Add(pqKeyLifetime + time.Minute)
	if b.pqOwn().seq == old.seq {
		t.Fatal("no new key after its lifetime")
	}
	secret := newRatchetSecret()
	cur, _ := newBoxKeys()
	init := newPQInit(&cur, &cur, 0, &secret, 1)
	data, _ := init.encrypt(a, sessionTypePQInit, &b.publicEd, old)
	var got pqInit
	if ok, _ := got.decrypt(b, &a.publicEd, data); !ok {
		t.Fatal("an init under the key before was refused within the overlap")
	}
	clock = start.Add(pqKeyLifetime + pqKeyOverlap + 2*time.Minute)
	if ok, unknown := got.decrypt(b, &a.publicEd, data); ok || !unknown {
		t.Fatalf("an init under a key past its overlap: opened %v, asks for our PQInfo %v", ok, unknown)
	}
}

// TestPQInfoRules: the table takes a new number (with the clock slack), not a lower one or the same number with
// another key, and keeps a lower one with another key aside only within its notAfter.
func TestPQInfoRules(t *testing.T) {
	pc := newBarePC(t)
	now := time.Now()
	pc.pq.now = func() time.Time { return now }
	var logged []string
	cfg := pqOn
	cfg.Logf = func(f string, args ...any) { logged = append(logged, f) }
	pc.SetPQ(cfg)
	var peer edPub
	copy(peer[:], pc.publicEd[:]) // any valid key does: its X25519 half is what the table needs
	k1, k2, k3 := newPQKeyPub(t), newPQKeyPub(t), newPQKeyPub(t)
	day := uint64(24 * 3600)
	n := uint64(now.Unix())
	if ok, upd := pc.pq.accept(&peer, &k1, n, n+2*day); !ok || !upd {
		t.Fatal("the first key not taken")
	}
	if ok, _ := pc.pq.accept(&peer, &k2, n, n+2*day); ok {
		t.Fatal("the same number with another key taken")
	}
	// a lower number, another key, within its notAfter: kept aside, not in use
	if ok, _ := pc.pq.accept(&peer, &k2, n-10, n+day); ok {
		t.Fatal("a lower number taken")
	}
	if k := pc.pq.takeRollback(&peer); k == nil || k.pub != k2 {
		t.Fatal("the lower-numbered key was not kept aside")
	}
	// a lower number past its notAfter (but within the slack): not even kept
	if ok, _ := pc.pq.accept(&peer, &k3, n-20, n-day); ok || pc.pq.takeRollback(&peer) != nil {
		t.Fatal("a lower-numbered key past its own notAfter kept for rollback")
	}
	// a new number, two days past its notAfter by our clock (ahead): taken (the slack)
	if ok, _ := pc.pq.accept(&peer, &k3, n+100, n-2*day); !ok {
		t.Fatal("a key two days out of time by our clock refused (the slack)")
	}
	// four days past: refused, with a line in the log
	k4 := newPQKeyPub(t)
	if ok, _ := pc.pq.accept(&peer, &k4, n+200, n-4*day); ok {
		t.Fatal("a key four days out of time taken")
	}
	refusals := 0
	for _, line := range logged {
		if bytes.Contains([]byte(line), []byte("out of time")) {
			refusals++
		}
	}
	if refusals != 1 {
		t.Fatalf("log lines on a refusal by time: %d", refusals)
	}
}

func newPQKeyPub(t *testing.T) (pub pqPub) {
	t.Helper()
	pc := newBarePC(t)
	return pc.pqOwn().pub
}

// TestPQDirectionKeys: each end derives the same key for a direction, the two directions differ, and a packet of one
// does not open with the other's key; the header (associated data) cannot be changed.
func TestPQDirectionKeys(t *testing.T) {
	var shared boxShared
	copy(shared[:], bytes.Repeat([]byte{7}, len(shared)))
	secretX, secretY := newRatchetSecret(), newRatchetSecret()
	var x, y edPub
	x[0], y[0] = 1, 2
	xToY := pqTrafficKey(&shared, &secretY, &x, &y, 3, 4)
	xToYatY := pqTrafficKey(&shared, &secretY, &x, &y, 3, 4)
	yToX := pqTrafficKey(&shared, &secretX, &y, &x, 4, 3)
	sameSecretOtherWay := pqTrafficKey(&shared, &secretY, &y, &x, 4, 3)
	nonce := pqNonce(1)
	header := []byte{sessionTypePQTraffic, 3, 4, 1, 9}
	sealed := xToY.Seal(nil, nonce[:], []byte("msg"), header)
	if _, err := xToYatY.Open(nil, nonce[:], sealed, header); err != nil {
		t.Fatal("the two ends derived different keys for one direction")
	}
	if _, err := yToX.Open(nil, nonce[:], sealed, header); err == nil {
		t.Fatal("a packet opened with the other direction's key")
	}
	if _, err := sameSecretOtherWay.Open(nil, nonce[:], sealed, header); err == nil {
		t.Fatal("the label did not tell the directions apart")
	}
	bad := append([]byte(nil), header...)
	bad[4] ^= 1 // the epoch byte
	if _, err := xToYatY.Open(nil, nonce[:], sealed, bad); err == nil {
		t.Fatal("a changed header opened")
	}
}

// TestPQOwnSecrets: a packet under the secret before the newest opens while that one is kept (sessionTimeout after
// the first packet under the newest); under one no longer kept it is stale; secrets sharing the epoch byte are both
// tried.
func TestPQOwnSecrets(t *testing.T) {
	pc := newBarePC(t)
	info := newSession(&pc.publicEd, [32]byte{1}, [32]byte{2}, 10)
	info.mgr = &pc.sessions
	info.pq = true
	var shared boxShared
	shared[0] = 5
	peer := info.ed
	seal := func(secret *ratchetSecret, no uint64) []byte {
		aead := pqTrafficKey(&shared, secret, &peer, &pc.publicEd, 1, 2)
		n := pqNonce(1)
		return aead.Seal(nil, n[:], []byte("m"), []byte{byte(no)})
	}
	open := func(no uint64, sealed []byte) (bool, bool) {
		_, ok, stale := info._openPQ(nil, sealed, []byte{byte(no)}, 1, byte(no), 0, &shared, 1, 2)
		return ok, stale
	}
	s1, s2 := newRatchetSecret(), newRatchetSecret()
	info.own = []pqOwnSecret{{secret: s2, no: 2}, {secret: s1, no: 1, confirmed: true}}
	if ok, _ := open(1, seal(&s1, 1)); !ok {
		t.Fatal("the secret before did not open while the newest was unconfirmed")
	}
	if ok, _ := open(2, seal(&s2, 2)); !ok {
		t.Fatal("the newest did not open")
	}
	if info.own[1].until.IsZero() {
		t.Fatal("the newest confirmed, the one before has no end")
	}
	info.own[1].until = time.Now().Add(-time.Second)
	if ok, stale := open(1, seal(&s1, 1)); ok || !stale {
		t.Fatalf("under a secret no longer kept: opened %v, stale %v", ok, stale)
	}
	// two kept secrets with one epoch byte (numbers 256 apart): each tried
	s3 := newRatchetSecret()
	info.own = []pqOwnSecret{{secret: s3, no: 258}, {secret: s2, no: 2}}
	if ok, _ := open(2, seal(&s2, 2)); !ok {
		t.Fatal("of two secrets with one epoch byte, the older was not tried")
	}
}

// TestInitReplyLimited: an init in reply to traffic goes at once the first time, then at most once per
// initReplyInterval.
func TestInitReplyLimited(t *testing.T) {
	pc := newBarePC(t)
	now := time.Now()
	pc.pq.now = func() time.Time { return now }
	var k edPub
	k[0] = 9
	if !pc.pq.initReplyDue(&k) {
		t.Fatal("the first init in reply held back")
	}
	if pc.pq.initReplyDue(&k) {
		t.Fatal("a second init in reply at once")
	}
	now = now.Add(initReplyInterval)
	if !pc.pq.initReplyDue(&k) {
		t.Fatal("no init in reply after the interval")
	}
}
