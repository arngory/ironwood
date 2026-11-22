package encrypted

import (
	"container/list"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mlkem"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// PQConfig turns on the hybrid post-quantum sessions (niko docs/design/ironwood-pq.md). Off, a PacketConn sends no
// PQ packet of its own and drops those that come, as a node without them does: what it sends of its own is
// upstream's, byte for byte. Its replies are not upstream's in all: an init in reply to traffic goes at most once in
// initReplyInterval (3 s) per key, PQ on or off, and a repeated init is answered at most once in half pqInitRetry
// (1 s); off, PQ traffic (0x13) from a key with no session gets a classic init in reply, as classic traffic does (a
// peer that held a PQ session with us hears from us again; upstream's nodes send no 0x13).
//
// A PQ session is kept up by what opens under it, not by what we send: nothing opened in a minute, it goes, so that
// a peer that dropped it (PQ turned off, a restart) is noticed. A side that only reads sends an empty PQ packet once
// it sent nothing for half a minute, so that a one-way flow keeps its session. An empty message (WriteTo with no bytes) is not
// delivered over a PQ session: an empty PQ packet is the probe that confirms a session. Over a classic one it is
// delivered, as upstream does.
type PQConfig struct {
	Enabled bool
	// AnswerOnly: PQ in answer only. This node starts no PQ session itself: no PQInfo of its own to upgrade a classic
	// session, no PQ init for its own data or a later upgrade. A PQ session a peer starts is answered as with PQ on
	// (its PQ init, ack and traffic, our PQ init in reply to its PQ traffic with no session), and the node's ML-KEM key
	// is still announced in reply to the peer's PQ packets, so that a peer holding this node to PQ keeps its session.
	// A key held to PQ here (Required, or sticky) is the exception: with it the node starts PQ as with PQ on, or there
	// would be no session at all. A way back from PQ without a break: the peers held to it stay PQ, the others classic.
	// No key is held to PQ anew in answer only, nor is a hold moved on: the holds there run out (pqKeyValidity at
	// most), and a peer that starts PQ with this node is not started with by it after. Ignored while Enabled is false.
	AnswerOnly bool
	// Required reports the keys a session with must be PQ: classic init, ack and traffic from them are dropped,
	// and none goes to them. Others are "where possible": classic at once, PQ in its place once both ends know each
	// other's ML-KEM key. A key that had a PQ session in this process (a PQ packet of it opened, or its verified PQ
	// ack came with no classic session beside) is held to PQ too, for as long as its ML-KEM key lasts: until the
	// end (notAfter) of that key and the clock slack (3 days), and never more than pqKeyValidity (2 days) from the last
	// time it was held. Its PQ traffic (under the key of its session) and its newer keys move that on. Nil: none.
	Required func(key ed25519.PublicKey) bool
	// Logf takes the warnings: a PQInfo refused by its time (with the difference of the clocks), a key with a lower
	// number taken after a restart, a key held to PQ that asks for classic, a PQ session that did not come up. It is
	// called from a goroutine of its own, after the event (it may call into the PacketConn); past 64 lines waiting,
	// lines are dropped, and their number logged. Lines of events before Close may still come shortly after it.
	// Nil: none.
	Logf func(format string, args ...any)
	// SessionMax is the most PQ sessions up, with traffic opened under them or not, for this node to start a PQ one
	// with a peer that may be classic: past it, a new peer gets a classic session (a line in the log). Each PQ session
	// holds some 12.4 KB (a classic one 3.1). A peer that starts PQ with us still gets it, and so does a key held to PQ,
	// and our answer to PQ traffic, up to a hard limit of SessionMax and a quarter of it more (at least 64 more): the
	// PQ sessions held at once, and their memory (one that goes is let go at once). At the hard limit a PQ session
	// goes to make room: one nothing opened under yet first, then of the others the one nothing opened under for the
	// longest (10 s at least), a key held to PQ (sticky or Required) only after every other, and not while anything
	// opened under it in idleTimeout (a minute); its classic one takes its place where there is one. With every PQ
	// session in use, the new one is refused (classic where the key may be). Anyone with keys of its own, completing
	// the handshakes and keeping its sessions in use, can fill the table: new peers that may be classic, and peers
	// with sessions idle 10 s, get classic sessions meanwhile (PQ again once it stops); peers held to PQ keep theirs
	// while they are alive. PacketConn.PQSessionCount tells how many are up. 0: 2048.
	SessionMax int
}

var (
	pqKeyLifetime     = 24 * time.Hour // a process's ML-KEM key is replaced after this
	pqKeyOverlap      = 24 * time.Hour // and is still taken for this after the new one
	pqKeyValidity     = 48 * time.Hour // its notAfter: its number (the time it was made) and this
	pqClockSlack      = 72 * time.Hour // a PQInfo is taken this long after its notAfter (clocks of phones are off)
	pqInfoInterval    = 3 * time.Second
	pqInfoAnswerEvery = 30 * time.Second // our PQInfo in answer to a PQInfo, at most once per key (P-2)
	initReplyInterval = 3 * time.Second  // an init in reply to traffic, at most once in this per key
	pqInitRetry       = 2 * time.Second
	pqAwaitStart      = 3 * pqInitRetry // the higher key's wait for the lower's PQ init before it sends its own
	pqRollbackTries   = 3
	pqRollbackAfter   = 30 * time.Second
	pqStaleGrace      = 3 * time.Second
	pqPendingTimeout  = sessionTimeout   // a PQ init of ours unanswered this long is given up
	pqUpgradeRetry    = 5 * time.Minute  // then, on a classic session, tried again after this
	pqUnconfirmedMax  = 1024             // PQ sessions no traffic opened under yet
	pqProbeInterval   = time.Second      // an empty PQ packet, while a classic session beside a PQ one carries traffic
	pqSessionMax      = 2048             // PQ sessions, by default (PQConfig.SessionMax)
	pqEvictIdle       = 10 * time.Second // at the hard limit, a PQ session nothing opened under in this long may go
	pqPeersMax        = 4096
	pqStickyMax       = 65536
	pqStickyRefresh   = time.Minute // a sticky key with traffic opened is raised in the LRU at most once in this
	pqLogInterval     = time.Minute
	// PQInfos to keys with no announced ML-KEM key here, and PQ inits in reply to packets no one signed (unauthenticated
	// asks): at most this many a second for all of them, and as many at once
	pqUnsolicitedRate = 20.0
)

type pqState struct {
	cfg      atomic.Pointer[PQConfig]
	secretNo atomic.Uint64 // numbers of the ratchet secrets of this process, never repeated
	now      func() time.Time

	ownMu sync.Mutex
	own   *pqOwnKey // nil until enabled
	prev  *pqOwnKey // the key before own, taken until own.seq + pqKeyOverlap

	mu sync.Mutex
	// the keys announced in signed PQInfos, inits and acks, the least used at the back: an unauthenticated packet
	// makes no entry here, so it cannot push a real key out
	peers map[edPub]*list.Element // of *pqPeer
	lru   list.List
	// the reply limits of any key, apart: one pushed out loses only when its last reply went
	limits    map[edPub]*list.Element // of *pqLimit
	limitsLRU list.List
	// the buckets for answers that cost more than what asked for them: to keys with no entry in peers (unknown), and
	// to keys with one (a signed contact), apart, so that packets claimed from random keys cannot starve the others
	unknownBucket, knownBucket pqBucket
	// R5-3: signed asks of keys with no entry apart from both: no packet no one signed draws on it
	signedBucket pqBucket
	// Logf's lines waiting for its goroutine (logf)
	logMu      sync.Mutex
	logQ       []pqLogLine
	logRunning bool
	logDropped int
	// keys a session with must be PQ, the least recently confirmed at the back; one with traffic outlives one with
	// a handshake alone (stickyKey.traffic)
	sticky    map[edPub]*list.Element // of *stickyKey
	stickyLRU list.List
	// the last line in the log of each kind that may come from many keys: one a pqLogInterval
	stickyLogged, askedLogged, fullLogged, hardLogged, refusedLogged, unconfirmedLogged, noPQLogged, timeLogged time.Time
	// pqStickyMax, pqPendingTimeout, pqUpgradeRetry, pqPeersMax and pqAwaitStart, a test's own
	stickyMax      int
	pendingTimeout time.Duration
	awaitStart     time.Duration
	upgradeRetry   time.Duration
	peersMax       int
}

type pqBucket struct {
	tokens float64
	at     time.Time
}

type pqLogLine struct {
	logf   func(string, ...any)
	format string
	args   []any
}

// pqAsk: what a PQInfo of ours answers (infoDue)
type pqAsk int

const (
	askOwn      pqAsk = iota // our own traffic waits for a session: no token
	askSigned                // a signed packet of the key's: no token for a key in peers, the signed bucket's else
	askUnsigned              // a packet no one signed, claimed from the key: a token of the bucket its entry says
	askSealed                // a PQ init or ack sealed to an ML-KEM key of ours not taken: twice our answer, no token
)

const pqLogQueue = 64

type stickyKey struct {
	ed      edPub
	traffic bool
	until   uint64 // held until then (Unix seconds): holdUntil
}

type pqLimit struct {
	ed          edPub
	sentInfoAt  time.Time // our PQInfo to it, last
	initReplyAt time.Time // our init in reply to its traffic, last
	answeredAt  time.Time // our PQInfo in answer to a PQInfo of its, last
}

func (s *pqState) init() {
	s.now = time.Now
	s.peers = make(map[edPub]*list.Element)
	s.limits = make(map[edPub]*list.Element)
	s.sticky = make(map[edPub]*list.Element)
	s.unknownBucket.tokens, s.knownBucket.tokens, s.signedBucket.tokens = pqUnsolicitedRate, pqUnsolicitedRate, pqUnsolicitedRate
	s.stickyMax, s.pendingTimeout, s.upgradeRetry, s.peersMax = pqStickyMax, pqPendingTimeout, pqUpgradeRetry, pqPeersMax
	s.awaitStart = pqAwaitStart
}

func (s *pqState) config() *PQConfig {
	if cfg := s.cfg.Load(); cfg != nil && cfg.Enabled {
		return cfg
	}
	return nil
}

func (s *pqState) enabled() bool {
	return s.config() != nil
}

// initiates: this node may start a PQ session with key itself: PQ on, and not in answer only unless key is held to PQ
func (s *pqState) initiates(key *edPub) bool {
	cfg := s.config()
	return cfg != nil && (!cfg.AnswerOnly || s.required(key))
}

// answerOnly: PQ on, in answer only (PQConfig.AnswerOnly)
func (s *pqState) answerOnly() bool {
	cfg := s.config()
	return cfg != nil && cfg.AnswerOnly
}

// required: a session with key must be PQ (always false while PQ is off)
func (s *pqState) required(key *edPub) bool {
	cfg := s.config()
	if cfg == nil {
		return false
	}
	if s.isSticky(key) {
		return true
	}
	if cfg.Required == nil {
		return false
	}
	k := *key // a copy the callback may keep: key itself stays where it is (no allocation on the way without one)
	return cfg.Required(k[:])
}

// isSticky: key is held to PQ sessions (it had one here), its hold not past
func (s *pqState) isSticky(key *edPub) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s._held(key) != nil
}

// _held: key's sticky entry, nil if none or past its hold (such an entry goes). Under s.mu.
func (s *pqState) _held(key *edPub) *stickyKey {
	e, ok := s.sticky[*key]
	if !ok {
		return nil
	}
	k := e.Value.(*stickyKey)
	if s.now().Unix() > int64(k.until) {
		s.stickyLRU.Remove(e)
		delete(s.sticky, *key)
		return nil
	}
	return k
}

// _holdUntil: the end of a hold on a key under an ML-KEM key that ends at notAfter: that end and the clock slack (a
// peer's clock may be days off), and no more than pqKeyValidity from now (no hold is longer than a key lasts)
func (s *pqState) _holdUntil(notAfter uint64) uint64 {
	return min(uint64(s.now().Unix())+uint64(pqKeyValidity/time.Second), notAfter+uint64(pqClockSlack/time.Second))
}

// markSticky: key had a PQ session, by a verified ack, or by traffic that opened (traffic), under an ML-KEM key of it
// that ends at notAfter (the key of the session, not a newer one in the table: a session under a key the peer no
// longer announces holds it no longer than that key); it is held to PQ until _holdUntil. Past pqStickyMax, the
// least recently marked key with a handshake alone goes first (a full set would otherwise take no new key); each one
// that goes is a key that can be downgraded again, so it is logged.
func (s *pqState) markSticky(key *edPub, notAfter uint64, traffic bool) {
	if s.answerOnly() {
		return // answer only: no new hold, none moved on; the holds there run out (the owner's choice, 2026-11-22)
	}
	s.mu.Lock()
	until := s._holdUntil(notAfter)
	if k := s._held(key); k != nil {
		s.stickyLRU.MoveToFront(s.sticky[*key])
		k.traffic = k.traffic || traffic
		k.until = max(k.until, until)
		s.mu.Unlock()
		return
	}
	if s.now().Unix() > int64(until) {
		s.mu.Unlock()
		return // its key is out of time by our clock: not held
	}
	s.sticky[*key] = s.stickyLRU.PushFront(&stickyKey{ed: *key, traffic: traffic, until: until})
	if len(s.sticky) <= s.stickyMax {
		s.mu.Unlock()
		return
	}
	victim := s.stickyLRU.Back()
	for e, n := victim, 0; e != nil && n < 64; e, n = e.Prev(), n+1 {
		if !e.Value.(*stickyKey).traffic {
			victim = e
			break
		}
	}
	gone := victim.Value.(*stickyKey)
	s.stickyLRU.Remove(victim)
	delete(s.sticky, gone.ed)
	due := s._due(&s.stickyLogged)
	s.mu.Unlock()
	if due {
		s.logf("PQ: %d keys hold to PQ sessions, the most kept: %x is no longer held to them", s.stickyMax, gone.ed[:8])
	}
}

// _due: a line in the log of the kind last logged at *at may go now (at most one a pqLogInterval); counts it as
// logged. Under s.mu; the line itself goes after s.mu is let go (logf calls the embedder's Logf).
func (s *pqState) _due(at *time.Time) bool {
	if now := s.now(); now.Sub(*at) >= pqLogInterval {
		*at = now
		return true
	}
	return false
}

// logEvery: a line in the log, unless one of its kind (at) went less than pqLogInterval ago
func (s *pqState) logEvery(at *time.Time, format string, args ...any) {
	s.mu.Lock()
	due := s._due(at)
	s.mu.Unlock()
	if due {
		s.logf(format, args...)
	}
}

// logDue: a line at *at may go now (nothing is counted as sent)
func (s *pqState) logDue(at *time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Sub(*at) >= pqLogInterval
}

// sessionMax: PQConfig.SessionMax, or its default
func (s *pqState) sessionMax() int {
	if cfg := s.config(); cfg != nil && cfg.SessionMax > 0 {
		return cfg.SessionMax
	}
	return pqSessionMax
}

// hardMax: the most PQ sessions at all, SessionMax and a quarter of it more (at least 64 more)
func (s *pqState) hardMax() int {
	most := s.sessionMax()
	return most + max(64, most/4)
}

func (s *pqState) nextSecretNo() uint64 {
	return s.secretNo.Add(1)
}

// logf: a line to Logf, from a goroutine of its own (it may call into the PacketConn, which logf's callers hold:
// the manager's actor, a session's): queued, at most pqLogQueue waiting, the rest dropped and counted
func (s *pqState) logf(format string, args ...any) {
	cfg := s.cfg.Load()
	if cfg == nil || cfg.Logf == nil {
		return
	}
	s.logMu.Lock()
	if len(s.logQ) >= pqLogQueue {
		s.logDropped++
		s.logMu.Unlock()
		return
	}
	s.logQ = append(s.logQ, pqLogLine{logf: cfg.Logf, format: format, args: args})
	start := !s.logRunning
	s.logRunning = true
	s.logMu.Unlock()
	if start {
		go s.drainLog()
	}
}

// drainLog calls Logf with the lines queued, until none waits
func (s *pqState) drainLog() {
	for {
		s.logMu.Lock()
		if len(s.logQ) == 0 {
			s.logRunning = false
			s.logMu.Unlock()
			return
		}
		line, dropped := s.logQ[0], s.logDropped
		s.logQ, s.logDropped = s.logQ[1:], 0
		s.logMu.Unlock()
		if dropped != 0 {
			line.logf("PQ: %d lines of the log dropped (too many at once)", dropped)
		}
		line.logf(line.format, line.args...)
	}
}

/***********************
 * the process's keys *
 ***********************/

type pqOwnKey struct {
	priv     *mlkem.DecapsulationKey768
	hpke     hpke.PrivateKey
	pub      pqPub
	hash     pqHash
	seq      uint64 // the time it was made, Unix seconds; only grows
	notAfter uint64
	info     []byte // the signed PQInfo of it
}

func (pc *PacketConn) newPQOwnKey(seq uint64) *pqOwnKey {
	priv, err := mlkem.GenerateKey768()
	if err != nil {
		panic("failed to generate an ML-KEM key")
	}
	k := &pqOwnKey{priv: priv, seq: seq, notAfter: seq + uint64(pqKeyValidity/time.Second)}
	copy(k.pub[:], priv.EncapsulationKey().Bytes())
	k.hash = k.pub.hash()
	if k.hpke, err = pqHPKEPrivate(&pc.secretBox, priv); err != nil {
		panic("failed to make the hybrid key: " + err.Error())
	}
	k.info = (&sessionPQInfo{pub: k.pub, seq: k.seq, notAfter: k.notAfter}).encode(&pc.secretEd, pc.groupAuth)
	return k
}

// pqOwn: the process's ML-KEM key now, a new one made once the one in use has lived pqKeyLifetime
func (pc *PacketConn) pqOwn() *pqOwnKey {
	s := &pc.pq
	now := uint64(s.now().Unix())
	s.ownMu.Lock()
	defer s.ownMu.Unlock()
	switch {
	case s.own == nil:
		s.own = pc.newPQOwnKey(now)
	case now >= s.own.seq+uint64(pqKeyLifetime/time.Second):
		seq := now
		if seq <= s.own.seq {
			seq = s.own.seq + 1
		}
		s.prev, s.own = s.own, pc.newPQOwnKey(seq)
	}
	return s.own
}

// pqOwnFor: the process's key with number seq, if it is still taken (the one before for pqKeyOverlap after the new)
func (pc *PacketConn) pqOwnFor(seq uint64) *pqOwnKey {
	own := pc.pqOwn()
	s := &pc.pq
	s.ownMu.Lock()
	defer s.ownMu.Unlock()
	switch {
	case seq == own.seq:
		return own
	case s.prev != nil && seq == s.prev.seq && uint64(s.now().Unix()) < own.seq+uint64(pqKeyOverlap/time.Second):
		return s.prev
	}
	return nil
}

/**********
 * PQInfo *
 **********/

const sessionPQInfoSize = 1 + pqPubSize + 8 + 8 + edSigSize

// sessionPQInfo announces a process's ML-KEM key, signed by the node's ed25519 key: its number (the time it was
// made) and the time after which it is not taken.
type sessionPQInfo struct {
	pub      pqPub
	seq      uint64
	notAfter uint64
}

func (pq *sessionPQInfo) sigBytes() []byte {
	out := make([]byte, 0, len(pqInfoSigCtx)+1+pqPubSize+16)
	out = append(out, pqInfoSigCtx...)
	out = append(out, sessionTypePQInfo)
	out = append(out, pq.pub[:]...)
	out = binary.BigEndian.AppendUint64(out, pq.seq)
	return binary.BigEndian.AppendUint64(out, pq.notAfter)
}

func (pq *sessionPQInfo) encode(from *edPriv, auth groupAuth) []byte {
	sig := edSign(pq.sigBytes(), from, auth.preimage())
	data := make([]byte, 0, sessionPQInfoSize)
	data = append(data, sessionTypePQInfo)
	data = append(data, pq.pub[:]...)
	data = binary.BigEndian.AppendUint64(data, pq.seq)
	data = binary.BigEndian.AppendUint64(data, pq.notAfter)
	return append(data, sig[:]...)
}

func (pq *sessionPQInfo) decode(from *edPub, data []byte, auth groupAuth) bool {
	if len(data) != sessionPQInfoSize || data[0] != sessionTypePQInfo {
		return false
	}
	offset := bytesPop(pq.pub[:], data, 1)
	pq.seq = binary.BigEndian.Uint64(data[offset:])
	pq.notAfter = binary.BigEndian.Uint64(data[offset+8:])
	var sig edSig
	bytesPop(sig[:], data, offset+16)
	return edCheck(pq.sigBytes(), &sig, from, auth.preimage())
}

/*******************
 * the others' keys *
 *******************/

type pqPeer struct {
	ed       edPub
	key      *pqPeerKey // its ML-KEM key in use
	rollback *pqPeerKey // one with a lower number, taken once PQ inits under key go unanswered
	loggedAt time.Time
}

type pqPeerKey struct {
	pub      pqPub
	hash     pqHash
	seq      uint64
	notAfter uint64
	box      boxPub // the peer's static X25519 key, the other half of the hybrid key (hpkeKey)
}

func newPQPeerKey(ed *edPub, pub *pqPub, seq, notAfter uint64) *pqPeerKey {
	box, err := ed.toBox()
	if err != nil {
		return nil
	}
	k := &pqPeerKey{pub: *pub, hash: pub.hash(), seq: seq, notAfter: notAfter, box: *box}
	if _, err := k.hpkeKey(); err != nil {
		return nil // not a key
	}
	return k
}

// hpkeKey: the hybrid key to seal to, made where it is used: parsed, it holds some 8 KB, and the table keeps an entry
// for each of up to pqPeersMax keys (its bytes, 1.2 KB)
func (k *pqPeerKey) hpkeKey() (hpke.PublicKey, error) {
	return pqHPKEPublic(&k.box, &k.pub)
}

// _peer: ed's entry, made if absent, as the most recently used; only for a key ed signed. Past pqPeersMax, the least
// used entry of a key not held to PQ goes first. Under s.mu.
func (s *pqState) _peer(ed *edPub) *pqPeer {
	if e, ok := s.peers[*ed]; ok {
		s.lru.MoveToFront(e)
		return e.Value.(*pqPeer)
	}
	p := &pqPeer{ed: *ed}
	s.peers[*ed] = s.lru.PushFront(p)
	if len(s.peers) > s.peersMax {
		victim := s.lru.Back()
		for e, n := victim, 0; e != nil && n < 64; e, n = e.Prev(), n+1 {
			if _, held := s.sticky[e.Value.(*pqPeer).ed]; !held {
				victim = e
				break
			}
		}
		s.lru.Remove(victim)
		delete(s.peers, victim.Value.(*pqPeer).ed)
	}
	return p
}

// _limit: ed's reply limits, made if absent. Under s.mu.
func (s *pqState) _limit(ed *edPub) *pqLimit {
	if e, ok := s.limits[*ed]; ok {
		s.limitsLRU.MoveToFront(e)
		return e.Value.(*pqLimit)
	}
	l := &pqLimit{ed: *ed}
	s.limits[*ed] = s.limitsLRU.PushFront(l)
	if len(s.limits) > s.peersMax {
		last := s.limitsLRU.Back()
		s.limitsLRU.Remove(last)
		delete(s.limits, last.Value.(*pqLimit).ed)
	}
	return l
}

// take: one token of b, if there is one
func (b *pqBucket) take(now time.Time) bool {
	if !b.at.IsZero() {
		b.tokens = min(pqUnsolicitedRate, b.tokens+now.Sub(b.at).Seconds()*pqUnsolicitedRate)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// tokenDue: a token of the known bucket, for a PQ init in reply to a packet no one signed, claimed from a key whose
// ML-KEM key is known here (the init is some 25 times the packet, and the per-key limits are an LRU that such
// packets refill)
func (s *pqState) tokenDue() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.knownBucket.take(s.now())
}

func (s *pqState) _live(k *pqPeerKey, slack time.Duration) bool {
	return k != nil && s.now().Unix() <= int64(k.notAfter)+int64(slack/time.Second)
}

// usableKey: ed's ML-KEM key to seal to, nil if none is known or it is out of time; the entry counts as used
func (s *pqState) usableKey(ed *edPub) *pqPeerKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.peers[*ed]; ok {
		s.lru.MoveToFront(e)
		if p := e.Value.(*pqPeer); s._live(p.key, pqClockSlack) {
			return p.key
		}
	}
	return nil
}

// accept takes a key that ed announced (by PQInfo, or as the sender of a PQ init or ack, both signed). A new number
// is taken with the clock slack past notAfter. The same number with another key is not. A lower one with another key
// is a restart with a clock behind, or an old PQInfo replayed: it is kept aside (only within its notAfter, no slack)
// and taken once PQ inits under the key in use go unanswered (takeRollback). accepted: the key in use is this one;
// updated: it just became so.
func (s *pqState) accept(ed *edPub, pub *pqPub, seq, notAfter uint64) (accepted, updated bool) {
	now := s.now()
	if !s.plausible(seq, notAfter) {
		return false, false
	}
	if now.Unix() > int64(notAfter)+int64(pqClockSlack/time.Second) {
		// before any entry is made: a PQInfo out of time, replayed, would make its key one with an entry here (and our
		// answers to packets claimed from it would skip the bucket)
		s.logEvery(&s.timeLogged, "PQ: the ML-KEM key of %x is out of time by our clock (%s past its end, more than %s): refused; are the clocks right?",
			ed[:8], now.Sub(time.Unix(int64(notAfter), 0)).Round(time.Second), pqClockSlack)
		return false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s._peer(ed)
	switch {
	case p.key == nil || seq > p.key.seq:
		if k := newPQPeerKey(ed, pub, seq, notAfter); k != nil {
			p.key, p.rollback = k, nil
			if held := s._held(ed); held != nil && !s.answerOnly() {
				// a newer key of a sticky one: held to PQ for it (not in answer only, where no hold is moved on, R7-1)
				held.until = max(held.until, s._holdUntil(notAfter))
			}
			return true, true
		}
	case seq == p.key.seq:
		return p.key.pub == *pub, false
	case p.key.pub != *pub && now.Unix() <= int64(notAfter) && (p.rollback == nil || seq > p.rollback.seq):
		p.rollback = newPQPeerKey(ed, pub, seq, notAfter)
	}
	return false, false
}

// plausible: a key numbered no further ahead than the clocks can be apart, and valid no longer than any key is made
// for (so its notAfter is at most pqKeyValidity and pqClockSlack from now). One beyond either, replayed, would take
// the table's place of every real key after it (a lower number is a rollback, kept aside).
func (s *pqState) plausible(seq, notAfter uint64) bool {
	now := uint64(s.now().Unix())
	return seq <= now+uint64(pqClockSlack/time.Second) && notAfter >= seq && notAfter-seq <= uint64(pqKeyValidity/time.Second)
}

// logStripped: ed announced an ML-KEM key, and its PQ session did not come up (what: how; then: what it leaves):
// once in pqLogInterval
func (s *pqState) logStripped(ed *edPub, what, then string) {
	s.mu.Lock()
	e, ok := s.peers[*ed]
	if !ok {
		s.mu.Unlock()
		return
	}
	due := s._due(&e.Value.(*pqPeer).loggedAt)
	s.mu.Unlock()
	if !due {
		return
	}
	s.logf("PQ: %x announced an ML-KEM key, and %s in %s: %s (PQ packets lost or dropped on the way?)",
		ed[:8], what, s.pendingTimeout, then)
}

// takeRollback: the lower-numbered key kept aside for ed, now in use, if it is still within its notAfter
func (s *pqState) takeRollback(ed *edPub) *pqPeerKey {
	s.mu.Lock()
	e, ok := s.peers[*ed]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	p := e.Value.(*pqPeer)
	k := p.rollback
	p.rollback = nil
	if !s._live(k, 0) {
		s.mu.Unlock()
		return nil
	}
	old := p.key
	p.key = k
	s.mu.Unlock()
	s.logf("PQ: %x answers no PQ init under its ML-KEM key number %d; its key number %d, a lower one, taken (a restart with a clock behind?)",
		ed[:8], old.seq, k.seq)
	return k
}

// answerDue: a PQInfo of ed's may be answered with ours (at most once in pqInfoAnswerEvery); counts it. With a
// one-way delay of half pqInfoInterval or more, each end's answer would come after the other's limit ran out, and the
// two would answer each other for good (P-2)
func (s *pqState) answerDue(ed *edPub) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, now := s._limit(ed), s.now()
	if !l.answeredAt.IsZero() && now.Sub(l.answeredAt) < pqInfoAnswerEvery {
		return false
	}
	l.answeredAt = now
	return true
}

// infoDue: our PQInfo may go to ed now, at most once in pqInfoInterval, and with a token where ask says (pqAsk: in
// reply to a packet no one signed, of the unknown bucket for a key with no entry in peers, the known one for a key
// with one; to a signed packet of a key with no entry, of the signed bucket; none for a signed packet of a key in
// peers, our own data or a sealed init); counts it as sent. starved: none went for want of a token.
func (s *pqState) infoDue(ed *edPub, ask pqAsk) (due, starved bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, now := s._limit(ed), s.now()
	if !l.sentInfoAt.IsZero() && now.Sub(l.sentInfoAt) < pqInfoInterval {
		return false, false
	}
	_, known := s.peers[*ed]
	switch {
	case ask == askUnsigned && !known:
		if !s.unknownBucket.take(now) {
			return false, true
		}
	case ask == askUnsigned:
		if !s.knownBucket.take(now) {
			return false, true
		}
	case ask == askSigned && !known:
		if !s.signedBucket.take(now) {
			return false, true
		}
	}
	l.sentInfoAt = now
	return true, false
}

// initReplyDue: an init in reply to ed's traffic (no session, keys not matching, a packet that did not open) may go
// now, at most once in initReplyInterval; counts it as sent. The first goes at once.
func (s *pqState) initReplyDue(ed *edPub) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, now := s._limit(ed), s.now()
	if !l.initReplyAt.IsZero() && now.Sub(l.initReplyAt) < initReplyInterval {
		return false
	}
	l.initReplyAt = now
	return true
}
