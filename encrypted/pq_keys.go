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

// PQConfig turns on the hybrid post-quantum sessions (niko docs/design/ironwood-pq.md). Off, a PacketConn is the
// classic one: it sends no PQ packet and drops those that come, as a node without them does.
type PQConfig struct {
	Enabled bool
	// Required reports the keys a session with must be PQ: classic init, ack and traffic from them are dropped,
	// and none goes to them. Others are "where possible": classic at once, PQ in its place once both ends know each
	// other's ML-KEM key. A key that had a PQ session in this process is required from then on. Nil: none.
	Required func(key ed25519.PublicKey) bool
	// Logf takes the warnings: a PQInfo refused by its time (with the difference of the clocks), a key with a lower
	// number taken after a restart. Nil: none.
	Logf func(format string, args ...any)
}

var (
	pqKeyLifetime     = 24 * time.Hour // a process's ML-KEM key is replaced after this
	pqKeyOverlap      = 24 * time.Hour // and is still taken for this after the new one
	pqKeyValidity     = 48 * time.Hour // its notAfter: its number (the time it was made) and this
	pqClockSlack      = 72 * time.Hour // a PQInfo is taken this long after its notAfter (clocks of phones are off)
	pqInfoInterval    = 3 * time.Second
	initReplyInterval = 3 * time.Second // an init in reply to traffic, at most once in this per key
	pqInitRetry       = 2 * time.Second
	pqRollbackTries   = 3
	pqRollbackAfter   = 30 * time.Second
	pqStaleGrace      = 3 * time.Second
	pqPeersMax        = 4096
	pqStickyMax       = 65536
	pqLogInterval     = time.Minute
)

type pqState struct {
	cfg      atomic.Pointer[PQConfig]
	secretNo atomic.Uint64 // numbers of the ratchet secrets of this process, never repeated
	now      func() time.Time

	ownMu sync.Mutex
	own   *pqOwnKey // nil until enabled
	prev  *pqOwnKey // the key before own, taken until own.seq + pqKeyOverlap

	mu     sync.Mutex
	peers  map[edPub]*list.Element // of *pqPeer, the least used at the back
	lru    list.List
	sticky map[edPub]struct{}
}

func (s *pqState) init() {
	s.now = time.Now
	s.peers = make(map[edPub]*list.Element)
	s.sticky = make(map[edPub]struct{})
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

// required: a session with key must be PQ (always false while PQ is off)
func (s *pqState) required(key *edPub) bool {
	cfg := s.config()
	if cfg == nil {
		return false
	}
	s.mu.Lock()
	_, sticky := s.sticky[*key]
	s.mu.Unlock()
	return sticky || (cfg.Required != nil && cfg.Required(key.asKey()))
}

func (s *pqState) markSticky(key *edPub) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sticky[*key]; !ok && len(s.sticky) < pqStickyMax {
		s.sticky[*key] = struct{}{}
	}
}

func (s *pqState) nextSecretNo() uint64 {
	return s.secretNo.Add(1)
}

func (s *pqState) logf(format string, args ...any) {
	if cfg := s.cfg.Load(); cfg != nil && cfg.Logf != nil {
		cfg.Logf(format, args...)
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
	ed          edPub
	key         *pqPeerKey // its ML-KEM key in use
	rollback    *pqPeerKey // one with a lower number, taken once PQ inits under key go unanswered
	sentInfoAt  time.Time  // our PQInfo to it, last
	initReplyAt time.Time  // our init in reply to its traffic, last
	loggedAt    time.Time
}

type pqPeerKey struct {
	pub      pqPub
	hash     pqHash
	seq      uint64
	notAfter uint64
	hpke     hpke.PublicKey // with the peer's static X25519 key
}

func newPQPeerKey(ed *edPub, pub *pqPub, seq, notAfter uint64) *pqPeerKey {
	box, err := ed.toBox()
	if err != nil {
		return nil
	}
	k := &pqPeerKey{pub: *pub, hash: pub.hash(), seq: seq, notAfter: notAfter}
	if k.hpke, err = pqHPKEPublic(box, pub); err != nil {
		return nil
	}
	return k
}

// _peer: ed's entry, made if absent, as the most recently used. Under s.mu.
func (s *pqState) _peer(ed *edPub) *pqPeer {
	if e, ok := s.peers[*ed]; ok {
		s.lru.MoveToFront(e)
		return e.Value.(*pqPeer)
	}
	p := &pqPeer{ed: *ed}
	s.peers[*ed] = s.lru.PushFront(p)
	for len(s.peers) > pqPeersMax {
		last := s.lru.Back()
		s.lru.Remove(last)
		delete(s.peers, last.Value.(*pqPeer).ed)
	}
	return p
}

func (s *pqState) _live(k *pqPeerKey, slack time.Duration) bool {
	return k != nil && s.now().Unix() <= int64(k.notAfter)+int64(slack/time.Second)
}

// usableKey: ed's ML-KEM key to seal to, nil if none is known or it is out of time
func (s *pqState) usableKey(ed *edPub) *pqPeerKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.peers[*ed]; ok {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s._peer(ed)
	now := s.now()
	if now.Unix() > int64(notAfter)+int64(pqClockSlack/time.Second) {
		if now.Sub(p.loggedAt) >= pqLogInterval {
			p.loggedAt = now
			s.logf("PQ: the ML-KEM key of %x is out of time by our clock (%s past its end, more than %s): refused; are the clocks right?",
				ed[:8], now.Sub(time.Unix(int64(notAfter), 0)).Round(time.Second), pqClockSlack)
		}
		return false, false
	}
	switch {
	case p.key == nil || seq > p.key.seq:
		if k := newPQPeerKey(ed, pub, seq, notAfter); k != nil {
			p.key, p.rollback = k, nil
			return true, true
		}
	case seq == p.key.seq:
		return p.key.pub == *pub, false
	case p.key.pub != *pub && now.Unix() <= int64(notAfter) && (p.rollback == nil || seq > p.rollback.seq):
		p.rollback = newPQPeerKey(ed, pub, seq, notAfter)
	}
	return false, false
}

// takeRollback: the lower-numbered key kept aside for ed, now in use, if it is still within its notAfter
func (s *pqState) takeRollback(ed *edPub) *pqPeerKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.peers[*ed]
	if !ok {
		return nil
	}
	p := e.Value.(*pqPeer)
	k := p.rollback
	p.rollback = nil
	if !s._live(k, 0) {
		return nil
	}
	old := p.key
	p.key = k
	s.logf("PQ: %x answers no PQ init under its ML-KEM key number %d; its key number %d, a lower one, taken (a restart with a clock behind?)",
		ed[:8], old.seq, k.seq)
	return k
}

// infoDue: our PQInfo may go to ed now (at most once in pqInfoInterval); counts it as sent
func (s *pqState) infoDue(ed *edPub) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, now := s._peer(ed), s.now()
	if !p.sentInfoAt.IsZero() && now.Sub(p.sentInfoAt) < pqInfoInterval {
		return false
	}
	p.sentInfoAt = now
	return true
}

// initReplyDue: an init in reply to ed's traffic (no session, keys not matching, a packet that did not open) may go
// now, at most once in initReplyInterval; counts it as sent. The first goes at once.
func (s *pqState) initReplyDue(ed *edPub) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, now := s._peer(ed), s.now()
	if !p.initReplyAt.IsZero() && now.Sub(p.initReplyAt) < initReplyInterval {
		return false
	}
	p.initReplyAt = now
	return true
}
