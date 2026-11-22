package encrypted

import (
	"crypto/cipher"
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/Arceliar/phony"
)

/*

TODO:
  We either need to save the private keys for sent inits (so we can make a session when we receive an ack...) *or* we need to send an ack back when we receive an ack and we create a session because of it

*/

const (
	sessionTimeout            = time.Minute
	sessionTrafficOverheadMin = 1 + 1 + 1 + 1 + boxOverhead + boxPubSize // header, seq, seq, nonce
	sessionTrafficOverhead    = sessionTrafficOverheadMin + 9 + 9 + 9
	sessionInitSize           = 1 + boxPubSize + boxOverhead + edSigSize + boxPubSize + boxPubSize + 8 + 8
	sessionAckSize            = sessionInitSize
)

const (
	sessionTypeDummy = iota
	sessionTypeInit
	sessionTypeAck
	sessionTypeTraffic
)

/******************
 * sessionManager *
 ******************/

type sessionManager struct {
	phony.Inbox
	pc             *PacketConn
	sessions       map[edPub]*sessionInfo
	buffers        map[edPub]*sessionBuffer
	pqPending      map[edPub]*pqPending
	pqRetry        map[edPub]bool         // an upgrade to PQ to try again (_upgradeLater)
	pqAwait        map[edPub]bool         // a PQ init of the peer's awaited (_awaitPQInit)
	pqAsk          map[edPub]*pqAskState  // our PQInfo asked again of a peer whose key we lack (_askPQInfoAgain)
	pqUnconfirmed  map[edPub]*sessionInfo // PQ sessions no traffic may have opened under yet (_countUnconfirmed)
	pqCount        atomic.Int64           // the PQ sessions in sessions (_put); read by PQSessionCount
	unconfirmedMax int                    // pqUnconfirmedMax, a test's own
	idleTimeout    time.Duration          // sessionTimeout, a test's own
	evictIdle      time.Duration          // pqEvictIdle, a test's own
}

func (mgr *sessionManager) init(pc *PacketConn) {
	mgr.pc = pc
	mgr.sessions = make(map[edPub]*sessionInfo)
	mgr.buffers = make(map[edPub]*sessionBuffer)
	mgr.pqPending = make(map[edPub]*pqPending)
	mgr.pqRetry = make(map[edPub]bool)
	mgr.pqAwait = make(map[edPub]bool)
	mgr.pqAsk = make(map[edPub]*pqAskState)
	mgr.pqUnconfirmed = make(map[edPub]*sessionInfo)
	mgr.unconfirmedMax = pqUnconfirmedMax
	mgr.idleTimeout = sessionTimeout
	mgr.evictIdle = pqEvictIdle
}

// _put: info as the session with ed, nil for none; the count of PQ sessions follows
func (mgr *sessionManager) _put(ed edPub, info *sessionInfo) {
	if old := mgr.sessions[ed]; old != nil && old.pq {
		mgr.pqCount.Add(-1)
		if mgr.pqUnconfirmed[ed] == old {
			delete(mgr.pqUnconfirmed, ed) // whichever way it goes (_expire, _evict, replaced): not counted on (N-R5-3)
		}
	}
	if info == nil {
		delete(mgr.sessions, ed)
		delete(mgr.pqAsk, ed) // its asks of a classic session gone with it (round 8d)
		return
	}
	mgr.sessions[ed] = info
	if info.pq {
		mgr.pqCount.Add(1)
	}
}

// _restoreClassic: the classic session beside the PQ one info takes its place, with a timer of its own again (its
// own may have fired while the PQ one held the table, and done nothing: without a new one it would never go)
func (mgr *sessionManager) _restoreClassic(info *sessionInfo) {
	fb := info.fallback
	info.fallback = nil
	mgr._put(info.ed, fb)
	fb.Act(mgr, fb._resetTimer)
}

// _evict: the PQ session info goes, to make room: the classic one beside it takes its place where there is one (and
// the upgrade is tried again later); then: which, for the log
func (mgr *sessionManager) _evict(info *sessionInfo) (then string) {
	// its timer stopped: else it would hold the session (some 12.4 KB) for idleTimeout, and the hard limit would not
	// bound the memory of a churn of new ones
	defer info.Act(mgr, func() {
		if info.timer != nil {
			info.timer.Stop()
		}
	})
	// beside a confirmed one, the classic session is stale (the peer left it), as for dropPQ and _expire
	if info.fallback != nil && !info.confirmed.Load() && !mgr.pc.pq.required(&info.ed) {
		mgr._restoreClassic(info)
		mgr._upgradeLater(info.ed)
		return "its classic session stays"
	}
	mgr._put(info.ed, nil)
	return "it goes"
}

// _fallbackGrace: info, a PQ session, was confirmed here less than pqStaleGrace ago: the classic session beside it
// still takes the peer's traffic (round 8c). A key that must be PQ by the config has no classic session beside.
func (mgr *sessionManager) _fallbackGrace(info *sessionInfo) bool {
	if !info.confirmed.Load() {
		return false
	}
	at := info.confirmedAt.Load()
	return at != 0 && mgr.pc.pq.now().Sub(time.Unix(0, at)) < pqStaleGrace
}

// _expire: info's timer fired: nothing received under it in idleTimeout (a PQ session: nothing opened; our own sends
// keep a classic session up, not a PQ one, or a peer that dropped its PQ session would never be noticed)
func (mgr *sessionManager) _expire(info *sessionInfo) {
	if mgr.sessions[info.ed] != info {
		return // an old timer of a session replaced since
	}
	if info.fallback != nil && !info.confirmed.Load() && !mgr.pc.pq.required(&info.ed) {
		// a PQ session nothing opened under, of a key that may be classic: the classic one beside it stays
		mgr._restoreClassic(info)
		mgr.pc.pq.logStripped(&info.ed, "no PQ packet of its opened here", "the session stays classic")
		mgr._upgradeLater(info.ed)
		return
	}
	mgr._put(info.ed, nil)
}

// _openedWithin: a PQ packet opened under info less than d ago (by pq.now)
func (mgr *sessionManager) _openedWithin(info *sessionInfo, d time.Duration) bool {
	at := info.openedAt.Load()
	return at != 0 && mgr.pc.pq.now().UnixNano()-at < int64(d)
}

// upgradeClassic: each classic session up is upgraded later (_upgradeLater), PQ back from answer only
func (mgr *sessionManager) upgradeClassic() {
	mgr.Act(nil, func() {
		var keys []edPub
		for k, info := range mgr.sessions {
			if !info.pq {
				keys = append(keys, k)
			}
		}
		// spread over pqUpgradeRetry: all at once, thousands of PQ inits would be sealed in this actor in one go
		// (some 0.32 ms each) and sent in a burst (2.5 KB each)
		for i, k := range keys {
			mgr._upgradeAfter(k, mgr.pc.pq.upgradeRetry*time.Duration(i+1)/time.Duration(len(keys)))
		}
	})
}

// dropPQ forgets the PQ sessions and the PQ inits under way (PQ turned off): the next packet starts a classic one
func (mgr *sessionManager) dropPQ() {
	phony.Block(mgr, func() {
		for k, p := range mgr.pqPending {
			if p.timer != nil {
				p.timer.Stop()
			}
			delete(mgr.pqPending, k)
		}
		for k, info := range mgr.sessions {
			switch {
			case info.pq && info.fallback != nil && !info.confirmed.Load():
				// the classic session beside it goes on: the peer may still use it. Beside a confirmed one it is stale
				// (the peer left it), and goes with it
				mgr._restoreClassic(info)
			case info.pq:
				mgr._put(k, nil)
			}
		}
		clear(mgr.pqUnconfirmed)
	})
}

func (mgr *sessionManager) _newSession(ed *edPub, recv, send boxPub, seq uint64) *sessionInfo {
	info := newSession(ed, recv, send, seq)
	info.Act(mgr, func() {
		info.mgr = mgr
		info._resetTimer()
	})
	mgr._put(info.ed, info)
	return info
}

// _classic: the classic session with pub: the one in use, or the one kept beside a PQ session nothing opened under yet
func (mgr *sessionManager) _classic(pub *edPub) *sessionInfo {
	info := mgr.sessions[*pub]
	if info != nil && info.pq {
		return info.fallback
	}
	return info
}

func (mgr *sessionManager) _sessionForInit(pub *edPub, init *sessionInit) (*sessionInfo, *sessionBuffer) {
	var info *sessionInfo
	var buf *sessionBuffer
	if info = mgr._classic(pub); info == nil {
		if pq := mgr.sessions[*pub]; pq != nil && pq.pq {
			// classic from a key that may be classic, to a PQ session nothing opened under yet (pqRefusesClassic let
			// it through): the classic session goes beside it, as the one traffic takes until a PQ packet opens
			info = newSession(pub, init.current, init.next, init.seq)
			info.Act(mgr, func() {
				info.mgr = mgr
				info._resetTimer()
			})
			pq.fallback = info
		} else {
			info = mgr._newSession(pub, init.current, init.next, init.seq)
		}
		if buf = mgr.buffers[*pub]; buf != nil {
			buf.timer.Stop()
			delete(mgr.buffers, *pub)
			info.sendPub, info.sendPriv = buf.init.current, buf.currentPriv
			info.nextPub, info.nextPriv = buf.init.next, buf.nextPriv
			info._fixShared(0, 0)
			// The caller is responsible for sending buf.data when ready
		}
	}
	return info, buf
}

func (mgr *sessionManager) handleData(from phony.Actor, pub *edPub, data []byte) {
	mgr.Act(from, func() {
		if len(data) == 0 {
			return
		}
		pq := mgr.pc.pq.enabled()
		switch data[0] {
		case sessionTypeDummy:
		case sessionTypeInit:
			switch {
			case len(data) != sessionInitSize:
				// not an init: no answer to it
			case mgr.pc.pq.required(pub):
				// it must be PQ. With no session and its ML-KEM key known: our PQ init, as to its classic traffic (it
				// wants a session, and may start no PQ one: past its SessionMax, it starts none with a key that may be
				// classic, and we may have nothing to send). Else our PQInfo, so that it can start one if it has them
				mgr._logClassicAsked(pub, data)
				if key := mgr.pc.pq.usableKey(pub); key != nil && mgr.sessions[*pub] == nil {
					mgr._replyPQInit(pub, key)
				} else {
					mgr._replyPQInfo(pub)
				}
			default:
				if init := new(sessionInit); init.decrypt(&mgr.pc.secretBox, pub, data, mgr.pc.groupAuth) {
					if info := mgr.sessions[*pub]; pq && info != nil && info.pq && info.confirmed.Load() {
						// A classic init, signed, from a key not held to PQ (or no longer), to a PQ session: the peer
						// has no PQ session now (PQ turned off, or a restart without it), and the PQ session goes. Not
						// if it is older than the PQ session (replayed: the seq is in whole seconds, and an init kept in
						// a buffer keeps its seq while its sender writes on), nor while a PQ packet opened under the
						// session within idleTimeout: the init may be one its sender signed beside an unconfirmed PQ
						// session, held back on the way and let go now
						if init.seq <= info.initSeq || mgr._openedWithin(info, mgr.idleTimeout) {
							mgr._sendPQInfoDue(pub, askSigned)
							break
						}
						mgr._put(*pub, nil)
					}
					mgr._handleInit(pub, init)
				}
			}
			freeBytes(data)
		case sessionTypeAck:
			switch {
			case len(data) != sessionAckSize:
			case mgr.pqRefusesClassic(pub):
				mgr._replyPQInfo(pub)
			default:
				if ack := new(sessionAck); ack.decrypt(&mgr.pc.secretBox, pub, data, mgr.pc.groupAuth) {
					mgr._handleAck(pub, ack)
				}
			}
			freeBytes(data)
		case sessionTypeTraffic:
			mgr._handleTraffic(pub, data)
		case sessionTypePQInfo:
			if pq {
				mgr._handlePQInfo(pub, data)
			}
			freeBytes(data)
		case sessionTypePQInit, sessionTypePQAck:
			if pq {
				mgr._handlePQInit(pub, data, data[0] == sessionTypePQAck)
			}
			freeBytes(data)
		case sessionTypePQTraffic:
			if pq {
				mgr._handlePQTraffic(pub, data)
				break
			}
			// PQ off: from a peer whose PQ session with us we dropped (PQ turned off, or a restart without it), which
			// may never hear from us otherwise. A classic init in reply, as to classic traffic with no session: the
			// peer takes it once it holds us to PQ no longer. Upstream's nodes send no 0x13: to them, our replies are
			// upstream's
			if len(data) >= pqTrafficOverheadMin && mgr.sessions[*pub] == nil && mgr.pc.pq.initReplyDue(pub) {
				currentPub, _ := newBoxKeys()
				nextPub, _ := newBoxKeys()
				init := newSessionInit(&currentPub, &nextPub, 0)
				mgr.sendInit(pub, &init)
			}
			freeBytes(data)
		default:
		}
	})
}

func (mgr *sessionManager) _handleInit(pub *edPub, init *sessionInit) {
	if info, buf := mgr._sessionForInit(pub, init); info != nil {
		info.handleInit(mgr, init, nil)
		if buf != nil && buf.data != nil {
			info.doSend(mgr, buf.data)
		}
		mgr._maybeStartPQ(pub)
	}
}

func (mgr *sessionManager) _handleAck(pub *edPub, ack *sessionAck) {
	isOld := mgr._classic(pub) != nil
	if info, buf := mgr._sessionForInit(pub, &ack.sessionInit); info != nil {
		if isOld {
			info.handleAck(mgr, ack, nil)
		} else {
			info.handleInit(mgr, &ack.sessionInit, nil)
		}
		if buf != nil && buf.data != nil {
			info.doSend(mgr, buf.data)
		}
		mgr._maybeStartPQ(pub)
	}
}

func (mgr *sessionManager) _handleTraffic(pub *edPub, msg []byte) {
	if len(msg) < sessionTrafficOverheadMin {
		// too short to be traffic: no answer to it (an init or a PQInfo many times its size)
		freeBytes(msg)
		return
	}
	if info := mgr.sessions[*pub]; info != nil {
		required := mgr.pc.pq.required(pub)
		switch {
		case info.pq && info.fallback != nil && !info.confirmed.Load() && !required:
			// to the classic session beside a PQ one nothing opened under yet: the peer may not have the PQ one
			info.fallback.doRecv(mgr, msg)
			return
		case info.pq && info.fallback != nil && mgr._fallbackGrace(info) && !mgr.pc.pq.requiredByConfig(pub):
			// the PQ session confirmed here a moment ago, and the peer sends by the classic one still: it has not
			// opened a PQ packet of ours yet (a few ms behind, or ours held on the way). Taken for pqStaleGrace, or a
			// window of its data in flight is lost at the switch, and TCP over it stalls on its backoff (round 8c).
			// Only by the classic session of this pair, under its keys and replay window: nothing forged opens, and
			// nothing is downgraded (the hold the confirmation made refuses a new classic session)
			info.fallback.doRecv(mgr, msg)
			if mgr.pc.pq.initReplyDue(pub) {
				info.doSend(mgr, allocBytes(0)) // a PQ packet, to confirm the peer's session sooner
			}
			return
		case info.pq:
			if info.fallback != nil && required {
				// a key that must be PQ now (Required, or held to PQ): the classic session beside goes, not restored
				info.fallback = nil
			}
			// The peer sends by its classic session still: it has had no PQ packet of ours (we sent none since our
			// ack, which was lost), or went back to classic. Dropped, and an empty PQ packet in reply, at most once in
			// initReplyInterval: it confirms the peer's PQ session, or has the peer start a PQ init (_handlePQTraffic)
			if mgr.pc.pq.initReplyDue(pub) {
				info.doSend(mgr, allocBytes(0))
			}
			freeBytes(msg)
			return
		case !required:
			info.doRecv(mgr, msg)
			return
		}
		// a classic session of a key that must be PQ now (Required changed): it goes, as on our next write
		mgr._put(*pub, nil)
	}
	switch {
	case mgr.pc.pq.required(pub):
		// a PQ init of ours, its ML-KEM key known (a peer held to PQ that went back to classic, or lost its PQ
		// session: our PQInfo alone would not bring one, the peer may have the higher key and nothing waiting)
		if key := mgr.pc.pq.usableKey(pub); key == nil {
			mgr._replyPQInfo(pub)
		} else {
			mgr._replyPQInit(pub, key)
		}
	case !mgr.pc.pq.initReplyDue(pub):
		// one init in reply per initReplyInterval: every packet of a stream would send one
	default:
		// We don't know that the node really exists, it could be spoofed/replay
		// So we don't want to save session or a buffer based on this node
		// So we send an init with keys we'll forget
		// If they ack, we'll set up a session and let it self-heal...
		currentPub, _ := newBoxKeys()
		nextPub, _ := newBoxKeys()
		init := newSessionInit(&currentPub, &nextPub, 0)
		mgr.sendInit(pub, &init)
	}
	freeBytes(msg)
}

// _logClassicAsked: a key held to PQ (a PQ session was up with it) sent a classic init (checked first: of packets
// no one signed, nothing is logged): a line in the log, one a pqLogInterval for all keys. It may have turned its PQ
// sessions off, or restarted without them: it is refused until its hold ends.
func (mgr *sessionManager) _logClassicAsked(pub *edPub, init []byte) {
	s := &mgr.pc.pq
	if !s.logDue(&s.askedLogged) || !s.isSticky(pub) {
		return
	}
	if !new(sessionInit).decrypt(&mgr.pc.secretBox, pub, init, mgr.pc.groupAuth) {
		return
	}
	s.mu.Lock()
	k := s._held(pub)
	due := k != nil && s._due(&s.askedLogged)
	var until uint64
	if k != nil {
		until = k.until
	}
	s.mu.Unlock()
	if due {
		s.logf("PQ: a classic init from %x, held to PQ sessions (one was up with it): refused until %s; has it turned PQ sessions off?",
			pub[:8], time.Unix(int64(until), 0).UTC().Format(time.RFC3339))
	}
}

func (mgr *sessionManager) writeTo(toKey edPub, msg []byte) {
	// WARNING: unsafe to call from within an actor, must only be exposed over the PacketConn functions (which are, themselves, unsafe for actors to call in most cases, since they may block)
	phony.Block(mgr, func() {
		// a copy: the address of toKey itself would have the closure take it by reference (an allocation a write)
		toKey := toKey
		info := mgr.sessions[toKey]
		if info != nil && !info.pq && mgr.pc.pq.required(&toKey) {
			// the key became one that must be PQ (its node announced it): the classic session goes
			mgr._put(toKey, nil)
			info = nil
		}
		if info != nil && info.pq && info.fallback != nil {
			if info.confirmed.Load() || mgr.pc.pq.required(&toKey) {
				// our traffic by the PQ session now; the classic one kept for the peer's, for pqStaleGrace after
				// the confirmation (_fallbackGrace), then dropped
				if !mgr._fallbackGrace(info) {
					info.fallback = nil
				}
			} else {
				// nothing opened under the PQ session yet: traffic by the classic one, and a probe now and then
				info.fallback.doSend(mgr, msg)
				mgr._probe(info)
				return
			}
		}
		if info != nil {
			info.doSend(mgr, msg)
		} else {
			// Need to buffer the traffic
			mgr._bufferAndInit(toKey, msg)
		}
	})
}

func (mgr *sessionManager) _bufferAndInit(toKey edPub, msg []byte) {
	var buf *sessionBuffer
	if buf = mgr.buffers[toKey]; buf == nil {
		// Create a new buffer (including timer)
		buf = new(sessionBuffer)
		currentPub, currentPriv := newBoxKeys()
		nextPub, nextPriv := newBoxKeys()
		buf.init = newSessionInit(&currentPub, &nextPub, 0)
		buf.currentPriv = currentPriv
		buf.nextPriv = nextPriv
		buf.timer = time.AfterFunc(0, func() {})
		buf.since = time.Now()
		mgr.buffers[toKey] = buf
	}
	buf.data = msg
	buf.timer.Stop()
	if !mgr.pc.pq.required(&toKey) {
		mgr.sendInit(&toKey, &buf.init)
	} else if mgr.pc.pq.usableKey(&toKey) == nil && time.Since(buf.since) >= mgr.pc.pq.pendingTimeout {
		// it must be PQ, and no PQInfo of it came: no session. A line in the log, or nothing would tell why
		s := &mgr.pc.pq
		s.logEvery(&s.noPQLogged, "PQ: %x must be PQ, and no PQInfo of it came in %s: no session (it has no PQ sessions, or PQInfos are dropped on the way?)",
			toKey[:8], s.pendingTimeout)
	}
	mgr._maybeStartPQ(&toKey)
	buf.timer = time.AfterFunc(sessionTimeout, func() {
		mgr.Act(nil, func() {
			if b := mgr.buffers[toKey]; b == buf {
				b.timer.Stop()
				delete(mgr.buffers, toKey)
			}
		})
	})
}

// sendInit and sendAck send no classic init or ack to a key that must be PQ (the classic session beside a PQ one
// would, on traffic it cannot open)
func (mgr *sessionManager) sendInit(dest *edPub, init *sessionInit) {
	if mgr.pc.pq.required(dest) {
		return
	}
	if bs, err := init.encrypt(&mgr.pc.secretEd, dest, mgr.pc.groupAuth); err == nil {
		mgr.pc.writeRaw(bs, dest)
	}
}

func (mgr *sessionManager) sendAck(dest *edPub, ack *sessionAck) {
	if mgr.pc.pq.required(dest) {
		return
	}
	if bs, err := ack.encrypt(&mgr.pc.secretEd, dest, mgr.pc.groupAuth); err == nil {
		mgr.pc.writeRaw(bs, dest)
	}
}

/***************
 * sessionInfo *
 ***************/

type sessionInfo struct {
	phony.Inbox
	mgr            *sessionManager
	id             uint64 // its number in the process (_resetTimer)
	seq            uint64 // remote seq
	ed             edPub  // remote ed key
	remoteKeySeq   uint64 // signals rotation of current/next
	current        boxPub // send to this, expect to receive from it
	next           boxPub // if we receive from this, then rotate it to current
	localKeySeq    uint64 // signals rotation of recv/send/next
	recvPriv       boxPriv
	recvPub        boxPub
	recvShared     boxShared
	recvWindow     replayWindow
	sendPriv       boxPriv // becomes recvPriv when we ratchet forward
	sendPub        boxPub  // becomes recvPub
	sendShared     boxShared
	sendNonce      uint64
	nextPriv       boxPriv // becomes sendPriv
	nextPub        boxPub  // becomes sendPub
	timer          *time.Timer
	ack            *sessionAck
	since          time.Time
	rotated        time.Time // last time we rotated keys
	rx             uint64
	tx             uint64
	nextSendShared boxShared
	nextSendNonce  uint64
	nextRecvShared boxShared
	nextRecvNonce  uint64
	// a PQ session (pq_session.go): traffic of type sessionTypePQTraffic on keys from pqTrafficKey
	pq           bool
	peerSecret   ratchetSecret // the peer's, from its last init or ack: our traffic to it is keyed with it
	peerSecretNo uint64
	peerKey      *pqPeerKey    // the ML-KEM key its last init or ack came with
	own          []pqOwnSecret // ours that went in our inits and acks, the newest first
	keyGen       uint64        // counts _fixShared: the keys cached for an older count are stale
	sendAEAD     cipher.AEAD
	sendGen      uint64
	pqAck        *pqInit // as ack, for a repeat of the init it answers
	pqAckData    []byte  // it as sent: a repeat gets these bytes, not a new sealing
	reAckAt      time.Time
	lastOpened   time.Time
	stickyAt     time.Time    // the key marked sticky by traffic of this session, last (pq.now)
	sentAt       time.Time    // a PQ packet of ours sent under it, last
	seqCurrents  []boxPub     // R5-2: the peer's current keys of each init or ack taken at seq
	confirmed    atomic.Bool  // a PQ packet opened (read by the manager)
	confirmedAt  atomic.Int64 // then, first (pq.now, Unix nanoseconds; read by the manager: _fallbackGrace)
	openedAt     atomic.Int64 // then, last (pq.now, Unix nanoseconds; read by the manager)
	adBuf        [32]byte     // a PQ packet's header as associated data (Seal: not where the output goes)
	nonceBuf     [pqNonceSize]byte
	// the manager's: the classic session a PQ one of a key that may be classic replaced, kept and used until a PQ
	// packet opens (the peer may never have had the ack, or PQ packets be dropped on the way); a probe of ours, last;
	// the newest seq of a PQ init or ack passed to this session
	fallback *sessionInfo
	probeAt  time.Time
	initSeq  uint64
}

// pqOwnSecret is a ratchet secret of ours a peer may key its traffic to us with: the newest until a packet under it
// comes; older ones still sessionTimeout after that (packets reordered on the way). The peer names it by the low
// byte of its number (the epoch); the numbers are the process's, so two secrets of a session may share the byte,
// and each that does is tried.
type pqOwnSecret struct {
	secret    ratchetSecret
	no        uint64
	confirmed bool      // a packet under it came
	until     time.Time // zero: kept
	recv      [3]cipher.AEAD
	gen       uint64
}

const pqOwnSecretsMax = 4

func newSession(ed *edPub, current, next boxPub, seq uint64) *sessionInfo {
	info := new(sessionInfo)
	info.id = sessionIDs.Add(1)
	info.seq = seq - 1 // so the first update works
	info.ed = *ed
	info.current, info.next = current, next
	info.recvPub, info.recvPriv = newBoxKeys()
	info.sendPub, info.sendPriv = newBoxKeys()
	info.nextPub, info.nextPriv = newBoxKeys()
	info.since = time.Now()
	info._fixShared(0, 0)
	return info
}

// happens at session creation or after receiving an init/ack
func (info *sessionInfo) _fixShared(recvNonce, sendNonce uint64) {
	info.keyGen++
	getShared(&info.recvShared, &info.current, &info.recvPriv)
	getShared(&info.sendShared, &info.current, &info.sendPriv)
	getShared(&info.nextSendShared, &info.next, &info.sendPriv)
	getShared(&info.nextRecvShared, &info.next, &info.recvPriv)
	info.nextSendNonce, info.nextRecvNonce = 0, 0
	if recvNonce != 0 {
		// a ratchet step: the new receive key was the next key, taken up to recvNonce under a strict mark
		info.recvWindow.resetAt(recvNonce)
	} else {
		info.recvWindow.reset()
	}
	info.sendNonce = sendNonce
}

// _resetTimer: the session goes after idleTimeout with nothing under it. The timer holds its key and number, not the
// session: a timer stopped stays in the runtime's heap a while, and would hold a session pushed out (some 6.5 KB)
func (info *sessionInfo) _resetTimer() {
	if info.timer != nil {
		info.timer.Stop()
	}
	mgr, ed, id := info.mgr, info.ed, info.id
	info.timer = time.AfterFunc(mgr.idleTimeout, func() {
		mgr.Act(nil, func() {
			if s := mgr.sessions[ed]; s != nil && s.id == id {
				mgr._expire(s)
			}
		})
	})
}

// sessionIDs numbers the sessions of the process (sessionInfo.id)
var sessionIDs atomic.Uint64

// handleInit takes an init (pqi: it as a PQ init, nil for a classic one)
func (info *sessionInfo) handleInit(from phony.Actor, init *sessionInit, pqi *pqInit) {
	info.Act(from, func() {
		if init.seq < info.seq {
			return
		}
		// A PQ init of the same second as the last one taken, with other keys, is a new one of the peer's (it lost
		// the session and began anew within the second: the seq is in whole seconds), not a repeat: taken. One the
		// same (a repeat, or replayed) is not; no one else can sign one. Classic as upstream
		if init.seq == info.seq && (pqi == nil || info._seenAtSeq(&init.current)) {
			// The same init again: its sender has not had our ack, which may have gone out before we had a path back
			// (and the lookup for one was lost), or got lost on the way. Ignored, the contact would wait for this
			// session to time out. While nothing came from the sender over the session, the very ack of the first
			// time goes again (its traffic looks the path up anew): a sender with a session drops it by its seq and
			// keeps its keys. Once traffic came, the sender has the session, and a repeat is a replay: ignored.
			// At most once in half the sender's retry: a repeat costs it nothing, and the answer goes as the bytes
			// sealed the first time, not sealed anew.
			if info.rx != 0 || time.Since(info.reAckAt) < pqInitRetry/2 {
				return
			}
			info.reAckAt = time.Now()
			if info.pqAckData != nil {
				info.mgr.pc.writeRaw(info.pqAckData, &info.ed)
			} else if info.pqAck != nil {
				info.pqAckData = info.mgr.sendPQAck(&info.ed, info.pqAck, info.peerKey)
			} else if info.ack != nil {
				info.mgr.sendAck(&info.ed, info.ack)
			}
			return
		}
		info._handleUpdate(init, pqi, true)
		// Send a sessionAck
		info._sendAck()
	})
}

func (info *sessionInfo) handleAck(from phony.Actor, ack *sessionAck, pqi *pqInit) {
	info.Act(from, func() {
		// a PQ ack of the same second as the last init or ack taken, with other keys, is new, as for an init
		// (handleInit): the peer took an init of ours of that second, and its keys moved on
		if ack.seq < info.seq || (ack.seq == info.seq && (pqi == nil || info._seenAtSeq(&ack.current))) {
			return
		}
		info._handleUpdate(&ack.sessionInit, pqi, false)
	})
}

// _handleUpdate takes the peer's keys from an init or ack. A PQ one brings its ratchet secret too; one we answer
// (answering) gets a new secret of ours in the ack.
func (info *sessionInfo) _handleUpdate(init *sessionInit, pqi *pqInit, answering bool) {
	if pqi != nil {
		info.peerSecret, info.peerSecretNo, info.peerKey = pqi.secret, pqi.secretNo, pqi.senderKey
		if answering {
			info._newOwnSecret()
		}
	}
	info.current = init.current
	info.next = init.next
	if init.seq != info.seq {
		info.seqCurrents = info.seqCurrents[:0]
	}
	info.seqCurrents = append(info.seqCurrents, init.current)
	info.seq = init.seq
	info.remoteKeySeq = init.keySeq
	// Advance our keys, since this counts as a response
	info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
	info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
	info.nextPub, info.nextPriv = newBoxKeys()
	info.localKeySeq++
	// Don't roll back sendNonce, just to be extra safe
	old := info._replay()
	info._fixShared(0, info.sendNonce)
	info._carryReplay(&old)
	info._resetTimer()
}

// _seenAtSeq: an init or ack with current c was taken at info.seq already (R5-2: a replay, not new); past 8 of
// them, any is taken for one
func (info *sessionInfo) _seenAtSeq(c *boxPub) bool {
	if len(info.seqCurrents) >= 8 {
		return true
	}
	for i := range info.seqCurrents {
		if info.seqCurrents[i] == *c {
			return true
		}
	}
	return false
}

// sessionReplay: a session's receive keys and the replay state of each
type sessionReplay struct {
	recv, nextSend, nextRecv           boxShared
	window                             replayWindow
	nextSendNonce, nextRecvNonce, head uint64
}

func (info *sessionInfo) _replay() sessionReplay {
	return sessionReplay{
		recv: info.recvShared, nextSend: info.nextSendShared, nextRecv: info.nextRecvShared,
		window: info.recvWindow, nextSendNonce: info.nextSendNonce, nextRecvNonce: info.nextRecvNonce, head: info.recvWindow.head,
	}
}

// _carryReplay: after an init or ack of the peer's (_handleUpdate), each receive key that was one before keeps its
// replay state, or a packet seen under it would open again: an update that keeps the peer's keys moves ours on, and
// the send keys become receive ones, under which the peer's packets had a high-water mark of their nonces (classic
// and PQ alike; a key not seen before starts afresh). Upstream starts every key afresh here: a re-init of the peer's
// with its current keys opened again what it had sent under its next key (review R4-5)
func (info *sessionInfo) _carryReplay(old *sessionReplay) {
	seen := func(k *boxShared) (uint64, bool) {
		switch *k {
		case old.nextSend:
			return old.nextSendNonce, true
		case old.nextRecv:
			return old.nextRecvNonce, true
		case old.recv:
			return old.head, true
		}
		return 0, false
	}
	if info.recvShared == old.recv {
		info.recvWindow = old.window
	} else if n, ok := seen(&info.recvShared); ok {
		info.recvWindow.resetAt(n)
	}
	if n, ok := seen(&info.nextSendShared); ok {
		info.nextSendNonce = n
	}
	if n, ok := seen(&info.nextRecvShared); ok {
		info.nextRecvNonce = n
	}
}

func (info *sessionInfo) doSend(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		info._send(msg)
	})
}

func (info *sessionInfo) _send(msg []byte) {
	defer freeBytes(msg)
	info.sendNonce += 1 // Advance the nonce before anything else
	if info.sendNonce == 0 {
		// Nonce overflowed, so rotate keys
		info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
		info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
		info.nextPub, info.nextPriv = newBoxKeys()
		info.localKeySeq++
		info._fixShared(0, 0)
	}
	bs := allocBytes(pqTrafficOverhead + len(msg))
	defer freeBytes(bs)
	bs[0] = sessionTypeTraffic
	if info.pq {
		bs[0] = sessionTypePQTraffic
	}
	offset := 1
	offset += binary.PutUvarint(bs[offset:], info.localKeySeq)
	offset += binary.PutUvarint(bs[offset:], info.remoteKeySeq)
	offset += binary.PutUvarint(bs[offset:], info.sendNonce)
	if info.pq {
		// the epoch: which of the peer's secrets the key is from
		bs[offset] = byte(info.peerSecretNo)
		offset++
	}
	bs = bs[:offset]
	// We need to include info.nextPub below the layer of encryption
	// That way the remote side knows it's us when we send from it later...
	tmp := allocBytes(len(info.nextPub) + len(msg))[:0]
	tmp = append(tmp, info.nextPub[:]...)
	tmp = append(tmp, msg...)
	if info.pq {
		// the whole header is associated data: no number in it can be changed on the way
		ad := info.adBuf[:copy(info.adBuf[:], bs)]
		info.nonceBuf = pqNonce(info.sendNonce)
		bs = info._sendCipher().Seal(bs, info.nonceBuf[:], tmp, ad)
	} else {
		bs = boxSeal(bs, tmp, info.sendNonce, &info.sendShared)
	}
	freeBytes(tmp)
	// send
	info.mgr.pc.writeRaw(bs, &info.ed)
	info.tx += uint64(len(msg))
	if info.pq {
		info.sentAt = time.Now() // a PQ session is kept up by what opens under it (_expire), not by this
	} else {
		info._resetTimer()
	}
}

func (info *sessionInfo) doRecv(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		orig := msg
		defer freeBytes(orig)
		minSize, msgType := sessionTrafficOverheadMin, byte(sessionTypeTraffic)
		if info.pq {
			minSize, msgType = pqTrafficOverheadMin, sessionTypePQTraffic
		}
		if len(msg) < minSize || msg[0] != msgType {
			// a classic packet to a PQ session (sent before it took the classic one's place), or the reverse
			return
		}
		offset := 1
		remoteKeySeq, rksLen := binary.Uvarint(msg[offset:])
		if rksLen <= 0 {
			return
		}
		offset += rksLen
		localKeySeq, lksLen := binary.Uvarint(msg[offset:])
		if lksLen <= 0 {
			return
		}
		offset += lksLen
		nonce, nonceLen := binary.Uvarint(msg[offset:])
		if nonceLen <= 0 {
			return
		}
		offset += nonceLen
		var epoch byte
		if info.pq {
			if offset >= len(msg) {
				return
			}
			epoch = msg[offset]
			offset++
		}
		ad := orig[:offset] // a PQ packet's associated data: the header
		msg := msg[offset:]
		// The size check above counts a byte a varint, and Uvarint takes up to 10: the sealed part must still hold
		// the sender's next key, or opening it would slice that key out of less (a panic in this actor)
		if len(msg) < boxOverhead+boxPubSize {
			return
		}
		fromCurrent := remoteKeySeq == info.remoteKeySeq
		fromNext := remoteKeySeq == info.remoteKeySeq+1
		toRecv := localKeySeq+1 == info.localKeySeq
		toSend := localKeySeq == info.localKeySeq
		var sharedKey *boxShared
		var pqCase int
		var onSuccess func(boxPub)
		switch {
		case fromCurrent && toRecv:
			// The boring case, nothing to ratchet, just update nonce.
			// The replay window (rather than a strict high-water mark)
			// tolerates packets reordered in transit, at the cost of
			// tracking a bitmap of recent nonces.
			if !info.recvWindow.check(nonce) {
				return
			}
			sharedKey, pqCase = &info.recvShared, 0
			onSuccess = func(_ boxPub) {
				// Commit only after the packet has decrypted, so a
				// corrupted packet cannot burn a window slot.
				info.recvWindow.commit(nonce)
			}
		case fromNext && toSend:
			// The remote side appears to have ratcheted forward
			if !(info.nextSendNonce < nonce) {
				return
			}
			sharedKey, pqCase = &info.nextSendShared, 1
			onSuccess = func(innerKey boxPub) {
				info.nextSendNonce = nonce
				if info.rotated.IsZero() || time.Since(info.rotated) > time.Minute {
					// Rotate their keys
					info.current = info.next
					info.next = innerKey
					info.remoteKeySeq++ // = remoteKeySeq
					// Rotate our own keys
					info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
					info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
					info.localKeySeq++
					// Generate new next keys
					info.nextPub, info.nextPriv = newBoxKeys()
					// Update nonces
					info._fixShared(info.nextSendNonce, 0)
					info.rotated = time.Now()
				}
			}
		case fromNext && toRecv:
			// The remote side appears to have ratcheted forward early
			// Technically there's no reason we can't handle this
			//panic("DEBUG") // TODO test this
			if !(info.nextRecvNonce < nonce) {
				return
			}
			sharedKey, pqCase = &info.nextRecvShared, 2
			onSuccess = func(innerKey boxPub) {
				info.nextRecvNonce = nonce
				if info.rotated.IsZero() || time.Since(info.rotated) > time.Minute {
					// Rotate their keys
					info.current = info.next
					info.next = innerKey
					info.remoteKeySeq++ // = remoteKeySeq
					// Rotate our own keys
					info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
					info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
					info.localKeySeq++
					// Generate new next keys
					info.nextPub, info.nextPriv = newBoxKeys()
					// Update nonces
					info._fixShared(info.nextSendNonce, 0)
					info.rotated = time.Now()
				}
			}
		default:
			// We can't make sense of their message
			// Send a sessionInit and hope they ack so we can fix things
			info._sendInitFailed()
			return
		}
		// Decrypt and handle packet
		unboxed, ok := allocBytes(0), false
		defer func() { freeBytes(unboxed) }()
		if info.pq {
			var stale bool
			unboxed, ok, stale = info._openPQ(unboxed, msg, ad, nonce, epoch, pqCase, sharedKey, remoteKeySeq, localKeySeq)
			if stale {
				// under a secret of ours no longer kept: one late packet is dropped without a word (an init would
				// renegotiate the keys); a peer that keeps to it while nothing opens gets an init, as on a failure
				if time.Since(info.lastOpened) >= pqStaleGrace {
					info._sendInitDue()
				}
				return
			}
		} else {
			unboxed, ok = boxOpen(unboxed, msg, nonce, sharedKey)
		}
		if ok {
			var key boxPub
			copy(key[:], unboxed)
			msg := append(allocBytes(0), unboxed[len(key):]...)
			if info.pq && len(msg) == 0 {
				// a probe (_probe): it confirms the session, and is not a message
				freeBytes(msg)
			} else {
				info.mgr.pc.network.recv(info, msg)
			}
			// Misc remaining followup work
			onSuccess(key)
			info.rx += uint64(len(msg))
			info._resetTimer()
			if info.pq {
				// traffic opened under keys from a verified PQ init or ack: a PQ session, both ends, and the key is held
				// to PQ (before confirmed, which the manager reads first). Raised in the sticky LRU again at most once
				// in pqStickyRefresh, so that keys with a packet each do not push out a peer with traffic all along
				// (a packet replayed does not get here: the replay window, carried over the session's re-inits
				// (_carryReplay), turned it away before it was opened). The hold is by the ML-KEM key the session is
				// under, which a key of the peer's in the table, newer, does not move on (markSticky)
				now := info.mgr.pc.pq.now()
				if info.stickyAt.IsZero() || now.Sub(info.stickyAt) >= pqStickyRefresh {
					info.stickyAt = now
					var notAfter uint64
					if info.peerKey != nil {
						notAfter = info.peerKey.notAfter
					}
					info.mgr.pc.pq.markSticky(&info.ed, notAfter, true)
				}
				info.openedAt.Store(now.UnixNano())
				if !info.confirmed.Load() {
					info.confirmedAt.Store(now.UnixNano()) // before confirmed, which the manager reads first
					info.confirmed.Store(true)
				}
				info.lastOpened = time.Now()
				// The peer's session is kept up by what opens under it there: traffic of ours, or, while we only
				// read (a one-way flow), an empty packet once we sent nothing for a quarter of idleTimeout (one
				// lost, the next still comes in time). A peer that turned PQ off sends nothing that opens here, and
				// gets none: its silence still ends our session
				last := info.sentAt
				if last.Before(info.since) {
					last = info.since
				}
				if time.Since(last) >= info.mgr.idleTimeout/4 {
					info._send(allocBytes(0))
				}
			}
		} else {
			// Keys somehow became out-of-sync
			// This seems to happen in some edge cases if a node restarts
			// Fix by sending a new init
			info._sendInitFailed()
		}
	})
}

func (info *sessionInfo) _sendInit() {
	if info.pq {
		if len(info.own) == 0 {
			return // no secret of ours yet (the session waits for its handshake): nothing to init with
		}
		// our newest secret again: a re-init keeps it (the peer may key to it already)
		own := info.own[0]
		init := newPQInit(&info.sendPub, &info.nextPub, info.localKeySeq, &own.secret, own.no)
		info.mgr.sendPQInit(&info.ed, &init, info.peerKey)
		return
	}
	init := newSessionInit(&info.sendPub, &info.nextPub, info.localKeySeq)
	info.mgr.sendInit(&info.ed, &init)
}

// _sendInitFailed: an init in reply to a packet of the peer's that did not open (keys out of step), as
// _sendInitDue. Not from a PQ session under which a packet opened within pqStaleGrace: that one is in step, and the
// packet is not one of the peer's now (forged, or late from before a re-init); each would have us seal and send a PQ
// re-init (2.5 KB) to the peer for some 53 B that anyone can send, outside the bucket of the other answers to a
// packet no one signed (R7-2). A session that is out of step opens nothing, and its re-init goes once that is so.
func (info *sessionInfo) _sendInitFailed() {
	if info.pq && !info.lastOpened.IsZero() && time.Since(info.lastOpened) < pqStaleGrace {
		return
	}
	info._sendInitDue()
}

// _sendInitDue: an init in reply to the peer's traffic, at most once in initReplyInterval
func (info *sessionInfo) _sendInitDue() {
	if info.mgr.pc.pq.initReplyDue(&info.ed) {
		info._sendInit()
	}
}

func (info *sessionInfo) _sendAck() {
	if info.pq {
		if len(info.own) == 0 {
			return
		}
		own := info.own[0]
		ack := newPQInit(&info.sendPub, &info.nextPub, info.localKeySeq, &own.secret, own.no)
		info.pqAck = &ack // sent again, the same, to a repeat of the init it answers (handleInit)
		info.pqAckData = info.mgr.sendPQAck(&info.ed, &ack, info.peerKey)
		info.reAckAt = time.Now()
		return
	}
	init := newSessionInit(&info.sendPub, &info.nextPub, info.localKeySeq)
	ack := sessionAck{init}
	info.ack = &ack // sent again, the same, to a repeat of the init it answers (handleInit)
	info.mgr.sendAck(&info.ed, &ack)
}

/*********************
 * PQ session's keys *
 *********************/

// _newOwnSecret: a new ratchet secret of ours, for the ack about to go. The one before stays (the peer keys to it
// until the ack comes); one never confirmed is dropped once pqOwnSecretsMax are kept.
func (info *sessionInfo) _newOwnSecret() {
	fresh := pqOwnSecret{secret: newRatchetSecret(), no: info.mgr.pc.pq.nextSecretNo()}
	info.own = append([]pqOwnSecret{fresh}, info.own...)
	if len(info.own) > pqOwnSecretsMax {
		info.own = info.own[:pqOwnSecretsMax]
	}
}

func (info *sessionInfo) _sendCipher() cipher.AEAD {
	if info.sendAEAD == nil || info.sendGen != info.keyGen {
		ourEd := &info.mgr.pc.publicEd
		info.sendAEAD = pqTrafficKey(&info.sendShared, &info.peerSecret, ourEd, &info.ed, info.localKeySeq, info.remoteKeySeq)
		info.sendGen = info.keyGen
	}
	return info.sendAEAD
}

// _openPQ opens a PQ packet under the secret of ours its epoch byte names (each kept one with that byte is tried).
// stale: none kept has it. A packet under a secret confirms it, and starts the time the older ones are kept.
func (info *sessionInfo) _openPQ(out, msg, ad []byte, nonce uint64, epoch byte, pqCase int, shared *boxShared, fromKeySeq, toKeySeq uint64) ([]byte, bool, bool) {
	now := time.Now()
	info.nonceBuf = pqNonce(nonce)
	n := info.nonceBuf[:]
	stale := true
	for i := range info.own {
		own := &info.own[i]
		if byte(own.no) != epoch || (!own.until.IsZero() && now.After(own.until)) {
			continue
		}
		stale = false
		if own.gen != info.keyGen {
			own.recv, own.gen = [3]cipher.AEAD{}, info.keyGen
		}
		if own.recv[pqCase] == nil {
			own.recv[pqCase] = pqTrafficKey(shared, &own.secret, &info.ed, &info.mgr.pc.publicEd, fromKeySeq, toKeySeq)
		}
		opened, err := own.recv[pqCase].Open(out, n, msg, ad)
		if err != nil {
			continue
		}
		if !own.confirmed {
			own.confirmed = true
			for j := i + 1; j < len(info.own); j++ {
				if info.own[j].until.IsZero() {
					info.own[j].until = now.Add(sessionTimeout)
				}
			}
		}
		return opened, true, false
	}
	return out, false, stale
}

/***************
 * sessionInit *
 ***************/

type sessionInit struct {
	current boxPub
	next    boxPub
	keySeq  uint64
	seq     uint64 // timestamp or similar
}

func newSessionInit(current, next *boxPub, keySeq uint64) sessionInit {
	var init sessionInit
	init.current = *current
	init.next = *next
	init.keySeq = keySeq
	init.seq = uint64(time.Now().Unix())
	return init
}

func (init *sessionInit) encrypt(from *edPriv, to *edPub, auth groupAuth) ([]byte, error) {
	fromPub, fromPriv := newBoxKeys()
	var toBox *boxPub
	var err error
	if toBox, err = to.toBox(); err != nil {
		return nil, err
	}
	// Get sig bytes
	var sigBytes []byte // TODO initialize to correct size
	sigBytes = append(sigBytes, fromPub[:]...)
	sigBytes = append(sigBytes, init.current[:]...)
	sigBytes = append(sigBytes, init.next[:]...)
	offset := len(sigBytes)
	sigBytes = sigBytes[:offset+8]
	binary.BigEndian.PutUint64(sigBytes[offset:offset+8], init.keySeq)
	offset = len(sigBytes)
	sigBytes = sigBytes[:offset+8]
	binary.BigEndian.PutUint64(sigBytes[offset:offset+8], init.seq)
	// Sign
	sig := edSign(sigBytes, from, auth.preimage())
	// Prepare the payload (to be encrypted)
	var payload []byte // TODO initialize to correct size
	payload = append(payload, sig[:]...)
	payload = append(payload, sigBytes[boxPubSize:]...)
	// Encrypt
	var shared boxShared
	getShared(&shared, toBox, &fromPriv)
	bs := boxSeal(nil, payload, 0, &shared)
	// Assemble final message
	data := make([]byte, 1, sessionInitSize)
	data[0] = sessionTypeInit
	data = append(data, fromPub[:]...)
	data = append(data, bs...)
	if len(data) != sessionInitSize {
		panic("this should never happen")
	}
	return data, nil
}

func (init *sessionInit) decrypt(priv *boxPriv, from *edPub, data []byte, auth groupAuth) bool {
	if len(data) != sessionInitSize {
		return false
	}
	var fromBox boxPub
	offset := 1
	offset = bytesPop(fromBox[:], data, offset)
	bs := data[offset:]
	var shared boxShared
	getShared(&shared, &fromBox, priv)
	var payload []byte
	var ok bool
	if payload, ok = boxOpen(nil, bs, 0, &shared); !ok {
		return false
	}
	offset = 0
	var sig edSig
	offset = bytesPop(sig[:], payload, offset)
	tmp := payload[offset:] // Used in sigBytes
	offset = bytesPop(init.current[:], payload, offset)
	offset = bytesPop(init.next[:], payload, offset)
	init.keySeq = binary.BigEndian.Uint64(payload[offset : offset+8])
	offset += 8
	init.seq = binary.BigEndian.Uint64(payload[offset:])
	if init.seq == 0 {
		// a session's seq is the time it began: 0 is no one's, and seq-1 of a new session would wrap to the top
		return false
	}
	// Check signature
	var sigBytes []byte
	sigBytes = append(sigBytes, fromBox[:]...)
	sigBytes = append(sigBytes, tmp...)
	return edCheck(sigBytes, &sig, from, auth.preimage())
}

/**************
 * sessionAck *
 **************/

type sessionAck struct {
	sessionInit
}

func (ack *sessionAck) encrypt(from *edPriv, to *edPub, auth groupAuth) ([]byte, error) {
	data, err := ack.sessionInit.encrypt(from, to, auth)
	if err == nil {
		data[0] = sessionTypeAck
	}
	return data, err
}

/*****************
 * sessionBuffer *
 *****************/

type sessionBuffer struct {
	data        []byte
	init        sessionInit
	currentPriv boxPriv     // pairs with init.recv
	nextPriv    boxPriv     // pairs with init.send
	timer       *time.Timer // time.AfterFunc to clean up
	since       time.Time   // made then
}
