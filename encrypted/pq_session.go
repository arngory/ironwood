package encrypted

import (
	"bytes"
	"crypto/hpke"
	"encoding/binary"
	"time"
)

// The packet types of PQ sessions, apart from the classic ones (0-3, unchanged byte for byte): a node without them
// drops them silently (handleData, default), and they stay clear of the numbers upstream's PR 48 takes (3, 4).
const (
	sessionTypePQInfo    = 0x10
	sessionTypePQInit    = 0x11
	sessionTypePQAck     = 0x12
	sessionTypePQTraffic = 0x13
)

const (
	pqInitPayloadSize = edSigSize + pqPubSize + 8 + 8 + ratchetSecretSize + 8 + boxPubSize + boxPubSize + 8 + 8
	sessionPQInitSize = 1 + 8 + hpkeOverhead + pqInitPayloadSize
	// header, the three numbers, the epoch byte; the inner next key
	pqTrafficOverheadMin = 1 + 1 + 1 + 1 + 1 + pqAEADOverhead + boxPubSize
	pqTrafficOverhead    = pqTrafficOverheadMin + 9 + 9 + 9
)

/**********
 * pqInit *
 **********/

// pqInit is a PQ init or ack: the classic fields, the sender's ML-KEM key (to seal the answer to), and the sender's
// ratchet secret with its number, which the traffic to the sender is keyed with.
type pqInit struct {
	sessionInit
	senderPQ       pqPub
	senderSeq      uint64
	senderNotAfter uint64
	secret         ratchetSecret
	secretNo       uint64
	senderKey      *pqPeerKey // the sender's key above, as the answer is sealed to it (not on the wire)
}

func newPQInit(current, next *boxPub, keySeq uint64, secret *ratchetSecret, secretNo uint64) pqInit {
	return pqInit{sessionInit: newSessionInit(current, next, keySeq), secret: *secret, secretNo: secretNo}
}

func (init *pqInit) fields() []byte {
	out := make([]byte, 0, pqInitPayloadSize-edSigSize)
	out = append(out, init.senderPQ[:]...)
	out = binary.BigEndian.AppendUint64(out, init.senderSeq)
	out = binary.BigEndian.AppendUint64(out, init.senderNotAfter)
	out = append(out, init.secret[:]...)
	out = binary.BigEndian.AppendUint64(out, init.secretNo)
	out = append(out, init.current[:]...)
	out = append(out, init.next[:]...)
	out = binary.BigEndian.AppendUint64(out, init.keySeq)
	return binary.BigEndian.AppendUint64(out, init.seq)
}

// encrypt seals the init (or ack, by msgType) to the recipient's ML-KEM key to, signed with this node's key over
// the binding to the recipient and all the fields.
func (init *pqInit) encrypt(pc *PacketConn, msgType byte, toEd *edPub, to *pqPeerKey) ([]byte, error) {
	own := pc.pqOwn()
	init.senderPQ, init.senderSeq, init.senderNotAfter = own.pub, own.seq, own.notAfter
	fields := init.fields()
	signed := append(pqBinding(pqInitSigCtx, msgType, &pc.publicEd, toEd, to.seq, &to.hash), fields...)
	sig := edSign(signed, &pc.secretEd, pc.groupAuth.preimage())
	payload := append(sig[:], fields...)
	info := pqBinding(pqHPKEInfo, msgType, &pc.publicEd, toEd, to.seq, &to.hash)
	key, err := to.hpkeKey()
	if err != nil {
		return nil, err
	}
	sealed, err := hpke.Seal(key, pqKDF, pqAEAD, info, payload)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, sessionPQInitSize)
	data = append(data, msgType)
	data = binary.BigEndian.AppendUint64(data, to.seq)
	data = append(data, sealed...)
	if len(data) != sessionPQInitSize {
		panic("this should never happen")
	}
	return data, nil
}

// decrypt opens a PQ init or ack from from. unknownKey: it is sealed to an ML-KEM key of ours no longer taken (or
// never ours), so the sender needs our PQInfo.
func (init *pqInit) decrypt(pc *PacketConn, from *edPub, data []byte) (ok, unknownKey bool) {
	if len(data) != sessionPQInitSize {
		return false, false
	}
	msgType, seq := data[0], binary.BigEndian.Uint64(data[1:9])
	own := pc.pqOwnFor(seq)
	if own == nil {
		return false, true
	}
	info := pqBinding(pqHPKEInfo, msgType, from, &pc.publicEd, seq, &own.hash)
	payload, err := hpke.Open(own.hpke, pqKDF, pqAEAD, info, data[9:])
	if err != nil || len(payload) != pqInitPayloadSize {
		return false, false
	}
	var sig edSig
	offset := bytesPop(sig[:], payload, 0)
	offset = bytesPop(init.senderPQ[:], payload, offset)
	init.senderSeq = binary.BigEndian.Uint64(payload[offset:])
	init.senderNotAfter = binary.BigEndian.Uint64(payload[offset+8:])
	offset = bytesPop(init.secret[:], payload, offset+16)
	init.secretNo = binary.BigEndian.Uint64(payload[offset:])
	offset = bytesPop(init.current[:], payload, offset+8)
	offset = bytesPop(init.next[:], payload, offset)
	init.keySeq = binary.BigEndian.Uint64(payload[offset:])
	init.seq = binary.BigEndian.Uint64(payload[offset+8:])
	if init.seq == 0 {
		return false, false // no session began at 0 (see sessionInit.decrypt)
	}
	signed := append(pqBinding(pqInitSigCtx, msgType, from, &pc.publicEd, seq, &own.hash), payload[edSigSize:]...)
	return edCheck(signed, &sig, from, pc.groupAuth.preimage()), false
}

/*************************
 * the session manager's *
 *************************/

// pqPending is a PQ init this node started (data waiting, or a classic session to replace), kept until its ack or
// sessionTimeout, and sent again every pqInitRetry.
type pqPending struct {
	init        pqInit
	currentPriv boxPriv
	nextPriv    boxPriv
	key         *pqPeerKey // the peer's ML-KEM key it is sealed to
	data        []byte     // it, sealed
	first       time.Time  // the first send under key
	tries       int        // sends under key
	timer       *time.Timer
	// once: sent in reply to a packet no one signed, not again on its own (_replyPQInit): each retry would be 2.5 KB
	// out for the one packet
	once     bool
	resentAt time.Time // once: sent again to a crossing init of the peer's, last (R6A-4)
}

// pqRefusesClassic: classic init, ack and traffic from key are dropped (it must be PQ, or a PQ session with it is up)
func (mgr *sessionManager) pqRefusesClassic(key *edPub) bool {
	if !mgr.pc.pq.enabled() {
		return false
	}
	if info := mgr.sessions[*key]; info != nil && info.pq && info.confirmed.Load() {
		return true
	}
	return mgr.pc.pq.required(key)
}

func (mgr *sessionManager) sendPQInfo(dest *edPub) {
	mgr.pc.writeRaw(mgr.pc.pqOwn().info, dest)
}

// _sendPQInfoDue: our PQInfo to dest, if none went in pqInfoInterval and a token is there where ask says (infoDue);
// starved: none went for want of a token
func (mgr *sessionManager) _sendPQInfoDue(dest *edPub, ask pqAsk) (starved bool) {
	due, starved := mgr.pc.pq.infoDue(dest, ask)
	if due {
		mgr.sendPQInfo(dest)
	}
	return starved
}

// _replyPQInfo: our PQInfo in reply to a packet no one signed, claimed from dest: with a token, of the bucket of keys
// unknown here or of known ones
func (mgr *sessionManager) _replyPQInfo(dest *edPub) {
	mgr._sendPQInfoDue(dest, askUnsigned)
}

func (mgr *sessionManager) _handlePQInfo(pub *edPub, data []byte) {
	var pq sessionPQInfo
	if !pq.decode(pub, data, mgr.pc.groupAuth) {
		return
	}
	accepted, _ := mgr.pc.pq.accept(pub, &pq.pub, pq.seq, pq.notAfter)
	// an answer, so that the sender knows our key too (it may have lost it): limited, or two nodes would ping-pong
	// (pqInfoInterval, and pqInfoAnswerEvery for these answers: a slow path ping-pongs past the first, P-2)
	if mgr.pc.pq.answerRoom(pub) {
		// the burst's slot spent on an answer that went, not on one infoDue held back (round 8d)
		if due, _ := mgr.pc.pq.infoDue(pub, askSigned); due {
			mgr.pc.pq.answerSpent(pub)
			mgr.sendPQInfo(pub)
		}
	}
	if !accepted {
		return
	}
	if p := mgr.pqPending[*pub]; p != nil {
		mgr._resealPending(pub, p)
		return
	}
	mgr._maybeStartPQ(pub)
}

// _resealPending: p sealed to a key of the peer that is no longer the table's (a newer one came in a PQInfo or in its
// own init) goes again, to the table's
func (mgr *sessionManager) _resealPending(pub *edPub, p *pqPending) {
	if k := mgr.pc.pq.usableKey(pub); k != nil && k != p.key {
		p.key, p.data, p.tries, p.first = k, nil, 0, time.Time{}
		mgr._sendPending(pub, p)
	}
}

// _maybeStartPQ starts a PQ init to pub where one is wanted and none is under way: data is waiting for a session, or
// a classic session is up (that one replaced, started by the end with the lower key; the other sends its PQInfo, so
// that the first knows its key). With PQConfig.SessionMax PQ sessions up, a key that may be classic stays classic.
func (mgr *sessionManager) _maybeStartPQ(pub *edPub) {
	if !mgr.pc.pq.enabled() {
		return
	}
	_, buffered := mgr.buffers[*pub]
	info := mgr.sessions[*pub]
	if p := mgr.pqPending[*pub]; p != nil {
		if p.once && (buffered || (info != nil && !info.pq && mgr.pc.pq.initiates(pub))) {
			// one sent in reply to a packet no one signed, and a trigger of ours wants one now (data of ours waits
			// for it, or a classic session to replace: a signed handshake, our retry; not in answer only): sent again
			// until its ack, and its expiry schedules the retry, as for one we started. Left once, it would swallow
			// the trigger, and its expiry schedules nothing (R6A-2). A packet no one signed alone still starts no
			// retries (R3-4)
			p.once = false
			mgr._sendPending(pub, p)
		}
		return
	}
	if !mgr.pc.pq.initiates(pub) {
		return // answer only: neither our PQ init nor our PQInfo, which would have the peer start one
	}
	if info != nil && info.pq {
		return
	}
	if !buffered && info == nil {
		return
	}
	if mgr._pqStartFull(pub) {
		if info != nil {
			mgr._upgradeLater(*pub) // tried again later, once the table may have room (R6A-1: else classic for good)
		}
		return // nor our PQInfo, which would have the peer start one
	}
	key := mgr.pc.pq.usableKey(pub)
	if key == nil || (!buffered && bytes.Compare(mgr.pc.publicEd[:], pub[:]) > 0) {
		ask := askSigned // after a handshake of the peer's, or our retry
		if buffered {
			ask = askOwn
		}
		if mgr._sendPQInfoDue(pub, ask) && info != nil {
			mgr._upgradeLater(*pub) // no token for our PQInfo now: the upgrade tried again later, not dropped
		} else if key == nil && info != nil {
			mgr._askPQInfoAgain(*pub) // its answer may be lost: asked again, a few times (round 8b)
		}
		if key != nil && info != nil {
			mgr._awaitPQInit(*pub)
		}
		return
	}
	mgr._startPQ(pub, key, false)
}

// _awaitPQInit: the peer, with the lower key and its ML-KEM key known here, is to start the PQ init that replaces the
// classic session. None in awaitStart (a few init retries): this end sends its own. The peer may be in answer only,
// which never starts one (PQConfig.AnswerOnly: a node that leaves the start to its clients), or our PQInfos do not
// reach it; crossing inits are settled as ever (the lower key's goes on). Where this end cannot start one (no room,
// or the peer's key no longer usable), the upgrade is tried again after upgradeRetry, and a line in the log once
// pendingTimeout passed with the session still classic. Before round 8 this end only waited, and an answer-only
// peer with the lower key left the session classic for good.
func (mgr *sessionManager) _awaitPQInit(pub edPub) {
	if mgr.pqAwait[pub] {
		return
	}
	mgr.pqAwait[pub] = true
	time.AfterFunc(mgr.pc.pq.awaitStart, func() {
		mgr.Act(nil, func() {
			delete(mgr.pqAwait, pub)
			info := mgr.sessions[pub]
			if info == nil || info.pq || !mgr.pc.pq.initiates(&pub) {
				return
			}
			if p := mgr.pqPending[pub]; p != nil {
				if p.once {
					// a once-init (sent in reply to a packet no one signed) stands where ours would: it is not sent
					// again and its expiry schedules nothing, so one lost would leave the session classic. Sent
					// again until its ack, as _maybeStartPQ does for one (R6A-2; round 8d)
					p.once = false
					mgr._sendPending(&pub, p)
				}
				return
			}
			if key := mgr.pc.pq.usableKey(&pub); key != nil && !mgr._pqStartFull(&pub) {
				mgr._startPQ(&pub, key, false)
				return
			}
			// no room, or the peer's key no longer usable: tried again later, not dropped
			mgr._upgradeLater(pub)
			time.AfterFunc(mgr.pc.pq.pendingTimeout, func() {
				mgr.Act(nil, func() {
					if info := mgr.sessions[pub]; info != nil && !info.pq && mgr.pqPending[pub] == nil {
						mgr.pc.pq.logStripped(&pub, "no PQ init of it came to our PQInfo", "the session stays classic")
					}
				})
			})
		})
	})
}

// pqAskState: our PQInfos again to a peer with a classic session whose ML-KEM key we lack (_askPQInfoAgain)
type pqAskState struct {
	tries     int  // sent again so far
	waiting   bool // one is due
	exhausted bool // pqAskTries went unanswered: asked no more until the peer's next handshake (round 9)
}

// _askPQInfoAgain: a classic session up, PQ wanted, and the peer's ML-KEM key not known here: our PQInfo goes again
// after pqInfoInterval, then twice and four times that, pqAskTries in all, until its key comes (its PQInfo answers
// ours) or a PQ session is up. All unanswered, the peer most likely has no PQ: it is asked no more until its next
// handshake (round 9; before, a round again every upgradeRetry, some 5 KB in 5 minutes to each such peer). The price:
// a peer with PQ that lost all three answers stays classic until that handshake, not for upgradeRetry. The peer's
// answer may be lost:
// while a node finds the path to us one packet is held for us, and its PQInfo can give way to the packet of the
// classic session that went with it. Before round 8b nothing asked again, and a peer in answer only, which starts
// nothing, left the session classic.
func (mgr *sessionManager) _askPQInfoAgain(pub edPub) {
	a := mgr.pqAsk[pub]
	if a == nil {
		a = &pqAskState{}
		mgr.pqAsk[pub] = a
	}
	if a.waiting || a.exhausted {
		return
	}
	if a.tries >= pqAskTries {
		a.exhausted = true
		return
	}
	a.waiting = true
	time.AfterFunc(pqInfoInterval<<a.tries, func() {
		mgr.Act(nil, func() {
			a.waiting = false
			a.tries++
			info := mgr.sessions[pub]
			if info == nil || info.pq || mgr.pqPending[pub] != nil || mgr.pc.pq.usableKey(&pub) != nil {
				if mgr.pqAsk[pub] == a {
					delete(mgr.pqAsk, pub) // ours only: a newer entry of a session since has its own timer (round 9)
				}
				return
			}
			mgr._maybeStartPQ(&pub) // our PQInfo again (its interval passed), and the next ask
			if !a.waiting && !a.exhausted && mgr.pqAsk[pub] == a {
				// _maybeStartPQ asked nothing again (no token for our PQInfo, no room, PQ off or in answer only
				// now): the entry goes, or it would stay for good (round 8d)
				delete(mgr.pqAsk, pub)
			}
		})
	})
}

// _pqStartFull: this node starts no PQ session with pub: SessionMax PQ sessions are up, and pub may be classic. A
// key held to PQ gets one all the same (there are at most pqStickyMax, and room is made for each under the hard
// limit, _pqRoom). A line in the log, one a pqLogInterval.
func (mgr *sessionManager) _pqStartFull(pub *edPub) bool {
	most := mgr.pc.pq.sessionMax()
	if int(mgr.pqCount.Load()) < most || mgr.pc.pq.required(pub) {
		return false
	}
	s := &mgr.pc.pq
	s.logEvery(&s.fullLogged, "PQ: %d PQ sessions up (PQConfig.SessionMax): none started with %x, it stays classic (one it starts it gets)", most, pub[:8])
	return true
}

// _pqRoom: room for a new PQ session with pub under the hard limit (hardMax). At it, a PQ session goes: one nothing
// opened under yet first; then, of the confirmed ones, one of a key that may be classic, nothing opened under it in
// evictIdle (10 s); one of a key held to PQ only after every other, and only once nothing opened under it in
// idleTimeout (a held peer's session is kept while it is alive). Within each, the one nothing opened under for the
// longest (or started first) goes; its classic one takes its place where there is one. Every one in use: no room
// (pub gets a classic session if it may be classic, none if not). A line in the log either way.
func (mgr *sessionManager) _pqRoom(pub *edPub) bool {
	most := mgr.pc.pq.hardMax()
	if int(mgr.pqCount.Load()) < most {
		return true
	}
	now := mgr.pc.pq.now().UnixNano()
	var victim *sessionInfo
	var victimRank [3]int64 // confirmed, held to PQ, the last packet opened (or the start): the least goes
	for k, info := range mgr.sessions {
		if !info.pq {
			continue
		}
		confirmed := info.confirmed.Load()
		if at := info.openedAt.Load(); confirmed && at != 0 && now-at < int64(mgr.evictIdle) {
			continue // in use, held or not (idleTimeout >= evictIdle): no Required call (R5 scan)
		}
		held := mgr.pc.pq.required(&k)
		rank := [3]int64{0, 0, info.since.UnixNano()}
		if held {
			rank[1] = 1
		}
		if confirmed {
			floor := mgr.evictIdle
			if held {
				floor = mgr.idleTimeout
			}
			if mgr._openedWithin(info, floor) {
				continue // in use
			}
			rank[0], rank[2] = 1, info.openedAt.Load()
		}
		if victim == nil || rank[0] < victimRank[0] || (rank[0] == victimRank[0] && (rank[1] < victimRank[1] || (rank[1] == victimRank[1] && rank[2] < victimRank[2]))) {
			victim, victimRank = info, rank
		}
	}
	s := &mgr.pc.pq
	if victim == nil {
		s.logEvery(&s.refusedLogged, "PQ: %d PQ sessions up, the most held, each in use: %x gets no new one (classic if it may be)", most, pub[:8])
		return false
	}
	then := mgr._evict(victim)
	s.logEvery(&s.hardLogged, "PQ: %d PQ sessions up, the most held: the one of %x, nothing opened under it for the longest, made room (%s)",
		most, victim.ed[:8], then)
	return true
}

// _pqHardFull: the hard limit is reached, for an answer to a packet no one signed (a line in the log, naming no key)
func (mgr *sessionManager) _pqHardFull() bool {
	most := mgr.pc.pq.hardMax()
	if int(mgr.pqCount.Load()) < most {
		return false
	}
	s := &mgr.pc.pq
	s.logEvery(&s.refusedLogged, "PQ: %d PQ sessions up, the most held: no PQ init in answer to PQ traffic", most)
	return true
}

// _replyPQInit: a PQ init of ours in reply to a packet no one signed, claimed from pub (its ML-KEM key, key, known):
// once in initReplyInterval, with a token of the known bucket, and sent once, not retried; the peer's next packet
// brings it again (the same bytes, while it is pending). The peer wants a session (PQ traffic of its, or a classic
// packet of a key held to PQ here): below the hard limit, SessionMax or not (it bounds the upgrades we start).
func (mgr *sessionManager) _replyPQInit(pub *edPub, key *pqPeerKey) {
	p := mgr.pqPending[*pub]
	if p != nil && (!p.once || p.data == nil) {
		return // one of ours under way, sent again on its own
	}
	if !mgr.pc.pq.initReplyDue(pub) || (p == nil && mgr._pqHardFull()) || !mgr.pc.pq.tokenDue() {
		return
	}
	if p != nil {
		mgr.pc.writeRaw(p.data, pub)
		return
	}
	mgr._startPQ(pub, key, true)
}

// _startPQ: a PQ init of ours to pub, sealed to key, pending until its ack (once: not sent again, _replyPQInit)
func (mgr *sessionManager) _startPQ(pub *edPub, key *pqPeerKey, once bool) {
	currentPub, currentPriv := newBoxKeys()
	nextPub, nextPriv := newBoxKeys()
	secret := newRatchetSecret()
	p := &pqPending{
		init:        newPQInit(&currentPub, &nextPub, 0, &secret, mgr.pc.pq.nextSecretNo()),
		currentPriv: currentPriv,
		nextPriv:    nextPriv,
		key:         key,
		once:        once,
	}
	mgr.pqPending[*pub] = p
	mgr._sendPending(pub, p)
}

// _sendPending sends p (sealed once per key), and again after pqInitRetry while it is pending, until sessionTimeout.
// Unanswered pqRollbackTries times (or for pqRollbackAfter), it takes the peer's lower-numbered key kept aside.
func (mgr *sessionManager) _sendPending(pub *edPub, p *pqPending) {
	now := mgr.pc.pq.now()
	if p.first.IsZero() {
		p.first = now
	}
	if p.data == nil {
		var err error
		if p.data, err = p.init.encrypt(mgr.pc, sessionTypePQInit, pub, p.key); err != nil {
			delete(mgr.pqPending, *pub)
			return
		}
	}
	mgr.pc.writeRaw(p.data, pub)
	p.tries++
	if p.timer != nil {
		p.timer.Stop()
	}
	dest := *pub
	wait := pqInitRetry
	if p.once {
		wait = mgr.pc.pq.pendingTimeout // kept for its ack, not sent again
	}
	p.timer = time.AfterFunc(wait, func() {
		mgr.Act(nil, func() {
			if mgr.pqPending[dest] != p {
				return
			}
			now := mgr.pc.pq.now()
			if p.once || now.Sub(p.init.time()) >= mgr.pc.pq.pendingTimeout {
				delete(mgr.pqPending, dest)
				if p.once {
					return // in reply to a packet no one signed: no line, and no upgrade of ours later for it (R3-4)
				}
				if info := mgr.sessions[dest]; info != nil && !info.pq {
					// the peer announced its ML-KEM key, and nothing came back to ours: PQ packets lost on the way, or
					// dropped. The classic session stays; the upgrade is tried again later, not only after the next
					// classic handshake
					mgr.pc.pq.logStripped(&dest, "no answer came to our PQ init", "the session stays classic")
					mgr._upgradeLater(dest)
				} else if info == nil && mgr.pc.pq.required(&dest) {
					mgr.pc.pq.logStripped(&dest, "no answer came to our PQ init", "no session, it must be PQ")
				}
				return
			}
			if p.tries >= pqRollbackTries || now.Sub(p.first) >= pqRollbackAfter {
				if k := mgr.pc.pq.takeRollback(&dest); k != nil {
					p.key, p.data, p.tries, p.first = k, nil, 0, time.Time{}
				}
			}
			mgr._sendPending(&dest, p)
		})
	})
}

func (init *sessionInit) time() time.Time {
	return time.Unix(int64(init.seq), 0)
}

func (mgr *sessionManager) _handlePQInit(pub *edPub, data []byte, isAck bool) {
	var init pqInit
	ok, unknownKey := init.decrypt(mgr.pc, pub, data)
	if unknownKey {
		// nothing checked it: sealed to a key not ours (or ours before a restart). Our PQInfo is half its size: no
		// token, as for our own asks, only pqInfoInterval. A flood of small forged packets empties the buckets, and
		// a peer that holds us to PQ would not learn our new key while it lasts (R6A-3)
		mgr._sendPQInfoDue(pub, askSealed)
	}
	if !ok {
		return
	}
	if !mgr.pc.pq.plausible(init.senderSeq, init.senderNotAfter) {
		return // not taken (accept), nor answered
	}
	mgr.pc.pq.accept(pub, &init.senderPQ, init.senderSeq, init.senderNotAfter)
	// the answer is sealed to the key the sender signed in it, whatever the table holds
	answerTo := newPQPeerKey(pub, &init.senderPQ, init.senderSeq, init.senderNotAfter)
	if !mgr.pc.pq._live(answerTo, pqClockSlack) {
		return
	}
	init.senderKey = answerTo
	if p := mgr.pqPending[*pub]; p != nil && !isAck {
		// two PQ inits crossed: the one of the end with the lower key goes on, the other end answers it. Both
		// answered, each end's ack would be one its peer's session (made from the other init, the same second)
		// takes for a repeat, and the two ratchets would part.
		if bytes.Compare(mgr.pc.publicEd[:], pub[:]) < 0 {
			// ours goes on; sealed to a key of the peer older than the one its init came with, it would not open
			// there, and the peer, waiting for our ack, would not answer it: again, to that key. One of ours sent
			// once in reply to a packet no one signed goes on too: the peer gives way to it, and had ours given way
			// as well, each end would answer the other and the ratchets part for seconds (R6A-4). It may have been
			// lost (N-R4-1): it goes again now, the same bytes, at most once in half pqInitRetry, and stays once (the
			// peer's own retries bring it again; a replayed init of the peer's gets as many bytes as it is)
			if p.once {
				if k := mgr.pc.pq.usableKey(pub); k != nil && k != p.key {
					mgr._resealPending(pub, p)
				} else if now := mgr.pc.pq.now(); now.Sub(p.resentAt) >= pqInitRetry/2 {
					p.resentAt = now
					mgr.pc.writeRaw(p.data, pub)
				}
				return
			}
			mgr._resealPending(pub, p)
			return
		}
		if p.timer != nil {
			p.timer.Stop()
		}
		delete(mgr.pqPending, *pub)
	}
	isOld := false
	if info := mgr.sessions[*pub]; info != nil && info.pq {
		isOld = true
	}
	// an ack to a PQ init of ours that went on its own (not one sent once in reply to a packet no one signed, which
	// anyone can have us make, R6A-5)
	answersOurs := false
	if p := mgr.pqPending[*pub]; isAck && p != nil && !p.once {
		answersOurs = true
	}
	info := mgr._pqSessionForInit(pub, &init, isAck)
	if info == nil {
		return // the hard limit, every PQ session in use: classic, if the key may be
	}
	fresh := init.seq > info.initSeq
	info.initSeq = max(info.initSeq, init.seq)
	switch {
	case isAck && isOld:
		info.handleAck(mgr, &sessionAck{init.sessionInit}, &init)
	default:
		info.handleInit(mgr, &init.sessionInit, &init)
	}
	if isOld && !isAck && fresh {
		// a new PQ init of the peer's to a PQ session up here (it went back to classic, or lost it): an empty packet
		// after our ack confirms the new session there at once. Else its traffic goes by its classic session, which
		// ours drops, until our probe in reply to it (initReplyInterval)
		info.doSend(mgr, allocBytes(0))
	}
	if isAck && info.fallback == nil && fresh && (isOld || answersOurs) {
		// a verified ack, no classic session beside: the other end has the session, and the key is held to PQ. With
		// a classic one beside, only a PQ packet of the peer's that opens does it (doRecv): until then the peer may
		// not have the session (our ack to its ack lost), and goes on with the classic one. Only an ack newer than the
		// session's last, or one to an init of ours: an ack is not bound to the init it answers, and one replayed
		// (captured on the way) renews no hold (R6A-5, as R3-1 for traffic); else the first PQ packet that opens does
		mgr.pc.pq.markSticky(pub, init.senderNotAfter, false)
	}
	if buf := mgr.buffers[*pub]; buf != nil {
		if buf.data != nil {
			info.doSend(mgr, buf.data)
			buf.data = nil
		}
		if mgr.pc.pq.required(pub) {
			buf.timer.Stop()
			delete(mgr.buffers, *pub)
		}
		// else a classic init went with the data (a key that may be classic): its keys stay for the classic session
		// its ack makes, beside this one (_sessionForInit), or that one would be keyed to nothing the peer knows
	}
}

// _pqSessionForInit: the PQ session with pub, made from init if there is none (a classic one gives way to it); made
// from an ack, with the keys and secret of the PQ init of ours it answers
func (mgr *sessionManager) _pqSessionForInit(pub *edPub, init *pqInit, isAck bool) *sessionInfo {
	if info := mgr.sessions[*pub]; info != nil && info.pq {
		return info
	}
	if !mgr._pqRoom(pub) {
		if p := mgr.pqPending[*pub]; p != nil && isAck {
			if p.timer != nil {
				p.timer.Stop()
			}
			delete(mgr.pqPending, *pub)
		}
		return nil
	}
	info := newSession(pub, init.current, init.next, init.seq)
	info.pq = true
	if old := mgr.sessions[*pub]; old != nil && !old.pq && !mgr.pc.pq.required(pub) {
		// a key that may be classic: its classic session stays beside the PQ one until a PQ packet opens
		info.fallback = old
	}
	mgr._countUnconfirmed(info)
	if p := mgr.pqPending[*pub]; p != nil && isAck {
		if p.timer != nil {
			p.timer.Stop()
		}
		delete(mgr.pqPending, *pub)
		info.sendPub, info.sendPriv = p.init.current, p.currentPriv
		info.nextPub, info.nextPriv = p.init.next, p.nextPriv
		info.own = []pqOwnSecret{{secret: p.init.secret, no: p.init.secretNo}}
		info._fixShared(0, 0)
	}
	info.Act(mgr, func() {
		info.mgr = mgr
		info._resetTimer()
	})
	mgr._put(info.ed, info)
	return info
}

func (mgr *sessionManager) _handlePQTraffic(pub *edPub, msg []byte) {
	info := mgr.sessions[*pub]
	switch {
	case len(msg) < pqTrafficOverheadMin:
		// too short to be traffic: no answer to it
	case info != nil && info.pq:
		info.doRecv(mgr, msg)
		return
	case info != nil:
		// its PQ session is up and ours not yet: ours comes with its ack, if ours is pending. None is (its ack was
		// lost until ours expired): a new one, whatever the order of the keys, or the two ends would stay apart
		if key := mgr.pc.pq.usableKey(pub); key == nil {
			if mgr.pqPending[*pub] == nil && mgr.pc.pq.initReplyDue(pub) {
				mgr._replyPQInfo(pub)
			}
		} else {
			mgr._replyPQInit(pub, key)
		}
	default:
		// no session: the peer has a PQ session with us (and may hold us to PQ). Its ML-KEM key known, our PQ init
		// (_replyPQInit: sent once, a token, below the hard limit, not SessionMax, which bounds the upgrades we start;
		// its ack goes through _pqRoom), pending with its keys: the peer's ack makes the session at once (an init
		// with keys we forgot, answered within the second its session began, would take some seconds of inits to
		// settle). Else our PQInfo
		if key := mgr.pc.pq.usableKey(pub); key != nil {
			mgr._replyPQInit(pub, key)
		} else if mgr.pc.pq.initReplyDue(pub) {
			mgr._replyPQInfo(pub)
		}
	}
	freeBytes(msg)
}

// sendPQInit and sendPQAck seal a session's init or ack to the peer's key: the table's, else to (the one its last
// init or ack came with). None alive: our PQInfo, so that it answers with its own.
func (mgr *sessionManager) sendPQInit(dest *edPub, init *pqInit, to *pqPeerKey) {
	mgr.sendPQ(dest, init, sessionTypePQInit, to)
}

// sendPQAck returns the ack as sent (nil if none went), for a repeat of the init it answers
func (mgr *sessionManager) sendPQAck(dest *edPub, ack *pqInit, to *pqPeerKey) []byte {
	return mgr.sendPQ(dest, ack, sessionTypePQAck, to)
}

func (mgr *sessionManager) sendPQ(dest *edPub, init *pqInit, msgType byte, to *pqPeerKey) []byte {
	key := to
	if msgType == sessionTypePQInit {
		if k := mgr.pc.pq.usableKey(dest); k != nil {
			key = k
		}
	}
	if !mgr.pc.pq._live(key, pqClockSlack) {
		mgr._sendPQInfoDue(dest, askSigned)
		return nil
	}
	bs, err := init.encrypt(mgr.pc, msgType, dest, key)
	if err != nil {
		return nil
	}
	mgr.pc.writeRaw(bs, dest)
	return bs
}

// _probe: an empty PQ packet on info, a PQ session with a classic one beside it, at most once in pqProbeInterval: its
// opening at the peer confirms the session there, and the peer's at ours. Nothing opened in pendingTimeout, the PQ
// packets do not get through: the classic session takes the PQ one's place, and the upgrade is tried again later.
func (mgr *sessionManager) _probe(info *sessionInfo) {
	now := time.Now()
	if now.Sub(info.probeAt) < pqProbeInterval {
		return
	}
	info.probeAt = now
	if now.Sub(info.since) >= mgr.pc.pq.pendingTimeout {
		mgr._restoreClassic(info)
		mgr.pc.pq.logStripped(&info.ed, "no PQ packet of its opened here", "the session stays classic")
		mgr._upgradeLater(info.ed)
		return
	}
	info.doSend(mgr, allocBytes(0))
}

// _upgradeLater: a PQ init to pub again after pqUpgradeRetry, if the session is still classic then
func (mgr *sessionManager) _upgradeLater(pub edPub) {
	mgr._upgradeAfter(pub, mgr.pc.pq.upgradeRetry)
}

// _upgradeAfter: as _upgradeLater, after d
func (mgr *sessionManager) _upgradeAfter(pub edPub, d time.Duration) {
	if mgr.pqRetry[pub] {
		return
	}
	mgr.pqRetry[pub] = true
	time.AfterFunc(d, func() {
		mgr.Act(nil, func() {
			delete(mgr.pqRetry, pub)
			if info := mgr.sessions[pub]; info != nil && !info.pq {
				mgr._maybeStartPQ(&pub)
			}
		})
	})
}

// _countUnconfirmed keeps the PQ sessions no traffic opened under yet within pqUnconfirmedMax: each weighs some 12.4 KB
// (a classic one 3.2), and anyone with a key of its own makes one with a PQ init. Past the limit, those confirmed
// or gone since leave the count, then the oldest of the rest is dropped.
func (mgr *sessionManager) _countUnconfirmed(info *sessionInfo) {
	mgr.pqUnconfirmed[info.ed] = info
	if len(mgr.pqUnconfirmed) <= mgr.unconfirmedMax {
		return
	}
	var oldest *sessionInfo
	for k, s := range mgr.pqUnconfirmed {
		switch {
		case s.confirmed.Load() || (mgr.sessions[k] != s && s != info):
			delete(mgr.pqUnconfirmed, k)
		case s != info && (oldest == nil || s.since.Before(oldest.since)):
			oldest = s
		}
	}
	if len(mgr.pqUnconfirmed) > mgr.unconfirmedMax && oldest != nil {
		delete(mgr.pqUnconfirmed, oldest.ed)
		if mgr.sessions[oldest.ed] != oldest {
			return
		}
		s, then := &mgr.pc.pq, mgr._evict(oldest)
		s.logEvery(&s.unconfirmedLogged, "PQ: %d PQ sessions with nothing opened under them, the most kept: the oldest, of %x, %s",
			mgr.unconfirmedMax, oldest.ed[:8], then)
	}
}
