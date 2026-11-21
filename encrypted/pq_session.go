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
	sealed, err := hpke.Seal(to.hpke, pqKDF, pqAEAD, info, payload)
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
}

// pqRefusesClassic: classic init, ack and traffic from key are dropped (it must be PQ, or a PQ session with it is up)
func (mgr *sessionManager) pqRefusesClassic(key *edPub) bool {
	if !mgr.pc.pq.enabled() {
		return false
	}
	if info := mgr.sessions[*key]; info != nil && info.pq {
		return true
	}
	return mgr.pc.pq.required(key)
}

func (mgr *sessionManager) sendPQInfo(dest *edPub) {
	mgr.pc.writeRaw(mgr.pc.pqOwn().info, dest)
}

// _sendPQInfoDue: our PQInfo to dest, if none went in pqInfoInterval
func (mgr *sessionManager) _sendPQInfoDue(dest *edPub) {
	if mgr.pc.pq.infoDue(dest) {
		mgr.sendPQInfo(dest)
	}
}

func (mgr *sessionManager) _handlePQInfo(pub *edPub, data []byte) {
	var pq sessionPQInfo
	if !pq.decode(pub, data, mgr.pc.groupAuth) {
		return
	}
	accepted, updated := mgr.pc.pq.accept(pub, &pq.pub, pq.seq, pq.notAfter)
	// an answer, so that the sender knows our key too (it may have lost it): limited, or two nodes would ping-pong
	mgr._sendPQInfoDue(pub)
	if !accepted {
		return
	}
	if p := mgr.pqPending[*pub]; p != nil && updated {
		// sealed to its key before: again to the new one
		p.key, p.data, p.tries, p.first = mgr.pc.pq.usableKey(pub), nil, 0, time.Time{}
		if p.key != nil {
			mgr._sendPending(pub, p)
		}
		return
	}
	mgr._maybeStartPQ(pub)
}

// _maybeStartPQ starts a PQ init to pub where one is wanted and none is under way: data is waiting for a session, or
// a classic session is up (that one replaced, started by the end with the lower key; the other sends its PQInfo, so
// that the first knows its key).
func (mgr *sessionManager) _maybeStartPQ(pub *edPub) {
	if !mgr.pc.pq.enabled() || mgr.pqPending[*pub] != nil {
		return
	}
	info := mgr.sessions[*pub]
	if info != nil && info.pq {
		return
	}
	_, buffered := mgr.buffers[*pub]
	if !buffered && info == nil {
		return
	}
	key := mgr.pc.pq.usableKey(pub)
	if key == nil || (!buffered && bytes.Compare(mgr.pc.publicEd[:], pub[:]) > 0) {
		mgr._sendPQInfoDue(pub)
		return
	}
	currentPub, currentPriv := newBoxKeys()
	nextPub, nextPriv := newBoxKeys()
	secret := newRatchetSecret()
	p := &pqPending{
		init:        newPQInit(&currentPub, &nextPub, 0, &secret, mgr.pc.pq.nextSecretNo()),
		currentPriv: currentPriv,
		nextPriv:    nextPriv,
		key:         key,
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
	p.timer = time.AfterFunc(pqInitRetry, func() {
		mgr.Act(nil, func() {
			if mgr.pqPending[dest] != p {
				return
			}
			now := mgr.pc.pq.now()
			if now.Sub(p.init.time()) >= sessionTimeout {
				delete(mgr.pqPending, dest)
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
		mgr._sendPQInfoDue(pub)
	}
	if !ok {
		return
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
	info := mgr._pqSessionForInit(pub, &init, isAck)
	switch {
	case isAck && isOld:
		info.handleAck(mgr, &sessionAck{init.sessionInit}, &init)
	default:
		info.handleInit(mgr, &init.sessionInit, &init)
	}
	if isAck {
		// a verified ack: the other end has the session
		mgr.pc.pq.markSticky(pub)
	}
	if buf := mgr.buffers[*pub]; buf != nil {
		buf.timer.Stop()
		delete(mgr.buffers, *pub)
		if buf.data != nil {
			info.doSend(mgr, buf.data)
		}
	}
}

// _pqSessionForInit: the PQ session with pub, made from init if there is none (a classic one gives way to it); made
// from an ack, with the keys and secret of the PQ init of ours it answers
func (mgr *sessionManager) _pqSessionForInit(pub *edPub, init *pqInit, isAck bool) *sessionInfo {
	if info := mgr.sessions[*pub]; info != nil && info.pq {
		return info
	}
	info := newSession(pub, init.current, init.next, init.seq)
	info.pq = true
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
	mgr.sessions[info.ed] = info
	return info
}

func (mgr *sessionManager) _handlePQTraffic(pub *edPub, msg []byte) {
	info := mgr.sessions[*pub]
	switch {
	case info != nil && info.pq:
		info.doRecv(mgr, msg)
		return
	case info != nil:
		// its PQ session is up and ours not yet (its ack is on the way): ours comes with the ack
	case !mgr.pc.pq.initReplyDue(pub):
	default:
		// as for classic traffic without a session: an init with keys and a secret this node forgets
		if key := mgr.pc.pq.usableKey(pub); key != nil {
			currentPub, _ := newBoxKeys()
			nextPub, _ := newBoxKeys()
			secret := newRatchetSecret()
			init := newPQInit(&currentPub, &nextPub, 0, &secret, mgr.pc.pq.nextSecretNo())
			if bs, err := init.encrypt(mgr.pc, sessionTypePQInit, pub, key); err == nil {
				mgr.pc.writeRaw(bs, pub)
			}
		} else {
			mgr._sendPQInfoDue(pub)
		}
	}
	freeBytes(msg)
}

// sendPQInit and sendPQAck seal a session's init or ack to the peer's key: the table's, else to (the one its last
// init or ack came with). None alive: our PQInfo, so that it answers with its own.
func (mgr *sessionManager) sendPQInit(dest *edPub, init *pqInit, to *pqPeerKey) {
	mgr.sendPQ(dest, init, sessionTypePQInit, to)
}

func (mgr *sessionManager) sendPQAck(dest *edPub, ack *pqInit, to *pqPeerKey) {
	mgr.sendPQ(dest, ack, sessionTypePQAck, to)
}

func (mgr *sessionManager) sendPQ(dest *edPub, init *pqInit, msgType byte, to *pqPeerKey) {
	key := to
	if msgType == sessionTypePQInit {
		if k := mgr.pc.pq.usableKey(dest); k != nil {
			key = k
		}
	}
	if !mgr.pc.pq._live(key, pqClockSlack) {
		if mgr.pc.pq.infoDue(dest) {
			mgr.sendPQInfo(dest)
		}
		return
	}
	if bs, err := init.encrypt(mgr.pc, msgType, dest, key); err == nil {
		mgr.pc.writeRaw(bs, dest)
	}
}
