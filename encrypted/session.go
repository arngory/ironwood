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
	pqUnconfirmed  map[edPub]*sessionInfo // PQ sessions no traffic may have opened under yet (_countUnconfirmed)
	unconfirmedMax int                    // pqUnconfirmedMax, a test's own
}

func (mgr *sessionManager) init(pc *PacketConn) {
	mgr.pc = pc
	mgr.sessions = make(map[edPub]*sessionInfo)
	mgr.buffers = make(map[edPub]*sessionBuffer)
	mgr.pqPending = make(map[edPub]*pqPending)
	mgr.pqRetry = make(map[edPub]bool)
	mgr.pqUnconfirmed = make(map[edPub]*sessionInfo)
	mgr.unconfirmedMax = pqUnconfirmedMax
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
			case info.pq && info.fallback != nil:
				mgr.sessions[k] = info.fallback // the classic session beside it goes on
			case info.pq:
				delete(mgr.sessions, k)
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
	mgr.sessions[info.ed] = info
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
			case mgr.pqRefusesClassic(pub):
				// it must be PQ: our PQInfo, so that it can start a PQ init if it has them
				mgr._sendPQInfoDue(pub)
			default:
				if init := new(sessionInit); init.decrypt(&mgr.pc.secretBox, pub, data, mgr.pc.groupAuth) {
					mgr._handleInit(pub, init)
				}
			}
			freeBytes(data)
		case sessionTypeAck:
			switch {
			case len(data) != sessionAckSize:
			case mgr.pqRefusesClassic(pub):
				mgr._sendPQInfoDue(pub)
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
			} else {
				freeBytes(data)
			}
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
	} else if info := mgr.sessions[*pub]; info != nil {
		if info.pq && info.fallback != nil && !info.confirmed.Load() {
			// to the classic session beside a PQ one nothing opened under yet: the peer may not have the PQ one
			info.fallback.doRecv(mgr, msg)
		} else {
			// a PQ session drops it (a classic packet sent before the PQ session took the classic one's place)
			info.doRecv(mgr, msg)
		}
	} else if mgr.pc.pq.required(pub) {
		mgr._sendPQInfoDue(pub)
		freeBytes(msg)
	} else if !mgr.pc.pq.initReplyDue(pub) {
		// one init in reply per initReplyInterval: every packet of a stream would send one
		freeBytes(msg)
	} else {
		// We don't know that the node really exists, it could be spoofed/replay
		// So we don't want to save session or a buffer based on this node
		// So we send an init with keys we'll forget
		// If they ack, we'll set up a session and let it self-heal...
		currentPub, _ := newBoxKeys()
		nextPub, _ := newBoxKeys()
		init := newSessionInit(&currentPub, &nextPub, 0)
		mgr.sendInit(pub, &init)
		freeBytes(msg)
	}
}

func (mgr *sessionManager) writeTo(toKey edPub, msg []byte) {
	// WARNING: unsafe to call from within an actor, must only be exposed over the PacketConn functions (which are, themselves, unsafe for actors to call in most cases, since they may block)
	phony.Block(mgr, func() {
		info := mgr.sessions[toKey]
		if info != nil && !info.pq && mgr.pc.pq.required(&toKey) {
			// the key became one that must be PQ (its node announced it): the classic session goes
			delete(mgr.sessions, toKey)
			info = nil
		}
		if info != nil && info.pq && info.fallback != nil {
			if info.confirmed.Load() || mgr.pc.pq.required(&toKey) {
				info.fallback = nil
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
		mgr.buffers[toKey] = buf
	}
	buf.data = msg
	buf.timer.Stop()
	if !mgr.pc.pq.required(&toKey) {
		mgr.sendInit(&toKey, &buf.init)
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

func (mgr *sessionManager) sendInit(dest *edPub, init *sessionInit) {
	if bs, err := init.encrypt(&mgr.pc.secretEd, dest, mgr.pc.groupAuth); err == nil {
		mgr.pc.writeRaw(bs, dest)
	}
}

func (mgr *sessionManager) sendAck(dest *edPub, ack *sessionAck) {
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
	confirmed    atomic.Bool // a PQ packet opened (read by the manager)
	// the manager's: the classic session a PQ one of a key that may be classic replaced, kept and used until a PQ
	// packet opens (the peer may never have had the ack, or PQ packets be dropped on the way); a probe of ours, last
	fallback *sessionInfo
	probeAt  time.Time
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
	info.recvWindow.reset()
	if recvNonce != 0 {
		info.recvWindow.commit(recvNonce)
	}
	info.sendNonce = sendNonce
}

func (info *sessionInfo) _resetTimer() {
	if info.timer != nil {
		info.timer.Stop()
	}
	info.timer = time.AfterFunc(sessionTimeout, func() {
		info.mgr.Act(nil, func() {
			if oldInfo := info.mgr.sessions[info.ed]; oldInfo == info {
				if info.fallback != nil && !info.confirmed.Load() {
					// a PQ session nothing opened under: the classic one beside it stays
					info.mgr.sessions[info.ed] = info.fallback
				} else {
					delete(info.mgr.sessions, info.ed)
				}
			}
		})
	})
}

// handleInit takes an init (pqi: it as a PQ init, nil for a classic one)
func (info *sessionInfo) handleInit(from phony.Actor, init *sessionInit, pqi *pqInit) {
	info.Act(from, func() {
		if init.seq < info.seq {
			return
		}
		if init.seq == info.seq {
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
		if ack.seq <= info.seq {
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
	info.seq = init.seq
	info.remoteKeySeq = init.keySeq
	// Advance our keys, since this counts as a response
	info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
	info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
	info.nextPub, info.nextPriv = newBoxKeys()
	info.localKeySeq++
	// Don't roll back sendNonce, just to be extra safe
	info._fixShared(0, info.sendNonce)
	info._resetTimer()
}

func (info *sessionInfo) doSend(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
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
			var header [32]byte
			ad := header[:copy(header[:], bs)]
			nonce := pqNonce(info.sendNonce)
			bs = info._sendCipher().Seal(bs, nonce[:], tmp, ad)
		} else {
			bs = boxSeal(bs, tmp, info.sendNonce, &info.sendShared)
		}
		freeBytes(tmp)
		// send
		info.mgr.pc.writeRaw(bs, &info.ed)
		info.tx += uint64(len(msg))
		info._resetTimer()
	})
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
		var header [32]byte
		ad := header[:copy(header[:], orig[:offset])]
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
					info._fixShared(nonce, 0)
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
					info._fixShared(nonce, 0)
					info.rotated = time.Now()
				}
			}
		default:
			// We can't make sense of their message
			// Send a sessionInit and hope they ack so we can fix things
			info._sendInitDue()
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
				if info.lastOpened.IsZero() {
					// traffic opened under keys from a verified PQ init or ack: a PQ session, both ends
					info.mgr.pc.pq.markSticky(&info.ed, true)
					info.confirmed.Store(true)
				}
				info.lastOpened = time.Now()
			}
		} else {
			// Keys somehow became out-of-sync
			// This seems to happen in some edge cases if a node restarts
			// Fix by sending a new init
			info._sendInitDue()
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
	n := pqNonce(nonce)
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
		opened, err := own.recv[pqCase].Open(out, n[:], msg, ad)
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
}
