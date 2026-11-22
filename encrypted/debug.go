package encrypted

import (
	"crypto/ed25519"
	"time"

	"github.com/Arceliar/phony"
)

type Debug struct {
	pc *PacketConn
}

func (d *Debug) init(pc *PacketConn) {
	d.pc = pc
}

type DebugSessionInfo struct {
	Key    ed25519.PublicKey
	Uptime time.Duration
	RX     uint64
	TX     uint64
	PQ     bool // a hybrid post-quantum session
	// PQConfirmed: a PQ session a packet of the peer's opened under: until then the peer may not have it, and a
	// classic session beside it carries the traffic
	PQConfirmed bool
}

func (d *Debug) GetSessions() (infos []DebugSessionInfo) {
	var sessions []*sessionInfo
	phony.Block(&d.pc.sessions, func() {
		for _, session := range d.pc.sessions.sessions {
			sessions = append(sessions, session)
		}
	})
	// each session's counters in its own actor, which writes them
	for _, session := range sessions {
		var info DebugSessionInfo
		phony.Block(session, func() {
			info.Key = append(info.Key, session.ed[:]...)
			info.Uptime = time.Since(session.since)
			info.RX, info.TX = session.rx, session.tx
			info.PQ = session.pq
			info.PQConfirmed = session.pq && session.confirmed.Load()
		})
		infos = append(infos, info)
	}
	return
}
