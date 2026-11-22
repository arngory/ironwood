package encrypted

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// Hybrid post-quantum sessions (niko docs/design/ironwood-pq.md). The cryptography is that of Arceliar/ironwood
// PR 48: init and ack sealed by HPKE with ML-KEM-768 + X25519, the X25519 half the recipient's static key from its
// ed25519 key and the ML-KEM half a key of the recipient's process, announced by a signed PQInfo; traffic on
// ChaCha20-Poly1305. Two changes to it: the init is bound to its recipient (the signature and HPKE's info cover the
// recipient's ed25519 key and the number and hash of its ML-KEM key), and each direction's traffic key mixes in the
// recipient's ratchet secret, which PR 48 carries and never uses.

const (
	pqPubSize         = mlkem.EncapsulationKeySize768
	pqHashSize        = sha256.Size
	hpkeEncSize       = mlkem.CiphertextSize768 + boxPubSize
	hpkeTagSize       = 16 // AES-256-GCM
	hpkeOverhead      = hpkeEncSize + hpkeTagSize
	ratchetSecretSize = 32
	pqAEADOverhead    = chacha20poly1305.Overhead
	pqNonceSize       = chacha20poly1305.NonceSize
)

var (
	pqKDF  = hpke.HKDFSHA256()
	pqAEAD = hpke.AES256GCM()

	pqHPKEInfo    = "ironwood/session/v2"
	pqInitSigCtx  = "ironwood-init-v2"
	pqInfoSigCtx  = "ironwood-pqinfo-v2"
	pqTrafficInfo = "ironwood/v2 traffic"
)

type pqPub [pqPubSize]byte
type pqHash [pqHashSize]byte
type ratchetSecret [ratchetSecretSize]byte

func (pub *pqPub) hash() pqHash {
	return pqHash(sha256.Sum256(pub[:]))
}

func newRatchetSecret() (secret ratchetSecret) {
	if _, err := rand.Read(secret[:]); err != nil {
		panic("failed to generate a ratchet secret")
	}
	return
}

// pqBinding is what binds a PQ init or ack to its recipient: the type, both ed25519 keys and the ML-KEM key it is
// sealed to (number and hash). HPKE's info and the signature both cover it, so neither can be resealed to another.
func pqBinding(ctx string, msgType byte, from, to *edPub, toSeq uint64, toHash *pqHash) []byte {
	out := make([]byte, 0, len(ctx)+1+2*edPubSize+8+pqHashSize)
	out = append(out, ctx...)
	out = append(out, msgType)
	out = append(out, from[:]...)
	out = append(out, to[:]...)
	out = binary.BigEndian.AppendUint64(out, toSeq)
	return append(out, toHash[:]...)
}

func pqHPKEPublic(toBox *boxPub, toPQ *pqPub) (hpke.PublicKey, error) {
	x, err := ecdh.X25519().NewPublicKey(toBox[:])
	if err != nil {
		return nil, err
	}
	pq, err := mlkem.NewEncapsulationKey768(toPQ[:])
	if err != nil {
		return nil, err
	}
	return hpke.NewHybridPublicKey(pq, x)
}

func pqHPKEPrivate(box *boxPriv, pq *mlkem.DecapsulationKey768) (hpke.PrivateKey, error) {
	x, err := ecdh.X25519().NewPrivateKey(box[:])
	if err != nil {
		return nil, err
	}
	return hpke.NewHybridPrivateKey(pq, x)
}

// pqTrafficKey is the key of the direction from → to: HKDF-SHA256 of the pair's X25519 secret (as box precomputes
// it) and the recipient's ratchet secret, labelled with the sender's and the recipient's ed25519 keys, in that order,
// and the numbers of their keys. The roles order the label, so both ends derive one key per direction and the two
// directions differ.
func pqTrafficKey(shared *boxShared, secret *ratchetSecret, from, to *edPub, fromKeySeq, toKeySeq uint64) cipher.AEAD {
	ikm := make([]byte, 0, boxSharedSize+ratchetSecretSize)
	ikm = append(append(ikm, shared[:]...), secret[:]...)
	info := make([]byte, 0, len(pqTrafficInfo)+2*edPubSize+16)
	info = append(info, pqTrafficInfo...)
	info = append(append(info, from[:]...), to[:]...)
	info = binary.BigEndian.AppendUint64(info, fromKeySeq)
	info = binary.BigEndian.AppendUint64(info, toKeySeq)
	key, err := hkdf.Key(sha256.New, ikm, nil, string(info), chacha20poly1305.KeySize)
	if err != nil {
		panic("hkdf failed")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic("chacha20poly1305 failed")
	}
	return aead
}

func pqNonce(u64 uint64) (nonce [pqNonceSize]byte) {
	binary.BigEndian.PutUint64(nonce[pqNonceSize-8:], u64)
	return
}
