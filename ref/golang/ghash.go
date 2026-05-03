// Package gem implements AES-GEM (Galois Extended Mode), an AEAD cipher
// with extended nonces and hierarchical key derivation.
//
// GHASH is implemented here because Go's standard library only exposes
// it internally (crypto/internal/fips140/gcm). There is no public
// GHASH API in crypto/cipher or golang.org/x/crypto.
package gem

import bsg "gitlab.com/yawning/bsaes.git/ghash"

const blockSize = 16

// ghash implements GHASH: a universal hash over GF(2^128).
type ghash struct {
	h     [blockSize]byte // GHASH key
	state [blockSize]byte // running accumulator
}

func newGHash(h [blockSize]byte) *ghash {
	return &ghash{h: h}
}

// update XORs a full 16-byte block into the state and multiplies by H.
func (g *ghash) update(block [blockSize]byte) {
	bsg.Ghash(&g.state, &g.h, block[:])
}

// updatePadded processes arbitrary-length data, zero-padding the final
// partial block if necessary (matching GCM's GHASH padding).
func (g *ghash) updatePadded(data []byte) {
	full := len(data) &^ (blockSize - 1)

	if full > 0 {
		bsg.Ghash(&g.state, &g.h, data[:full])
	}

	if full < len(data) {
		var block [blockSize]byte
		copy(block[:], data[full:])
		bsg.Ghash(&g.state, &g.h, block[:])
	}
}

// finalize returns the current GHASH state.
func (g *ghash) finalize() [blockSize]byte {
	return g.state
}
