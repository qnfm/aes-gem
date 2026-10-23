//go:build arm64 && !purego

package gem

import (
	"bytes"
	"crypto/rand"
	"testing"

	bsg "gitlab.com/yawning/bsaes.git/ghash"
)

// TestGHashPMULLMatchesGeneric cross-checks the PMULL assembly against the
// bitsliced reference for lengths that exercise the 8-block and single-block
// loops and the transition between them.
func TestGHashPMULLMatchesGeneric(t *testing.T) {
	if !useGHashPMULL {
		t.Skip("CPU does not support PMULL")
	}
	for blocks := 0; blocks <= 40; blocks++ {
		for iter := 0; iter < 8; iter++ {
			var h, y [blockSize]byte
			rand.Read(h[:])
			rand.Read(y[:])
			data := make([]byte, blocks*blockSize)
			rand.Read(data)

			want := y
			bsg.Ghash(&want, &h, data)

			got := y
			ghashUpdate(&got, &h, data)

			if !bytes.Equal(got[:], want[:]) {
				t.Fatalf("blocks=%d: got %x, want %x", blocks, got, want)
			}
		}
	}
}

func BenchmarkGHashPMULL4K(b *testing.B) {
	benchmarkGHash(b, ghashUpdate)
}

func BenchmarkGHashGeneric4K(b *testing.B) {
	benchmarkGHash(b, bsg.Ghash)
}

func benchmarkGHash(b *testing.B, f func(y, h *[blockSize]byte, data []byte)) {
	var h, y [blockSize]byte
	rand.Read(h[:])
	data := make([]byte, 4096)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		f(&y, &h, data)
	}
}
