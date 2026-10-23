//go:build arm64 && !purego

package gem

import (
	"log"

	bsg "gitlab.com/yawning/bsaes.git/ghash"
	"golang.org/x/sys/cpu"
)

var useGHashPMULL = cpu.ARM64.HasPMULL

func ghashUpdate(y, h *[blockSize]byte, data []byte) {
	if len(data)%blockSize != 0 {
		log.Panic("ghashUpdate: data length must be multiple of 16")
	}
	if len(data) == 0 {
		return
	}
	if useGHashPMULL {
		// Powers H^8..H^1 with Karatsuba precomputations, same layout as
		// Go's crypto/internal/fips140/aes/gcm productTable.
		var tbl [16 * blockSize]byte
		powers := 1
		if len(data) >= 8*blockSize {
			powers = 8
		}
		ghashInitPMULL(&tbl, h, powers)
		ghashUpdatePMULL(&tbl, y, data)
		return
	}
	bsg.Ghash(y, h, data)
}

//go:noescape
func ghashInitPMULL(tbl *[16 * blockSize]byte, h *[blockSize]byte, powers int)

//go:noescape
func ghashUpdatePMULL(tbl *[16 * blockSize]byte, y *[blockSize]byte, data []byte)
