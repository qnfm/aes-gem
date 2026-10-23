//go:build amd64 && !purego

package gem

import (
	"log"

	bsg "gitlab.com/yawning/bsaes.git/ghash"
)

func ghashUpdateGeneric(y, h *[blockSize]byte, data []byte) {
	if len(data)%blockSize != 0 {
		log.Panic("ghashUpdateGeneric: data length must be multiple of 16")
	}
	if len(data) == 0 {
		return
	}
	bsg.Ghash(y, h, data)
}
