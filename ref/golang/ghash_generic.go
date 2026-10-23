//go:build (!amd64 && !arm64) || purego

package gem

import (
	"log"

	bsg "gitlab.com/yawning/bsaes.git/ghash"
)

// ghashUpdate is the portable fallback used on architectures without an
// optimized assembly implementation and for purego builds. It uses the
// constant-time bitsliced GHASH from bsaes.
func ghashUpdate(y, h *[blockSize]byte, data []byte) {
	if len(data)%blockSize != 0 {
		log.Panic("ghashUpdate: data length must be multiple of 16")
	}
	if len(data) == 0 {
		return
	}
	bsg.Ghash(y, h, data)
}
