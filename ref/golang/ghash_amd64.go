//go:build amd64 && !purego

package gem

import "golang.org/x/sys/cpu"

func ghashUpdate(y, h *[blockSize]byte, data []byte) {
	if len(data)%blockSize != 0 {
		panic("ghashUpdate: data length must be multiple of 16")
	}
	if len(data) == 0 {
		return
	}
	if cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSSE3 {
		ghashUpdatePCLMUL(y, h, data)
		return
	}
	ghashUpdateGeneric(y, h, data)
}

//go:noescape
func ghashUpdatePCLMUL(y, h *[blockSize]byte, data []byte)
