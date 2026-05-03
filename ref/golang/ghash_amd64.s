//go:build amd64 && !purego

#include "textflag.h"

#define B0   X0
#define H    X1
#define HM   X2
#define ACC0 X3
#define ACC1 X4
#define ACCM X5
#define T0   X6
#define T1   X7
#define POLY X8
#define BSWAP X9

DATA bswapMask<>+0x00(SB)/8, $0x08090a0b0c0d0e0f
DATA bswapMask<>+0x08(SB)/8, $0x0001020304050607
GLOBL bswapMask<>(SB), (NOPTR+RODATA), $16

DATA gcmPoly<>+0x00(SB)/8, $0x0000000000000001
DATA gcmPoly<>+0x08(SB)/8, $0xc200000000000000
GLOBL gcmPoly<>(SB), (NOPTR+RODATA), $16

// func ghashUpdatePCLMUL(y, h *[16]byte, data []byte)
//
// Contract:
//   - len(data) must be a multiple of 16.
//   - y and h are in normal GHASH byte order.
//   - y is updated in place.
//
// This is a simple single-block-at-a-time PCLMUL GHASH.
// It uses the same byte-swap / reduction strategy as Go's AES-GCM assembly,
// but without the 8-way aggregation used by the stdlib fast path.
TEXT ·ghashUpdatePCLMUL(SB), NOSPLIT, $0-40
	// Args.
	MOVQ y+0(FP), DI
	MOVQ h+8(FP), SI
	MOVQ data_base+16(FP), DX
	MOVQ data_len+24(FP), CX

	TESTQ CX, CX
	JEQ done

	MOVOU bswapMask<>(SB), BSWAP
	MOVOU gcmPoly<>(SB), POLY

	// Load H and convert to internal reversed-byte representation.
	MOVOU (SI), H
	PSHUFB BSWAP, H

	// Convert H to the representation used by Go's GCM multiply code:
	// H = H * 2 in GF(2^128), then HM = H.low^H.high precompute.
	MOVOU H, T0
	PSHUFD $0xff, H, T1
	PSRAL $31, T1
	PAND POLY, T1
	PSRLL $31, T0
	PSLLDQ $4, T0
	PSLLL $1, H
	PXOR T1, H
	PXOR T0, H

	// HM = H xor swap64(H). Used for Karatsuba middle term.
	MOVOU H, HM
	PSHUFD $78, HM, HM
	PXOR H, HM

	// Load current accumulator y and convert to internal representation.
	MOVOU (DI), ACC0
	PSHUFB BSWAP, ACC0

loop:
	CMPQ CX, $16
	JB store

	// Load next input block and byte-swap.
	MOVOU (DX), B0
	PSHUFB BSWAP, B0

	// B0 = B0 xor ACC0
	PXOR ACC0, B0

	// Karatsuba carryless multiply B0 * H.
	MOVOU H, ACC0
	MOVOU H, ACC1
	MOVOU HM, ACCM

	// T0 = low64(B0) xor high64(B0), in swapped-lane form.
	MOVOU B0, T0
	PSHUFD $78, T0, T0
	PXOR B0, T0

	PCLMULQDQ $0x00, B0, ACC0
	PCLMULQDQ $0x11, B0, ACC1
	PCLMULQDQ $0x00, T0, ACCM

	PXOR ACC0, ACCM
	PXOR ACC1, ACCM

	MOVOU ACCM, T0
	PSRLDQ $8, ACCM
	PSLLDQ $8, T0
	PXOR ACCM, ACC1
	PXOR T0, ACC0

	// Barrett-style reduction, same structure as Go's gcm_amd64.s.
	MOVOU POLY, T0
	PCLMULQDQ $0x01, ACC0, T0
	PSHUFD $78, ACC0, ACC0
	PXOR T0, ACC0

	MOVOU POLY, T0
	PCLMULQDQ $0x01, ACC0, T0
	PSHUFD $78, ACC0, ACC0
	PXOR T0, ACC0

	PXOR ACC1, ACC0

	LEAQ 16(DX), DX
	SUBQ $16, CX
	JMP loop

store:
	// Convert accumulator back to normal GHASH byte order.
	PSHUFB BSWAP, ACC0
	MOVOU ACC0, (DI)

done:
	RET
