//go:build arm64 && !purego

#include "textflag.h"

// PMULL-based GHASH, derived from Go's
// crypto/internal/fips140/aes/gcm/gcm_arm64.s (BSD license).

#define B0 V0
#define B1 V1
#define B2 V2
#define B3 V3
#define B4 V4
#define B5 V5
#define B6 V6
#define B7 V7

#define ACC0 V8
#define ACC1 V9
#define ACCM V10

#define T0 V11
#define T1 V12
#define T2 V13
#define T3 V14

#define POLY V15
#define ZERO V16

#define loadPoly(R) \
	MOVD	$0xC2, R              \
	LSL	$56, R                \
	VMOV	R, POLY.D[0]          \
	MOVD	$1, R                 \
	VMOV	R, POLY.D[1]          \
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

#define reduce() \
	VEOR	ACC0.B16, ACCM.B16, ACCM.B16     \
	VEOR	ACC1.B16, ACCM.B16, ACCM.B16     \
	VEXT	$8, ZERO.B16, ACCM.B16, T0.B16   \
	VEXT	$8, ACCM.B16, ZERO.B16, ACCM.B16 \
	VEOR	ACCM.B16, ACC0.B16, ACC0.B16     \
	VEOR	T0.B16, ACC1.B16, ACC1.B16       \
	VPMULL	POLY.D1, ACC0.D1, T0.Q1          \
	VEXT	$8, ACC0.B16, ACC0.B16, ACC0.B16 \
	VEOR	T0.B16, ACC0.B16, ACC0.B16       \
	VPMULL	POLY.D1, ACC0.D1, T0.Q1          \
	VEOR	T0.B16, ACC1.B16, ACC1.B16       \
	VEXT	$8, ACC1.B16, ACC1.B16, ACC1.B16 \
	VEOR	ACC1.B16, ACC0.B16, ACC0.B16

#define mulRound(X) \
	VLD1.P	32(R0), [T1.B16, T2.B16]   \
	VREV64	X.B16, X.B16               \
	VEXT	$8, X.B16, X.B16, T0.B16   \
	VEOR	X.B16, T0.B16, T0.B16      \
	VPMULL	X.D1, T1.D1, T3.Q1         \
	VEOR	T3.B16, ACC1.B16, ACC1.B16 \
	VPMULL2	X.D2, T1.D2, T3.Q1         \
	VEOR	T3.B16, ACC0.B16, ACC0.B16 \
	VPMULL	T0.D1, T2.D1, T3.Q1        \
	VEOR	T3.B16, ACCM.B16, ACCM.B16

// func ghashInitPMULL(tbl *[256]byte, h *[16]byte, powers int)
//
// Stores H^1 (plus Karatsuba term) at tbl[224:256]. If powers == 8, also
// stores H^2..H^8 at tbl[192:224] down to tbl[0:32].
TEXT ·ghashInitPMULL(SB), NOSPLIT, $0-24
	MOVD	tbl+0(FP), R0
	MOVD	h+8(FP), R1
	MOVD	powers+16(FP), R2

	loadPoly(R3)

	VLD1	(R1), [B0.B16]
	VREV64	B0.B16, B0.B16

	// Multiply H by 2 modulo P.
	VMOV	B0.D[0], R3
	ASR	$63, R3
	VMOV	R3, T1.D[0]
	VMOV	R3, T1.D[1]
	VAND	POLY.B16, T1.B16, T1.B16
	VUSHR	$63, B0.D2, T2.D2
	VEXT	$8, ZERO.B16, T2.B16, T2.B16
	VSHL	$1, B0.D2, B0.D2
	VEOR	T1.B16, B0.B16, B0.B16
	VEOR	T2.B16, B0.B16, B0.B16

	// Karatsuba pre-computation.
	VEXT	$8, B0.B16, B0.B16, B1.B16
	VEOR	B0.B16, B1.B16, B1.B16

	ADD	$14*16, R0
	VST1	[B0.B16, B1.B16], (R0)

	SUBS	$1, R2
	BLE	initDone
	SUB	$2*16, R0

	VMOV	B0.B16, B2.B16
	VMOV	B1.B16, B3.B16

initLoop:
	// Compute powers of H.
	SUBS	$1, R2

	VPMULL	B0.D1, B2.D1, T1.Q1
	VPMULL2	B0.D2, B2.D2, T0.Q1
	VPMULL	B1.D1, B3.D1, T2.Q1
	VEOR	T0.B16, T2.B16, T2.B16
	VEOR	T1.B16, T2.B16, T2.B16
	VEXT	$8, ZERO.B16, T2.B16, T3.B16
	VEXT	$8, T2.B16, ZERO.B16, T2.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VEOR	T3.B16, T1.B16, T1.B16
	VPMULL	POLY.D1, T0.D1, T2.Q1
	VEXT	$8, T0.B16, T0.B16, T0.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VPMULL	POLY.D1, T0.D1, T2.Q1
	VEXT	$8, T0.B16, T0.B16, T0.B16
	VEOR	T2.B16, T0.B16, T0.B16
	VEOR	T1.B16, T0.B16, B2.B16
	VMOV	B2.B16, B3.B16
	VEXT	$8, B2.B16, B2.B16, B2.B16
	VEOR	B2.B16, B3.B16, B3.B16

	VST1	[B2.B16, B3.B16], (R0)
	SUB	$2*16, R0

	BNE	initLoop

initDone:
	RET

// func ghashUpdatePMULL(tbl *[256]byte, y *[16]byte, data []byte)
//
// Contract:
//   - len(data) must be a multiple of 16.
//   - tbl was filled by ghashInitPMULL with powers == 8 if len(data) >= 128.
//   - y is in normal GHASH byte order and is updated in place.
TEXT ·ghashUpdatePMULL(SB), NOSPLIT, $0-40
	MOVD	tbl+0(FP), R0
	MOVD	y+8(FP), R2
	MOVD	data_base+16(FP), R1
	MOVD	data_len+24(FP), R3

	loadPoly(R4)
	MOVD	R0, R5

	VLD1	(R2), [ACC0.B16]
	VREV64	ACC0.B16, ACC0.B16

octetsLoop:
	CMP	$128, R3
	BLT	singlesStart
	SUB	$128, R3

	VLD1.P	32(R1), [B0.B16, B1.B16]

	VLD1.P	32(R0), [T1.B16, T2.B16]
	VREV64	B0.B16, B0.B16
	VEOR	ACC0.B16, B0.B16, B0.B16
	VEXT	$8, B0.B16, B0.B16, T0.B16
	VEOR	B0.B16, T0.B16, T0.B16
	VPMULL	B0.D1, T1.D1, ACC1.Q1
	VPMULL2	B0.D2, T1.D2, ACC0.Q1
	VPMULL	T0.D1, T2.D1, ACCM.Q1

	mulRound(B1)
	VLD1.P	32(R1), [B2.B16, B3.B16]
	mulRound(B2)
	mulRound(B3)
	VLD1.P	32(R1), [B4.B16, B5.B16]
	mulRound(B4)
	mulRound(B5)
	VLD1.P	32(R1), [B6.B16, B7.B16]
	mulRound(B6)
	mulRound(B7)

	MOVD	R5, R0
	reduce()
	B	octetsLoop

singlesStart:
	ADD	$14*16, R0
	VLD1	(R0), [T1.B16, T2.B16]

singlesLoop:
	CMP	$16, R3
	BLT	done
	SUB	$16, R3

	VLD1.P	16(R1), [B0.B16]
	VREV64	B0.B16, B0.B16
	VEOR	ACC0.B16, B0.B16, B0.B16

	VEXT	$8, B0.B16, B0.B16, T0.B16
	VEOR	B0.B16, T0.B16, T0.B16
	VPMULL	B0.D1, T1.D1, ACC1.Q1
	VPMULL2	B0.D2, T1.D2, ACC0.Q1
	VPMULL	T0.D1, T2.D1, ACCM.Q1

	reduce()
	B	singlesLoop

done:
	VREV64	ACC0.B16, ACC0.B16
	VST1	[ACC0.B16], (R2)
	RET
