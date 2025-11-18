/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * Custom FIPS-202 x4 wrapper for mldsa-native
 *
 * This provides serial fallback implementations for vectorized SHAKE operations.
 */

#ifndef CUSTOM_FIPS202X4_H
#define CUSTOM_FIPS202X4_H

#include "custom_fips202.h"

/* x4 contexts - fall back to 4 separate contexts */
typedef struct {
	mld_shake128ctx ctx[4];
} mld_shake128x4ctx;

typedef struct {
	mld_shake256ctx ctx[4];
} mld_shake256x4ctx;

/* SHAKE128 x4 functions - serial implementation */
#define mld_shake128x4_init MLD_NAMESPACE(shake128x4_init)
static MLD_INLINE void mld_shake128x4_init(mld_shake128x4ctx *state)
{
	for (int i = 0; i < 4; i++)
		mld_shake128_init(&state->ctx[i]);
}

#define mld_shake128x4_absorb_once MLD_NAMESPACE(shake128x4_absorb_once)
static MLD_INLINE void mld_shake128x4_absorb_once(
	mld_shake128x4ctx *state,
	const uint8_t *in0, const uint8_t *in1,
	const uint8_t *in2, const uint8_t *in3,
	size_t inlen)
{
	mld_shake128_absorb(&state->ctx[0], in0, inlen);
	mld_shake128_finalize(&state->ctx[0]);
	mld_shake128_absorb(&state->ctx[1], in1, inlen);
	mld_shake128_finalize(&state->ctx[1]);
	mld_shake128_absorb(&state->ctx[2], in2, inlen);
	mld_shake128_finalize(&state->ctx[2]);
	mld_shake128_absorb(&state->ctx[3], in3, inlen);
	mld_shake128_finalize(&state->ctx[3]);
}

#define mld_shake128x4_squeezeblocks MLD_NAMESPACE(shake128x4_squeezeblocks)
static MLD_INLINE void mld_shake128x4_squeezeblocks(
	uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
	size_t nblocks, mld_shake128x4ctx *state)
{
	size_t outlen = nblocks * SHAKE128_RATE;
	mld_shake128_squeeze(out0, outlen, &state->ctx[0]);
	mld_shake128_squeeze(out1, outlen, &state->ctx[1]);
	mld_shake128_squeeze(out2, outlen, &state->ctx[2]);
	mld_shake128_squeeze(out3, outlen, &state->ctx[3]);
}

#define mld_shake128x4_release MLD_NAMESPACE(shake128x4_release)
static MLD_INLINE void mld_shake128x4_release(mld_shake128x4ctx *state)
{
	for (int i = 0; i < 4; i++)
		mld_shake128_release(&state->ctx[i]);
}

/* SHAKE256 x4 functions - serial implementation */
#define mld_shake256x4_init MLD_NAMESPACE(shake256x4_init)
static MLD_INLINE void mld_shake256x4_init(mld_shake256x4ctx *state)
{
	for (int i = 0; i < 4; i++)
		mld_shake256_init(&state->ctx[i]);
}

#define mld_shake256x4_absorb_once MLD_NAMESPACE(shake256x4_absorb_once)
static MLD_INLINE void mld_shake256x4_absorb_once(
	mld_shake256x4ctx *state,
	const uint8_t *in0, const uint8_t *in1,
	const uint8_t *in2, const uint8_t *in3,
	size_t inlen)
{
	mld_shake256_absorb(&state->ctx[0], in0, inlen);
	mld_shake256_finalize(&state->ctx[0]);
	mld_shake256_absorb(&state->ctx[1], in1, inlen);
	mld_shake256_finalize(&state->ctx[1]);
	mld_shake256_absorb(&state->ctx[2], in2, inlen);
	mld_shake256_finalize(&state->ctx[2]);
	mld_shake256_absorb(&state->ctx[3], in3, inlen);
	mld_shake256_finalize(&state->ctx[3]);
}

#define mld_shake256x4_squeezeblocks MLD_NAMESPACE(shake256x4_squeezeblocks)
static MLD_INLINE void mld_shake256x4_squeezeblocks(
	uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
	size_t nblocks, mld_shake256x4ctx *state)
{
	size_t outlen = nblocks * SHAKE256_RATE;
	mld_shake256_squeeze(out0, outlen, &state->ctx[0]);
	mld_shake256_squeeze(out1, outlen, &state->ctx[1]);
	mld_shake256_squeeze(out2, outlen, &state->ctx[2]);
	mld_shake256_squeeze(out3, outlen, &state->ctx[3]);
}

#define mld_shake256x4_release MLD_NAMESPACE(shake256x4_release)
static MLD_INLINE void mld_shake256x4_release(mld_shake256x4ctx *state)
{
	for (int i = 0; i < 4; i++)
		mld_shake256_release(&state->ctx[i]);
}

#endif /* !CUSTOM_FIPS202X4_H */
