/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * Custom FIPS-202 wrapper for mldsa-native using leancrypto's SHA3/SHAKE
 *
 * This file provides the FIPS-202 API required by mldsa-native using
 * leancrypto's SHA3 implementation.
 */

#ifndef CUSTOM_FIPS202_H
#define CUSTOM_FIPS202_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "../../../hash/api/lc_sha3.h"
#include "../../../hash/api/lc_hash.h"
#include "../../../internal/api/lc_memset_secure.h"

/* We need the MLD_INLINE definition from sys.h */
#ifndef MLD_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define MLD_INLINE __attribute__((always_inline)) static inline
#else
#define MLD_INLINE static inline
#endif
#endif /* !MLD_INLINE */

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define SHA3_256_HASHBYTES 32
#define SHA3_512_HASHBYTES 64

/* SHAKE128 context wrapping leancrypto's SHA3 context */
typedef struct {
	struct lc_hash_ctx hash_ctx;
	uint8_t shake_state[LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_256_CTX_SIZE)];
//	uint8_t shake_state[LC_SHA3_STATE_SIZE_ALIGN(LC_SHAKE_128_STATE_SIZE)];
} mld_shake128ctx;

/* SHAKE256 context wrapping leancrypto's SHA3 context */
typedef struct {
	struct lc_hash_ctx hash_ctx;
	uint8_t shake_state[LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_256_CTX_SIZE)];
} mld_shake256ctx;

/*************************************************
 * Name:        mld_shake128_init
 *
 * Description: Initializes state for use as SHAKE128 XOF
 *
 * Arguments:   - mld_shake128ctx *state: pointer to (uninitialized) state
 **************************************************/
#define mld_shake128_init MLD_NAMESPACE(shake128_init)
static MLD_INLINE void mld_shake128_init(mld_shake128ctx *state)
{
	LC_SHAKE_128_CTX((&state->hash_ctx));
	lc_hash_init(&state->hash_ctx);
}

/*************************************************
 * Name:        mld_shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 XOF
 *
 * Arguments:   - mld_shake128ctx *state: pointer to (initialized) state
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
#define mld_shake128_absorb MLD_NAMESPACE(shake128_absorb)
static MLD_INLINE void mld_shake128_absorb(mld_shake128ctx *state,
					   const uint8_t *in, size_t inlen)
{
	lc_hash_update(&state->hash_ctx, in, inlen);
}

/*************************************************
 * Name:        mld_shake128_finalize
 *
 * Description: Concludes the absorb phase of the SHAKE128 XOF
 *
 * Arguments:   - mld_shake128ctx *state: pointer to state
 **************************************************/
#define mld_shake128_finalize MLD_NAMESPACE(shake128_finalize)
static MLD_INLINE void mld_shake128_finalize(mld_shake128ctx *state)
{
	/* In leancrypto, finalization happens implicitly during squeeze */
	(void)state;
}

/*************************************************
 * Name:        mld_shake128_squeeze
 *
 * Description: Squeeze step of SHAKE128 XOF
 *
 * Arguments:   - uint8_t *out: pointer to output blocks
 *              - size_t outlen: number of bytes to be squeezed
 *              - mld_shake128ctx *state: pointer to state
 **************************************************/
#define mld_shake128_squeeze MLD_NAMESPACE(shake128_squeeze)
static MLD_INLINE void mld_shake128_squeeze(uint8_t *out, size_t outlen,
					    mld_shake128ctx *state)
{
	lc_hash_set_digestsize(&state->hash_ctx, outlen);
	lc_hash_final(&state->hash_ctx, out);
}

/*************************************************
 * Name:        mld_shake128_release
 *
 * Description: Release and securely zero the SHAKE128 state
 *
 * Arguments:   - mld_shake128ctx *state: pointer to state
 **************************************************/
#define mld_shake128_release MLD_NAMESPACE(shake128_release)
static MLD_INLINE void mld_shake128_release(mld_shake128ctx *state)
{
	lc_memset_secure(state, 0, sizeof(mld_shake128ctx));
}

/*************************************************
 * Name:        mld_shake256_init
 *
 * Description: Initializes state for use as SHAKE256 XOF
 *
 * Arguments:   - mld_shake256ctx *state: pointer to (uninitialized) state
 **************************************************/
#define mld_shake256_init MLD_NAMESPACE(shake256_init)
static MLD_INLINE void mld_shake256_init(mld_shake256ctx *state)
{
	LC_SHAKE_256_CTX((&state->hash_ctx));
	lc_hash_init(&state->hash_ctx);
}

/*************************************************
 * Name:        mld_shake256_absorb
 *
 * Description: Absorb step of the SHAKE256 XOF
 *
 * Arguments:   - mld_shake256ctx *state: pointer to (initialized) state
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
#define mld_shake256_absorb MLD_NAMESPACE(shake256_absorb)
static MLD_INLINE void mld_shake256_absorb(mld_shake256ctx *state,
					   const uint8_t *in, size_t inlen)
{
	lc_hash_update(&state->hash_ctx, in, inlen);
}

/*************************************************
 * Name:        mld_shake256_finalize
 *
 * Description: Concludes the absorb phase of the SHAKE256 XOF
 *
 * Arguments:   - mld_shake256ctx *state: pointer to state
 **************************************************/
#define mld_shake256_finalize MLD_NAMESPACE(shake256_finalize)
static MLD_INLINE void mld_shake256_finalize(mld_shake256ctx *state)
{
	/* In leancrypto, finalization happens implicitly during squeeze */
	(void)state;
}

/*************************************************
 * Name:        mld_shake256_squeeze
 *
 * Description: Squeeze step of SHAKE256 XOF
 *
 * Arguments:   - uint8_t *out: pointer to output blocks
 *              - size_t outlen: number of bytes to be squeezed
 *              - mld_shake256ctx *state: pointer to state
 **************************************************/
#define mld_shake256_squeeze MLD_NAMESPACE(shake256_squeeze)
static MLD_INLINE void mld_shake256_squeeze(uint8_t *out, size_t outlen,
					    mld_shake256ctx *state)
{
	lc_hash_set_digestsize(&state->hash_ctx, outlen);
	lc_hash_final(&state->hash_ctx, out);
}

/*************************************************
 * Name:        mld_shake256_release
 *
 * Description: Release and securely zero the SHAKE256 state
 *
 * Arguments:   - mld_shake256ctx *state: pointer to state
 **************************************************/
#define mld_shake256_release MLD_NAMESPACE(shake256_release)
static MLD_INLINE void mld_shake256_release(mld_shake256ctx *state)
{
	lc_memset_secure(state, 0, sizeof(mld_shake256ctx));
}

/*************************************************
 * Name:        mld_shake256
 *
 * Description: SHAKE256 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
#define mld_shake256 MLD_NAMESPACE(shake256)
static MLD_INLINE void mld_shake256(uint8_t *out, size_t outlen,
				    const uint8_t *in, size_t inlen)
{
	LC_SHAKE_256_CTX_ON_STACK(ctx);

	lc_hash_init(ctx);
	lc_hash_update(ctx, in, inlen);
	lc_hash_set_digestsize(ctx, outlen);
	lc_hash_final(ctx, out);
	lc_hash_zero(ctx);
}

#endif /* !CUSTOM_FIPS202_H */
