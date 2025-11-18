/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * API wrapper for mldsa-native integration
 *
 * This file provides the bridge between leancrypto's Dilithium API
 * and the mldsa-native implementation. It uses mldsa-native for all
 * operations, with leancrypto's FIPS202 for streaming API hashing.
 */

#include "compare.h"
#include "dilithium_type.h"
#include "dilithium_selftest.h"
#include "visibility.h"
#include "../../../hash/api/lc_sha3.h"
#include "../../../hash/api/lc_sha256.h"
#include "../../../hash/api/lc_sha512.h"
#include "../../../internal/api/lc_memset_secure.h"
#include "../../../drng/api/lc_rng.h"
#include "signature_domain_separation.h"

#include "mldsa_native_all.h"

/* Extract tr from secret key */
static inline void unpack_sk_tr(uint8_t tr[LC_DILITHIUM_TRBYTES],
				const struct lc_dilithium_sk *sk)
{
	memcpy(tr, sk->sk + 2 * LC_DILITHIUM_SEEDBYTES, LC_DILITHIUM_TRBYTES);
}

/*
 * Keypair generation from seed using mldsa-native
 */
static int lc_dilithium_keypair_from_seed_mldsa(struct lc_dilithium_pk *pk,
						  struct lc_dilithium_sk *sk,
						  const uint8_t *seed,
						  size_t seedlen)
{
	if (!pk || !sk || !seed)
		return -EINVAL;

	if (seedlen < MLDSA_SEEDBYTES)
		return -EINVAL;

	return lc_mldsa_native_keypair_internal(pk->pk, sk->sk, seed);
}

/*
 * Keypair generation using mldsa-native
 */
static int lc_dilithium_keypair_mldsa(struct lc_dilithium_pk *pk,
				       struct lc_dilithium_sk *sk,
				       struct lc_rng_ctx *rng_ctx)
{
	uint8_t seed[MLDSA_SEEDBYTES];
	int ret;

	if (!pk || !sk || !rng_ctx)
		return -EINVAL;

	/* Generate seed using leancrypto's RNG */
	ret = lc_rng_generate(rng_ctx, NULL, 0, seed, sizeof(seed));
	if (ret)
		return ret;

	/* Generate keypair from seed */
	ret = lc_mldsa_native_keypair_internal(pk->pk, sk->sk, seed);
	lc_memset_secure(seed, 0, sizeof(seed));

	return ret;
}

/*
 * Signature verification using mldsa-native
 */
static int lc_dilithium_verify_mldsa(const struct lc_dilithium_sig *sig,
				      const uint8_t *m, size_t mlen,
				      const struct lc_dilithium_pk *pk)
{
	uint8_t pre[2];
	int ret;

	if (!sig || !m || !pk)
		return -EINVAL;

	// Construct domain separation prefix for pure ML-DSA with no context
	pre[0] = 0;
	pre[1] = 0;

	ret = lc_mldsa_native_verify_internal(sig->sig, MLDSA_SIG_BYTES,
		m, mlen, pre, 2, pk->pk, 0);

	// Convert mldsa-native error code: -1 means verification failed
	return (ret == -1) ? -EBADMSG : ret;
}

/*
 * Streaming signature generation using mldsa-native pre-hash API
 */
/*
 * Signature generation using mldsa-native
 */

/*
 * Streaming signature init using mldsa-native
 */
static int lc_dilithium_sign_init_mldsa(struct lc_dilithium_ctx *ctx,
					 const struct lc_dilithium_sk *sk)
{
	uint8_t tr[LC_DILITHIUM_TRBYTES];
	struct lc_hash_ctx *hash_ctx;
	int ret;

	if (!ctx || !sk)
		return -EINVAL;

	hash_ctx = &ctx->dilithium_hash_ctx;

	/* Require the use of SHAKE256 */
	if (hash_ctx->hash != lc_shake256)
		return -EOPNOTSUPP;

	unpack_sk_tr(tr, sk);

	/* Initialize hash and add tr */
	ret = lc_hash_init(hash_ctx);
	if (ret)
		return ret;
	lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
	lc_memset_secure(tr, 0, sizeof(tr));

	/* Apply domain separation */
	return signature_domain_separation(
		&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
		ctx->dilithium_prehash_type, ctx->userctx, ctx->userctxlen,
		NULL, 0, ctx->randomizer, ctx->randomizerlen,
		LC_DILITHIUM_NIST_CATEGORY);
}

static int lc_dilithium_sign_update_mldsa(struct lc_dilithium_ctx *ctx,
					   const uint8_t *m, size_t mlen)
{
	if (!ctx || !m)
		return -EINVAL;

	/* Continue hashing the message */
	lc_hash_update(&ctx->dilithium_hash_ctx, m, mlen);

	return 0;
}

static int lc_dilithium_sign_final_mldsa(struct lc_dilithium_sig *sig,
					  struct lc_dilithium_ctx *ctx,
					  const struct lc_dilithium_sk *sk,
					  struct lc_rng_ctx *rng_ctx)
{
	uint8_t mu[LC_DILITHIUM_CRHBYTES];
	uint8_t rnd[MLDSA_RNDBYTES];
	size_t siglen;
	int ret;

	if (!sig || !ctx || !sk)
		return -EINVAL;

	/* Finalize the hash to get mu */
	lc_hash_set_digestsize(&ctx->dilithium_hash_ctx, sizeof(mu));
	lc_hash_final(&ctx->dilithium_hash_ctx, mu);

	/* Generate or use deterministic random bytes */
	if (rng_ctx) {
		ret = lc_rng_generate(rng_ctx, NULL, 0, rnd, sizeof(rnd));
		if (ret)
			goto out;
	} else {
		memset(rnd, 0, sizeof(rnd));
	}

	/* Sign with external mu */
	ret = lc_mldsa_native_signature_internal(sig->sig, &siglen,
		mu, sizeof(mu), NULL, 0, rnd, sk->sk, 1);

out:
	lc_memset_secure(rnd, 0, sizeof(rnd));
	lc_memset_secure(mu, 0, sizeof(mu));
	lc_hash_zero(&ctx->dilithium_hash_ctx);

	return ret;
}

static int lc_dilithium_sign_ctx_mldsa(struct lc_dilithium_sig *sig,
					struct lc_dilithium_ctx *ctx,
					const uint8_t *m, size_t mlen,
					const struct lc_dilithium_sk *sk,
					struct lc_rng_ctx *rng_ctx)
{
	uint8_t rnd[MLDSA_RNDBYTES];
	uint8_t pre[512]; /* TODO: Doesn't need to be that large */
	size_t prelen;
	size_t siglen;
	int ret;

	// Generate or use deterministic random bytes
	if (rng_ctx) {
		ret = lc_rng_generate(rng_ctx, NULL, 0, rnd, sizeof(rnd));
		if (ret)
			goto out;
	} else {
		memset(rnd, 0, sizeof(rnd));
	}

	// a) If external mu is provided, use it directly
	if (ctx->external_mu) {
		if (ctx->external_mu_len != LC_DILITHIUM_CRHBYTES) {
			ret = -EINVAL;
			goto out;
		}
		ret = lc_mldsa_native_signature_internal(sig->sig, &siglen,
			ctx->external_mu, ctx->external_mu_len, NULL, 0, rnd, sk->sk, 1);
	}
	// b) No external mu - check if pre-hashing is used
	else if (ctx->dilithium_prehash_type) {
		// b.2) Pre-hashing is used - determine prehash type and call API
		uint8_t prehash_type;

		// Map leancrypto hash type to mldsa-native prehash type
		if (ctx->dilithium_prehash_type == lc_sha256) {
			prehash_type = MLD_PREHASH_SHA2_256;
		} else if (ctx->dilithium_prehash_type == lc_sha512) {
			prehash_type = MLD_PREHASH_SHA2_512;
		} else if (ctx->dilithium_prehash_type == lc_shake256) {
			prehash_type = MLD_PREHASH_SHAKE_256;
		} else {
			ret = -EOPNOTSUPP;
			goto out;
		}

		ret = lc_mldsa_native_signature_pre_hash_internal(sig->sig, &siglen,
			m, mlen, ctx->userctx, ctx->userctxlen, rnd, sk->sk, prehash_type);
	} else {
		// b.1) No pre-hash, no external mu
		if (ctx->ml_dsa_internal) {
			// Internal API: no domain separation
			ret = lc_mldsa_native_signature_internal(sig->sig, &siglen,
				m, mlen, NULL, 0, rnd, sk->sk, 0);
		} else {
			// Standard API: construct domain separation prefix
			if (ctx->userctxlen > 255) {
				ret = -EINVAL;
				goto out;
			}

			// Construct prefix: 0x00 || ctxlen || ctx
			pre[0] = 0;
			pre[1] = (uint8_t)ctx->userctxlen;
			if (ctx->userctxlen > 0) {
				memcpy(pre + 2, ctx->userctx, ctx->userctxlen);
			}
			prelen = 2 + ctx->userctxlen;

			ret = lc_mldsa_native_signature_internal(sig->sig, &siglen,
   			    m, mlen, pre, prelen, rnd, sk->sk, 0);
			if (ret != 0) {
			    return -EINVAL;
			}
		}
	}

	out:
		lc_memset_secure(rnd, 0, sizeof(rnd));
		lc_memset_secure(pre, 0, sizeof(pre));
		return ret;
}

static int lc_dilithium_sign_mldsa(struct lc_dilithium_sig *sig,
				    const uint8_t *m, size_t mlen,
				    const struct lc_dilithium_sk *sk,
				    struct lc_rng_ctx *rng_ctx)
{
	LC_DILITHIUM_CTX_ON_STACK(dilithium_ctx);
	int ret = lc_dilithium_sign_ctx_mldsa(sig, dilithium_ctx, m, mlen, sk,
					      rng_ctx);

	lc_dilithium_ctx_zero(dilithium_ctx);
	return ret;
}

/*
 * Streaming verification using mldsa-native pre-hash API
 */

/*
 * Streaming verification init using mldsa-native
 */
static int lc_dilithium_verify_init_mldsa(struct lc_dilithium_ctx *ctx,
					   const struct lc_dilithium_pk *pk)
{
	uint8_t mu[LC_DILITHIUM_TRBYTES];
	struct lc_hash_ctx *hash_ctx;
	int ret;

	if (!ctx || !pk)
		return -EINVAL;

	hash_ctx = &ctx->dilithium_hash_ctx;

	/* Require the use of SHAKE256 */
	if (hash_ctx->hash != lc_shake256)
		return -EOPNOTSUPP;

	/* Compute CRH(H(rho, t1), msg) */
	ret = lc_xof(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES, mu,
		     LC_DILITHIUM_TRBYTES);
	if (ret)
		return ret;

	ret = lc_hash_init(hash_ctx);
	if (ret)
		return ret;
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_TRBYTES);
	lc_memset_secure(mu, 0, sizeof(mu));

	/* Apply domain separation */
	return signature_domain_separation(
		&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
		ctx->dilithium_prehash_type, ctx->userctx, ctx->userctxlen,
		NULL, 0, ctx->randomizer, ctx->randomizerlen,
		LC_DILITHIUM_NIST_CATEGORY);
}

/*
 * Streaming verification update using mldsa-native
 */
static int lc_dilithium_verify_update_mldsa(struct lc_dilithium_ctx *ctx,
					     const uint8_t *m, size_t mlen)
{
	if (!ctx || !m)
		return -EINVAL;

	/* Continue hashing the message */
	lc_hash_update(&ctx->dilithium_hash_ctx, m, mlen);

	return 0;
}

/*
 * Streaming verification final using mldsa-native
 */
static int lc_dilithium_verify_final_mldsa(const struct lc_dilithium_sig *sig,
					    struct lc_dilithium_ctx *ctx,
					    const struct lc_dilithium_pk *pk)
{
	uint8_t mu[LC_DILITHIUM_CRHBYTES];
	int ret;

	if (!sig || !ctx || !pk)
		return -EINVAL;

	/* Finalize the hash to get mu */
	lc_hash_set_digestsize(&ctx->dilithium_hash_ctx, sizeof(mu));
	lc_hash_final(&ctx->dilithium_hash_ctx, mu);

	/* Verify with external mu */
	ret = lc_mldsa_native_verify_internal(sig->sig, MLDSA_SIG_BYTES,
		mu, sizeof(mu), NULL, 0, pk->pk, 1);

	lc_memset_secure(mu, 0, sizeof(mu));
	lc_hash_zero(&ctx->dilithium_hash_ctx);

	// Convert mldsa-native error code: -1 means verification failed
	return (ret == -1) ? -EBADMSG : ret;
}

static int lc_dilithium_verify_ctx_mldsa(const struct lc_dilithium_sig *sig,
					  struct lc_dilithium_ctx *ctx,
					  const uint8_t *m, size_t mlen,
					  const struct lc_dilithium_pk *pk)
{
	uint8_t pre[257];
	size_t prelen;
        int ret;

	if (!sig || !ctx || !pk)
		return -EINVAL;
	if (!m && !ctx->external_mu)
		return -EINVAL;

	// a) If external mu is provided, use verify_internal with externalmu=1
	if (ctx->external_mu) {
		if (ctx->external_mu_len != LC_DILITHIUM_CRHBYTES)
			return -EINVAL;
		ret = lc_mldsa_native_verify_internal(sig->sig, MLDSA_SIG_BYTES,
			ctx->external_mu, ctx->external_mu_len, NULL, 0, pk->pk, 1);
	}
	// b) No external mu - check if pre-hashing is used
	else if (ctx->dilithium_prehash_type) {
		// b.2) Pre-hashing is used - determine prehash type and call API
		uint8_t prehash_type;

		// Map leancrypto hash type to mldsa-native prehash type
		if (ctx->dilithium_prehash_type == lc_sha256) {
			prehash_type = MLD_PREHASH_SHA2_256;
		} else if (ctx->dilithium_prehash_type == lc_sha512) {
			prehash_type = MLD_PREHASH_SHA2_512;
		} else if (ctx->dilithium_prehash_type == lc_shake256) {
			prehash_type = MLD_PREHASH_SHAKE_256;
		} else {
			return -EOPNOTSUPP;
		}

		ret = lc_mldsa_native_verify_pre_hash_internal(sig->sig, MLDSA_SIG_BYTES,
			m, mlen, ctx->userctx, ctx->userctxlen, pk->pk, prehash_type);
	} else {
		// b.1) No pre-hash, no external mu
		if (ctx->ml_dsa_internal) {
			// Internal API: no domain separation
			ret = lc_mldsa_native_verify_internal(sig->sig, MLDSA_SIG_BYTES,
				m, mlen, NULL, 0, pk->pk, 0);
		} else {
			// Standard API: construct domain separation prefix
			if (ctx->userctxlen > 255)
				return -EINVAL;

			// Construct prefix: 0x00 || ctxlen || ctx
			pre[0] = 0;
			pre[1] = (uint8_t)ctx->userctxlen;
			if (ctx->userctxlen > 0) {
				memcpy(pre + 2, ctx->userctx, ctx->userctxlen);
			}
			prelen = 2 + ctx->userctxlen;

			ret = lc_mldsa_native_verify_internal(sig->sig, MLDSA_SIG_BYTES,
				m, mlen, pre, prelen, pk->pk, 0);

			lc_memset_secure(pre, 0, sizeof(pre));
		}
	}

	// Convert mldsa-native error code: -1 means verification failed
	return (ret == -1) ? -EBADMSG : ret;
}

/*
 * Interface functions - all using mldsa-native
 */

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_from_seed,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      const uint8_t *seed, size_t seedlen)
{
	dilithium_keypair_tester(lc_dilithium_keypair_from_seed_mldsa);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_KEYGEN);

	return lc_dilithium_keypair_from_seed_mldsa(pk, sk, seed, seedlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair, struct lc_dilithium_pk *pk,
		      struct lc_dilithium_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	dilithium_keypair_tester(lc_dilithium_keypair_from_seed_mldsa);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_KEYGEN);

	return lc_dilithium_keypair_mldsa(pk, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign, struct lc_dilithium_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	dilithium_siggen_tester(lc_dilithium_sign_ctx_mldsa);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGGEN);

	return lc_dilithium_sign_mldsa(sig, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	/* Selftest expects streaming API signature */
	dilithium_sigver_tester(lc_dilithium_verify_ctx_mldsa);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_mldsa(sig, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_ctx, struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	/* Selftest uses streaming API */
	dilithium_siggen_tester(lc_dilithium_sign_ctx_mldsa);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGGEN);

	return lc_dilithium_sign_ctx_mldsa(sig, ctx, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_init, struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk)
{
	/* Selftest uses streaming API */
	dilithium_siggen_tester(lc_dilithium_sign_ctx_mldsa);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGGEN);

	return lc_dilithium_sign_init_mldsa(ctx, sk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_update,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_sign_update_mldsa(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_final,
		      struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_sign_final_mldsa(sig, ctx, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_ctx,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	/* Selftest uses streaming API */
	dilithium_sigver_tester(lc_dilithium_verify_ctx_mldsa);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_ctx_mldsa(sig, ctx, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	/* Selftest uses streaming API */
	dilithium_sigver_tester(lc_dilithium_verify_ctx_mldsa);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_init_mldsa(ctx, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_verify_update_mldsa(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_final_mldsa(sig, ctx, pk);
}
