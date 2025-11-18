/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * Leancrypto configuration for mldsa-native integration
 *
 * This configuration adapts mldsa-native for use within leancrypto,
 * following the monolithic_build_multilevel pattern and using leancrypto's
 * FIPS202 and RNG implementations.
 */

#ifndef LEANCRYPTO_MLDSA_CONFIG_H
#define LEANCRYPTO_MLDSA_CONFIG_H

/* Map leancrypto's parameter set specification to mldsa-native's. */
#ifdef LC_DILITHIUM_TYPE_87
#define MLD_CONFIG_PARAMETER_SET 87
#elif defined(LC_DILITHIUM_TYPE_65)
#define MLD_CONFIG_PARAMETER_SET 65
#elif defined(LC_DILITHIUM_TYPE_44)
#define MLD_CONFIG_PARAMETER_SET 44
#else
#error "No LC_DILITHIUM_TYPE defined"
#endif

/* The prefix to use to namespace global symbols. */
#ifdef LC_DILITHIUM_TYPE_87
#define MLD_CONFIG_NAMESPACE_PREFIX mldsa_native_87
#elif defined(LC_DILITHIUM_TYPE_65)
#define MLD_CONFIG_NAMESPACE_PREFIX mldsa_native_65
#elif defined(LC_DILITHIUM_TYPE_44)
#define MLD_CONFIG_NAMESPACE_PREFIX mldsa_native_44
#else
#error "No LC_DILITHIUM_TYPE defined"
#endif

/* Use standard native arithmetic backends. */
#define MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLD_CONFIG_ARITH_BACKEND_FILE "native/meta.h"

/* Use leancrypto's FIPS202 implementation instead of mldsa-native's. */
#define MLD_CONFIG_FIPS202_CUSTOM_HEADER "custom_fips202.h"
#define MLD_CONFIG_FIPS202X4_CUSTOM_HEADER "custom_fips202x4.h"

/* Use leancrypto's RNG instead of requiring external randombytes(). */
#define MLD_CONFIG_CUSTOM_RANDOMBYTES
#if !defined(__ASSEMBLER__)
#include <stdint.h>
#include "mldsa-native/src/sys.h"
#include "../../../drng/api/lc_rng.h"
static MLD_INLINE void mld_randombytes(uint8_t *ptr, size_t len)
{
	lc_rng_generate(NULL, NULL, 0, ptr, len);
}
#endif /* !__ASSEMBLER__ */

/* Make internal API static for single-CU build. */
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static

#endif /* LEANCRYPTO_MLDSA_CONFIG_H */
