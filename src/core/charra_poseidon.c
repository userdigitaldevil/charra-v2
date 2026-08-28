/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file charra_poseidon.c
 * @brief Poseidon x5_8 over BN254 -- see charra_poseidon.h.
 *
 * A direct transcription of `permute` from the Noir library the circuit
 * compiles against. Every structural choice here exists because Noir does it
 * that way, not because it is the natural way to write Poseidon:
 *
 *   - the partial rounds use sparse matrices and pre-folded round constants
 *     (circomlib's optimisation), so the round-constant indexing is not the
 *     textbook t*(round)+i;
 *   - apply_matrix is TRANSPOSED: out[i] = sum_j vec[j] * M[j][i];
 *   - hash_7 puts its inputs at state[1..8], leaving state[0] zero, and
 *     returns state[0] after permuting.
 *
 * Field arithmetic uses mbedTLS MPI, already a dependency. It is slow per
 * operation -- roughly 137k modular multiplications for a 33-entry log --
 * but that is a fraction of a second against a ten-second proof.
 */

#include "charra_poseidon.h"

#include <stdbool.h>
#include <string.h>

#include <mbedtls/bignum.h>

#include "../common/charra_log.h"
#include "charra_poseidon_consts.h"

#define LOG_NAME "poseidon"

#define T CHARRA_POSEIDON_T   /* 8  */
#define RF CHARRA_POSEIDON_RF /* 8  */
#define RP CHARRA_POSEIDON_RP /* 64 */
#define SPARSE_STRIDE (2 * T - 1) /* 15 */

/* --- constant table, parsed once ------------------------------------- */

typedef struct {
    bool ready;
    mbedtls_mpi p;
    mbedtls_mpi rc[CHARRA_POSEIDON_N_RC];
    mbedtls_mpi mds[T * T];
    mbedtls_mpi presparse[T * T];
    mbedtls_mpi sparse[CHARRA_POSEIDON_N_SPARSE];
} poseidon_consts;

static poseidon_consts g_consts = {0};

/* mbedtls_mpi_read_string() does not accept a "0x" prefix. */
static int read_hex(mbedtls_mpi* x, const char* s) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }
    return mbedtls_mpi_read_string(x, 16, s);
}

static int load_array(mbedtls_mpi* dst, const char* const* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        mbedtls_mpi_init(&dst[i]);
        int rc = read_hex(&dst[i], src[i]);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

static CHARRA_RC ensure_consts(void) {
    if (g_consts.ready) {
        return CHARRA_RC_SUCCESS;
    }
    mbedtls_mpi_init(&g_consts.p);
    if (read_hex(&g_consts.p, CHARRA_POSEIDON_P) != 0 ||
            load_array(g_consts.rc, CHARRA_POSEIDON_RC,
                    CHARRA_POSEIDON_N_RC) != 0 ||
            load_array(g_consts.mds, CHARRA_POSEIDON_MDS, T * T) != 0 ||
            load_array(g_consts.presparse, CHARRA_POSEIDON_PRESPARSE,
                    T * T) != 0 ||
            load_array(g_consts.sparse, CHARRA_POSEIDON_SPARSE,
                    CHARRA_POSEIDON_N_SPARSE) != 0) {
        charra_log_error("[" LOG_NAME "] Could not parse Poseidon constants.");
        return CHARRA_RC_CRYPTO_ERROR;
    }
    g_consts.ready = true;
    return CHARRA_RC_SUCCESS;
}

/* --- field arithmetic ------------------------------------------------- */

static int f_mul(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
    int rc = mbedtls_mpi_mul_mpi(r, a, b);
    if (rc != 0) {
        return rc;
    }
    return mbedtls_mpi_mod_mpi(r, r, &g_consts.p);
}

static int f_add(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
    int rc = mbedtls_mpi_add_mpi(r, a, b);
    if (rc != 0) {
        return rc;
    }
    return mbedtls_mpi_mod_mpi(r, r, &g_consts.p);
}

/* x^5, as Noir's sigma() computes it: t*t, then squared, then times t. */
static int f_pow5(mbedtls_mpi* x) {
    mbedtls_mpi tt, tttt;
    mbedtls_mpi_init(&tt);
    mbedtls_mpi_init(&tttt);
    int rc = f_mul(&tt, x, x);
    if (rc == 0) {
        rc = f_mul(&tttt, &tt, &tt);
    }
    if (rc == 0) {
        rc = f_mul(x, x, &tttt);
    }
    mbedtls_mpi_free(&tt);
    mbedtls_mpi_free(&tttt);
    return rc;
}

static int sigma(mbedtls_mpi state[T]) {
    for (size_t i = 0; i < T; i++) {
        int rc = f_pow5(&state[i]);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

/* out[i] = sum_j vec[j] * M[j][i]  -- note the transposed indexing. */
static int apply_matrix(const mbedtls_mpi* m, mbedtls_mpi state[T]) {
    mbedtls_mpi out[T], prod;
    for (size_t i = 0; i < T; i++) {
        mbedtls_mpi_init(&out[i]);
    }
    mbedtls_mpi_init(&prod);

    int rc = 0;
    for (size_t i = 0; i < T && rc == 0; i++) {
        for (size_t j = 0; j < T && rc == 0; j++) {
            rc = f_mul(&prod, &state[j], &m[j * T + i]);
            if (rc == 0) {
                rc = f_add(&out[i], &out[i], &prod);
            }
        }
    }
    if (rc == 0) {
        for (size_t i = 0; i < T; i++) {
            rc = mbedtls_mpi_copy(&state[i], &out[i]);
            if (rc != 0) {
                break;
            }
        }
    }

    for (size_t i = 0; i < T; i++) {
        mbedtls_mpi_free(&out[i]);
    }
    mbedtls_mpi_free(&prod);
    return rc;
}

/* --- the permutation -------------------------------------------------- */

static int permute(mbedtls_mpi state[T]) {
    int rc = 0;

    /* Initial ARK. */
    for (size_t i = 0; i < T && rc == 0; i++) {
        rc = f_add(&state[i], &state[i], &g_consts.rc[i]);
    }

    /* First half of the full rounds, less one. */
    for (size_t r = 0; r < RF / 2 - 1 && rc == 0; r++) {
        rc = sigma(state);
        for (size_t i = 0; i < T && rc == 0; i++) {
            rc = f_add(&state[i], &state[i], &g_consts.rc[T * (r + 1) + i]);
        }
        if (rc == 0) {
            rc = apply_matrix(g_consts.mds, state);
        }
    }

    /* The round that hands over to the sparse representation. */
    if (rc == 0) {
        rc = sigma(state);
    }
    for (size_t i = 0; i < T && rc == 0; i++) {
        rc = f_add(&state[i], &state[i], &g_consts.rc[T * (RF / 2) + i]);
    }
    if (rc == 0) {
        rc = apply_matrix(g_consts.presparse, state);
    }

    /* Partial rounds: S-box on state[0] only, sparse matrix for the rest. */
    mbedtls_mpi new0, prod;
    mbedtls_mpi_init(&new0);
    mbedtls_mpi_init(&prod);
    for (size_t r = 0; r < RP && rc == 0; r++) {
        rc = f_pow5(&state[0]);
        if (rc == 0) {
            rc = f_add(&state[0], &state[0],
                    &g_consts.rc[(RF / 2 + 1) * T + r]);
        }

        /* new0 must be accumulated from the OLD state[0..T), so compute it
         * before state[1..T) are updated below. */
        if (rc == 0) {
            rc = mbedtls_mpi_lset(&new0, 0);
        }
        for (size_t j = 0; j < T && rc == 0; j++) {
            rc = f_mul(&prod, &g_consts.sparse[SPARSE_STRIDE * r + j],
                    &state[j]);
            if (rc == 0) {
                rc = f_add(&new0, &new0, &prod);
            }
        }
        for (size_t k = 1; k < T && rc == 0; k++) {
            rc = f_mul(&prod, &state[0],
                    &g_consts.sparse[SPARSE_STRIDE * r + T + k - 1]);
            if (rc == 0) {
                rc = f_add(&state[k], &state[k], &prod);
            }
        }
        if (rc == 0) {
            rc = mbedtls_mpi_copy(&state[0], &new0);
        }
    }
    mbedtls_mpi_free(&new0);
    mbedtls_mpi_free(&prod);

    /* Second half of the full rounds, less one. */
    for (size_t r = 0; r < RF / 2 - 1 && rc == 0; r++) {
        rc = sigma(state);
        for (size_t i = 0; i < T && rc == 0; i++) {
            rc = f_add(&state[i], &state[i],
                    &g_consts.rc[(RF / 2 + 1) * T + RP + r * T + i]);
        }
        if (rc == 0) {
            rc = apply_matrix(g_consts.mds, state);
        }
    }

    /* Final round: no ARK. */
    if (rc == 0) {
        rc = sigma(state);
    }
    if (rc == 0) {
        rc = apply_matrix(g_consts.mds, state);
    }
    return rc;
}

/* --- public entry point ----------------------------------------------- */

CHARRA_RC charra_poseidon_commit(const uint8_t* path, uint32_t path_len,
        const uint8_t salt[32], uint8_t out[32]) {
    if (path == NULL || salt == NULL || out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (path_len > CHARRA_POSEIDON_MAX_PATH) {
        charra_log_error("[" LOG_NAME "] Path of %u bytes exceeds the %u the "
                         "circuit accepts.",
                path_len, CHARRA_POSEIDON_MAX_PATH);
        return CHARRA_RC_BAD_ARGUMENT;
    }

    CHARRA_RC charra_r = ensure_consts();
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    /* The circuit packs the zero-PADDED buffer, not just the real bytes. */
    uint8_t padded[CHARRA_POSEIDON_MAX_PATH] = {0};
    memcpy(padded, path, path_len);

    mbedtls_mpi state[T], byte, len_f, salt_f;
    for (size_t i = 0; i < T; i++) {
        mbedtls_mpi_init(&state[i]);
    }
    mbedtls_mpi_init(&byte);
    mbedtls_mpi_init(&len_f);
    mbedtls_mpi_init(&salt_f);

    int rc = 0;

    /* hash_7 places the seven inputs at state[1..8]; state[0] stays zero. */
    for (size_t l = 0; l < CHARRA_POSEIDON_LIMBS && rc == 0; l++) {
        mbedtls_mpi* acc = &state[1 + l];
        rc = mbedtls_mpi_lset(acc, 0);
        for (size_t j = 0; j < CHARRA_POSEIDON_LIMB_BYTES && rc == 0; j++) {
            size_t idx = l * CHARRA_POSEIDON_LIMB_BYTES + j;
            if (idx >= CHARRA_POSEIDON_MAX_PATH) {
                break; /* the last limb is only partly used */
            }
            rc = mbedtls_mpi_mul_int(acc, acc, 256);
            if (rc == 0) {
                rc = mbedtls_mpi_add_int(acc, acc, padded[idx]);
            }
        }
    }

    if (rc == 0) {
        rc = mbedtls_mpi_lset(&len_f, (mbedtls_mpi_sint)path_len);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_copy(&state[1 + CHARRA_POSEIDON_LIMBS], &len_f);
    }

    /* A 32-byte salt can exceed the field order, so reduce it. The value
     * fed to the circuit must be this reduced one. */
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&salt_f, salt, 32);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_mod_mpi(&salt_f, &salt_f, &g_consts.p);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_copy(&state[2 + CHARRA_POSEIDON_LIMBS], &salt_f);
    }

    if (rc == 0) {
        rc = permute(state);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary(&state[0], out, 32);
    }

    for (size_t i = 0; i < T; i++) {
        mbedtls_mpi_free(&state[i]);
    }
    mbedtls_mpi_free(&byte);
    mbedtls_mpi_free(&len_f);
    mbedtls_mpi_free(&salt_f);

    if (rc != 0) {
        charra_log_error("[" LOG_NAME "] Poseidon failed (mbedTLS %d).", rc);
        return CHARRA_RC_CRYPTO_ERROR;
    }
    return CHARRA_RC_SUCCESS;
}
