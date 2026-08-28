/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file charra_poseidon.h
 * @brief Poseidon commitment over BN254, matching the ZK circuit exactly.
 *
 * The RP redacts each measured path to Poseidon(path, salt) and the circuit
 * proves that commitment corresponds to a path that really was measured. For
 * that to work, this implementation and zk/circuit/src/commit.nr must agree
 * bit for bit on every input.
 *
 * It therefore mirrors Noir's poseidon/bn254 `hash_7` -- the x5_8 instance,
 * t = 8, 8 full rounds, 64 partial, alpha = 5 -- including its use of the
 * optimised circomlib permutation. A textbook Poseidon with the same nominal
 * parameters produces different output; see charra_poseidon_consts.h.
 *
 * Correctness is not argued, it is checked: tests/test_poseidon.c runs the
 * 33 commitments the circuit itself produced for the real IMA log through
 * this code and requires every one to match.
 */

#ifndef CHARRA_POSEIDON_H
#define CHARRA_POSEIDON_H

#include <stdint.h>

#include "../common/charra_error.h"

/** Longest path (including its NUL) the circuit accepts; template.nr's
 *  MAX_PATH. Paths longer than this cannot be committed to. */
#define CHARRA_POSEIDON_MAX_PATH 136

/** Bytes per field limb when packing the path. 31 keeps every limb below
 *  the BN254 prime unconditionally. */
#define CHARRA_POSEIDON_LIMB_BYTES 31

/** Path limbs: ceil(136 / 31) = 5. */
#define CHARRA_POSEIDON_LIMBS 5

/**
 * @brief Commit to a measured file path.
 *
 * Computes hash_7(limb0..limb4, path_len, salt) exactly as commit.nr does:
 * the path is zero-padded to CHARRA_POSEIDON_MAX_PATH and packed big-endian
 * into five 31-byte limbs, then path_len and the salt are appended.
 *
 * path_len is committed to as well. Without it, a path and the same path
 * with its trailing NUL dropped would pack to identical bytes and collide.
 *
 * @param path      the n-ng field: the path INCLUDING its trailing NUL.
 * @param path_len  its length, at most CHARRA_POSEIDON_MAX_PATH.
 * @param salt      32 bytes from a CSPRNG, reduced mod the BN254 prime
 *                  before use. Must never be reused across entries or runs:
 *                  the space of plausible system paths is small enough to
 *                  enumerate, so an unsalted or repeated commitment is
 *                  recoverable and linkable.
 * @param out       the commitment, 32 bytes big-endian.
 */
CHARRA_RC charra_poseidon_commit(const uint8_t* path, uint32_t path_len,
        const uint8_t salt[32], uint8_t out[32]);

#endif /* CHARRA_POSEIDON_H */
