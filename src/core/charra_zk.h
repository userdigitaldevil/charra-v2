/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file charra_zk.h
 * @brief Witness data for the zero-knowledge redaction proof.
 *
 * Redaction throws away exactly what the proof needs: the real paths and the
 * salts they were committed under. Both must stay on the RP -- neither ever
 * leaves it -- so they are collected while redacting and handed straight to
 * the prover.
 *
 * See ZK_REDACTION.md.
 */

#ifndef CHARRA_ZK_H
#define CHARRA_ZK_H

#include <stdint.h>

#include "../common/charra_error.h"
#include "charra_poseidon.h"

/**
 * Entries the circuit is compiled for. A circuit has no runtime loop bound,
 * so this is fixed at compile time and a log of any other length cannot be
 * proved without recompiling and redistributing the verification key.
 * ZK_REDACTION.md section 7 covers what generalising this would cost.
 */
#define CHARRA_ZK_NUM_ENTRIES 33

/** One entry's witness. `path` and `salt` are secret and must not be
 *  marshaled into any message. */
typedef struct charra_zk_entry {
    uint8_t path[CHARRA_POSEIDON_MAX_PATH]; /**< n-ng field, with its NUL */
    uint32_t path_len;
    uint8_t salt[32];       /**< CSPRNG, never reused, never transmitted */
    uint8_t file_hash[32];  /**< public: the Verifier appraises against it */
    uint8_t commitment[32]; /**< Poseidon(path, salt), as it appears in log_r */
} charra_zk_entry;

typedef struct charra_zk_witness {
    uint32_t num_entries;
    uint8_t pcrdigest_a[32]; /**< filled in by the caller from Quote_a */
    charra_zk_entry entries[CHARRA_ZK_NUM_ENTRIES];
} charra_zk_witness;

/**
 * @brief Write the witness as the JSON the prover consumes.
 *
 * Same shape zk/dump_witness.c emits, so zk/gen_prover_toml.py reads either
 * without knowing which produced it.
 *
 * The file contains secrets. It is written into the job directory the proof
 * watcher reads and should be removed once the proof is collected.
 */
CHARRA_RC charra_zk_write_witness_json(
        const charra_zk_witness* witness, const char* path);

#endif /* CHARRA_ZK_H */
