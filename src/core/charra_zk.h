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

struct charra_zk_public_inputs;

/**
 * The MOST entries the circuit can prove -- main.nr's `global N`. A circuit
 * has no runtime loop bound, so this is fixed at compile time. Shorter logs
 * are fine: n_real marks the padding, and the Verifier ties it to log_r's own
 * entry count so the RP cannot understate it to hide entries.
 *
 * Every proof still pays for all N slots whatever n_real says -- padding is
 * computed and then discarded, because a circuit can only select between
 * results, never skip them. A longer log cannot be proved at all without
 * raising N, recompiling, and redistributing zk/vk.
 */
#define CHARRA_ZK_MAX_ENTRIES 33

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
    charra_zk_entry entries[CHARRA_ZK_MAX_ENTRIES];
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

/**
 * @brief Rebuild the proof's public inputs from log_r and the signed quote.
 *
 * The Verifier must never take these from the RP. A proof is only ever a
 * proof *about its public inputs* -- accept the RP's copy and a genuine
 * proof of a fabricated log verifies perfectly. So the file hashes and
 * commitments are read out of the log_r the Verifier is appraising, and
 * pcrdigest_a comes from the Quote_a whose signature it has already checked
 * against the trust anchor.
 *
 * @param log_r        the redacted log, as received.
 * @param pcrdigest_a  from attest_struct.attested.quote.pcrDigest.
 * @param out          filled in on success.
 */
CHARRA_RC charra_zk_public_inputs_from_log_r(const uint8_t* log_r,
        uint32_t log_r_len, const uint8_t pcrdigest_a[32],
        struct charra_zk_public_inputs* out);

#endif /* CHARRA_ZK_H */
