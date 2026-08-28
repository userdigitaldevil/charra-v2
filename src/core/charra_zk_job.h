/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file charra_zk_job.h
 * @brief Ask the proof watcher to prove or verify, and wait for the answer.
 *
 * bb cannot run in this container -- it is x86_64 under Rosetta, and Rosetta
 * does not emulate the ADX instructions barretenberg needs, so bb dies with
 * SIGILL regardless of version. zk/proof_watcher.sh runs on the arm64 host
 * and does the work; this is the client side of that handoff.
 *
 * The scaffolding is not part of the design: in a real deployment the RP and
 * Verifier would each invoke a local bb. Nothing here is load-bearing for
 * security -- the Verifier supplies its own verification key and builds its
 * own public inputs, so a compromised watcher can cause a failure but cannot
 * cause a false accept.
 *
 * See ZK_REDACTION.md section 5.
 */

#ifndef CHARRA_ZK_JOB_H
#define CHARRA_ZK_JOB_H

#include <stdbool.h>
#include <stdint.h>

#include "../common/charra_error.h"
#include "charra_zk.h"

/** Job queue root; override with CHARRA_ZK_JOBS. */
#define CHARRA_ZK_JOBS_DEFAULT "zk/jobs"

/** Verification key proofs are checked against, unless
 *  --zk-verification-key says otherwise. It must be the key for the exact
 *  circuit the RP proves with: recompiling the circuit changes the key, and a
 *  mismatched one rejects every proof. */
#define CHARRA_ZK_VK_DEFAULT "zk/vk"

/** How long to wait for the watcher before giving up. Proving takes about
 *  ten seconds; this is generous enough to absorb a queue but short enough
 *  that a watcher which is not running fails the attestation rather than
 *  hanging it forever. Override with CHARRA_ZK_TIMEOUT (seconds). */
#define CHARRA_ZK_TIMEOUT_DEFAULT 120

/**
 * @brief Public inputs, as the Verifier reconstructs them.
 *
 * Every one of these must come from something the Verifier has already
 * checked itself -- file hashes and commitments out of log_r, pcrdigest_a
 * out of the signature-verified Quote_a. Taking any of them from the RP
 * would let a valid proof of a fabricated log verify.
 *
 * PCR 0-7 are not stored: an IMA log never extends them, so they are zero,
 * and if that were ever false the proof would simply fail to verify.
 */
typedef struct charra_zk_public_inputs {
    uint8_t file_hashes[CHARRA_ZK_MAX_ENTRIES][32];
    uint8_t commitments[CHARRA_ZK_MAX_ENTRIES][32];
    uint8_t pcrdigest_a[32];
    /** How many of the arrays above are real entries; the circuit treats the
     * rest as padding.
     *
     * Counted by the Verifier from the log_r it is appraising, never taken
     * from the RP. If the RP set it, it could mark entries as padding to drop
     * them from the replay -- the `nreal` case in zk/negative_test.sh. */
    uint32_t n_real;
} charra_zk_public_inputs;

/**
 * @brief Produce a proof for this witness.
 *
 * @param witness    paths and salts included; never transmitted.
 * @param proof      allocated on success; caller frees.
 *
 * Returns CHARRA_RC_ERROR if the log does not replay to pcrdigest_a. That is
 * an attestation failure rather than a tooling failure, and it is logged as
 * such -- the two must not be confused.
 */
CHARRA_RC charra_zk_prove(const charra_zk_witness* witness, uint8_t** proof,
        uint32_t* proof_len);

/**
 * @brief Check a proof against public inputs the caller built itself.
 *
 * @param verified  set to the verdict. A false verdict is a *successful*
 *                  call: the return code says whether the check could be
 *                  performed, `verified` says what it concluded. Treating a
 *                  crashed verifier as a rejection is safe; treating it as
 *                  an accept is not, so they are kept separate.
 */
CHARRA_RC charra_zk_verify(const uint8_t* proof, uint32_t proof_len,
        const charra_zk_public_inputs* inputs, bool* verified);

/**
 * @brief Point verification at a specific verification key.
 *
 * Copied into every verify job, so the proof is checked against the key this
 * Verifier trusts rather than whichever one happens to sit in the
 * repository. NULL or unset means CHARRA_ZK_VK_DEFAULT.
 */
void charra_zk_set_verification_key_path(const char* path);

#endif /* CHARRA_ZK_JOB_H */
