/**
 * @file rp_evidence.h
 * @brief DRA-TLS Steps 2a and 2b: appraise the Attester's evidence, then
 * privacy-clean it into the bundle each Verifier receives.
 *
 * Step 2a runs against the *raw* log and is a hard gate -- nothing is
 * forwarded if it fails. Step 2b then redacts that log, replays it into
 * PCR_r and signs Quote_r. The Attester's raw log never leaves this module.
 */

#ifndef CHARRA_RP_EVIDENCE_H
#define CHARRA_RP_EVIDENCE_H

#include <stdbool.h>
#include <stdint.h>

#include "../common/charra_error.h"
#include "../core/charra_dto.h"

/**
 * @brief Step 2a -- local verification of the Attester's evidence.
 *
 * Runs all six spec checks in order: the Attester's RP-issued AK
 * certificate, the Quote_a signature, nonce freshness, each log entry's
 * self-consistency, the replayed PCR digest, and the file-hash policy.
 * Every check runs even after one fails, so one run reports everything
 * that is wrong rather than only the first thing.
 */
bool charra_rp_appraise_evidence(const msg_attestation_response_dto* res);

/**
 * @brief Step 2b -- redact the log, replay PCR_r, sign Quote_r.
 *
 * Called once per cycle, before any Verifier thread starts: the redaction
 * is randomised, so doing it per thread would hand each Verifier a
 * different log_r for the same attestation.
 */
CHARRA_RC charra_rp_prepare_evidence(void);

/** @brief Frees what charra_rp_prepare_evidence() allocated. */
void charra_rp_release_evidence(void);

/**
 * @brief Frees the heap fields of an /attest response DTO.
 *
 * Needed because the daemon loop runs this once per cycle; under the
 * original one-shot design nothing had to free them.
 */
void charra_free_attestation_response(msg_attestation_response_dto* res);

/**
 * @brief Builds and marshals the evidence message for one Verifier.
 *
 * Quote_r's signature covers (PCR_r || that Verifier's nonce), so each
 * Verifier gets a signature bound to the challenge it issued.
 */
CHARRA_RC charra_rp_build_evidence_message(
        int verifier_index, uint32_t* marshaled_len, uint8_t** marshaled);

#endif /* CHARRA_RP_EVIDENCE_H */
