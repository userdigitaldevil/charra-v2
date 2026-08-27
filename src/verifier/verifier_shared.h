/**
 * @file verifier_shared.h
 * @brief State one Verifier module defines and another needs.
 *
 * A libcoap handler signature is fixed, so per-round state has nowhere to
 * live but file scope. Each item below is *defined* by the module that
 * produces it and declared here only for the modules that consume it;
 * anything a single module owns end to end stays static in that module and
 * does not appear here. Giving this state a proper per-session home is a
 * separate job -- and the one that lifts the "one attestation round in
 * flight at a time" limit it currently imposes.
 *
 * Keep the declarations here in sync with their definitions -- a mismatch
 * is a link error, not a silent bug.
 */

#ifndef CHARRA_VERIFIER_SHARED_H
#define CHARRA_VERIFIER_SHARED_H

#include <stdint.h>

#include <tss2/tss2_tpm2_types.h>

#include "../core/charra_dto.h"

/* --- per-round challenge state (defined in verifier_nonce.c) ------------
 * Issued by /nonce, consumed by /appraise. Single slots, so exactly one
 * attestation round can be in flight per Verifier process. */

/** The nonce the RP gave the ATTESTER, needed for Quote_a's freshness check
 * (Step 3b item 3). Spent by /appraise once checked. */
extern msg_attestation_request_dto last_request;

/** This Verifier's OWN freshness challenge for Quote_r (Step 3a item 3).
 * Deliberately distinct from last_request.nonce: a nonce the RP chose
 * itself proves nothing to the Verifier. Spent by /appraise once checked. */
extern uint8_t verifier_challenge_nonce[TPM2_SHA256_DIGEST_SIZE];
extern uint32_t verifier_challenge_nonce_len;

/* --- paths, finalized in verifier.c's main() once --port is known ------ */

/** Per-round /appraise timings. Per port, since sibling Verifiers share one
 * working directory and would otherwise interleave into one file. */
extern char* durations_file_path;

/** RPs that have qualified. Deliberately the OPPOSITE of durations above:
 * ONE file shared by every Verifier instance, because the RP qualifies
 * just once and all of us must honour it. See verifier_qualified_rps.h. */
extern char* qualified_rps_file_path;

/** Private key /appraise signs its verdict with. See charra_verdict.h. */
extern char* verdict_signing_key_path;

/** Which proof of RP integrity this Verifier requires: the /qualify grant
 * (the default) or a TEE Attestation Document. Must match how the RP is
 * configured -- the RP states its own mode in every /appraise request, so a
 * mismatch is reported as one rather than presenting as an unexplained NO. */
extern charra_trust_mode verifier_trust_mode;

#endif /* CHARRA_VERIFIER_SHARED_H */
