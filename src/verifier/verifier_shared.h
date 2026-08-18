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
#include <time.h>

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

/* --- paths, finalized in verifier.c's main() once --port is known -------
 * All but qualification_state_file_path point into verifier.c's own
 * buffers, not string literals, so they must not be freed or reassigned. */

/** Synthetic TPM manufacturer root, for validating EK certificates. */
extern char* manufacturer_root_cert_path;

/** This Verifier's own Privacy CA (per port -- genuine key isolation, not
 * just separate ledgers, so one Verifier's compromise doesn't spread). */
extern char* verifier_ca_cert_path;
extern char* verifier_ca_key_path;

/** Lifetime of AK certificates this Verifier issues, as a duration from
 * issuance rather than a fixed instant. Settable with --ak-validity. */
extern time_t ak_cert_validity_seconds;

/** AK issuance ledgers, split by subject: an RP AK and a relayed Attester
 * AK must never be tracked -- or revoked -- as the same identity. Per port,
 * because charra_ak_state_renew() revokes any existing record for the same
 * EK, so a shared file would have each Verifier revoking every other's
 * separately-issued certificate. */
extern char* rp_ak_state_file_path;
extern char* attester_ak_state_file_path;

/** Who has passed /qualify + /qualify_submit. Unlike the ledgers above, ONE
 * file shared by every Verifier instance: qualifying with one qualifies
 * with all. Safe because this ledger only ever appends. */
extern char* qualification_state_file_path;

/** Per-round /appraise timings. Per port, since sibling Verifiers share one
 * working directory and would otherwise interleave into one file. */
extern char* durations_file_path;

#endif /* CHARRA_VERIFIER_SHARED_H */
