/**
 * @file verifier_shared.h
 * @brief State defined in verifier.c that src/verifier/ modules need.
 *
 * The Verifier's globals stay *defined* in verifier.c; this header only
 * declares them so the extracted resource handlers can reach them. Same
 * deliberate compromise as src/rp/rp_shared.h: a libcoap handler signature
 * is fixed, so per-round state (the outstanding request, this Verifier's
 * own challenge nonce, the pending qualification answer) has nowhere to
 * live but file scope. Splitting the file is the goal here; giving those
 * globals a proper per-session home is a separate job -- and the one that
 * actually lifts the "one attestation round in flight at a time" limit
 * they currently impose.
 *
 * Anything listed here has had its `static` removed in verifier.c. Keep
 * the two in sync -- a mismatch is a link error, not a silent bug.
 */

#ifndef CHARRA_VERIFIER_SHARED_H
#define CHARRA_VERIFIER_SHARED_H

#ifndef CHARRA_UNUSED
#define CHARRA_UNUSED __attribute__((unused))
#endif

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../core/charra_dto.h"
#include "../core/charra_rp_qualification.h"

/* How many synthetic log entries /qualify challenges the RP with. */
#define CHARRA_RP_QUALIFICATION_NUM_ENTRIES 5

/* --- per-round state ----------------------------------------------------
 * Single globals, so exactly one attestation round can be in flight per
 * Verifier process. Recorded as-is by the split rather than fixed by it. */

/** Result of the most recent appraisal step; overwritten as one proceeds. */
extern CHARRA_RC attestation_rc;

/** Rounds this Verifier has served, purely for the /nonce log delimiter. */
extern unsigned int attestation_round_counter;

/** The evidence request currently being appraised. Holds the nonce the RP
 * gave the ATTESTER -- needed for Quote_a's freshness check (Step 3b). */
extern msg_attestation_request_dto last_request;

/** This Verifier's OWN freshness challenge for Quote_r, reissued by
 * /nonce every round. Deliberately distinct from last_request.nonce: a
 * nonce the RP chose itself proves nothing to the Verifier. */
extern uint8_t verifier_challenge_nonce[TPM2_SHA256_DIGEST_SIZE];
extern uint32_t verifier_challenge_nonce_len;

/** The outstanding /qualify challenge's golden answer, awaiting the
 * matching /qualify_submit. The durable verdict lives on disk instead --
 * see qualification_state_file_path. */
extern rp_qualification_state qualification_state;

/* --- paths, finalized in main() once --port is known --------------------
 * The three per-port ones are pointers into verifier.c's own buffers, not
 * string literals, so they must not be freed or reassigned here. */

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
 * AK must never be tracked -- or revoked -- as the same identity. Per
 * port, because charra_ak_state_renew() revokes any existing record for
 * the same EK, so a shared file would have each Verifier revoking every
 * other's separately-issued certificate. */
extern char* rp_ak_state_file_path;
extern char* attester_ak_state_file_path;

/** Who has passed /qualify + /qualify_submit. Unlike the ledgers above,
 * ONE file shared by every Verifier instance: qualifying with one
 * qualifies with all. Safe because this ledger only ever appends. */
extern char* qualification_state_file_path;

#endif /* CHARRA_VERIFIER_SHARED_H */
