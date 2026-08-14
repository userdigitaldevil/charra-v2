/**
 * @file charra_qualification_state.h
 * @brief Persisted record of RPs that have passed the qualification
 * handshake (/qualify + /qualify/submit), keyed by RP identity.
 *
 * Mirrors charra_ak_state.h's shape deliberately: coap_qualify_submit_
 * handler() (verifier.c) is otherwise stateless -- charra_rp_qualification_
 * check() only ever updates an in-memory rp_qualification_state that holds
 * the *current in-flight challenge's* golden answer, not a durable verdict.
 * This module gives the *verdict* (qualified until when, for which RP)
 * memory, on disk, so it survives both across separate /qualify rounds and
 * across a server restart, and so multiple `bin/verifier` instances sharing
 * one CA (see start_verifiers.sh) share one view of who has qualified.
 *
 * Identity: records are keyed by the same ek_fingerprint charra_ak_state.h
 * already tracks -- SHA-256 of the requester's EK certificate. No separate
 * identity needs to travel over the wire for this: coap_qualify_submit_
 * handler() already chain-verifies the submitter's AK certificate and can
 * look its serial up in the AK-provisioning ledger to find the matching
 * ek_fingerprint, the same identity binding Step 3a/3b's own EK/AK checks
 * already rely on. This is what ties a qualification to a specific RP,
 * rather than "whichever RP's /qualify/submit was checked most recently" --
 * the single in-memory rp_qualification_state this module deliberately does
 * NOT replace could never do that, since it holds one outstanding challenge
 * at a time with no notion of who it was issued to.
 *
 * Renewal policy: a qualifying submission for an EK that already has a
 * record on file always appends a fresh one; charra_qualification_state_
 * find_by_ek_fingerprint() always returns the most recent, so an older,
 * expired record for the same EK is simply superseded, never consulted
 * again. Unlike AK certificates there is no separate revocation concept --
 * a qualification's only way to stop being trusted is to expire.
 *
 * File format: one line per record, whitespace-separated hex/decimal
 * fields, `#`-comments and blank lines skipped -- same convention charra_
 * ak_state.h and reference-pcrs.txt/whitelist-hashes.txt already use. Not
 * meant to be hand-edited in normal operation; charra_qualification_state_
 * renew() is the only writer.
 */

#ifndef CHARRA_QUALIFICATION_STATE_H
#define CHARRA_QUALIFICATION_STATE_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "../common/charra_error.h"

/** One passing-qualification record. */
typedef struct {
    /** SHA-256 of the qualified RP's EK certificate -- same identity
     * charra_ak_state_record::ek_fingerprint uses. */
    uint8_t ek_fingerprint[32];
    time_t qualified_at;
    time_t expires_at;
} charra_qualification_state_record;

/**
 * @brief Load every record from path into a freshly malloc'd array.
 *
 * @param[out] records_out malloc'd, *count_out entries; caller frees. NULL
 * if the file has no valid records (not an error -- an empty/missing state
 * file just means nobody has qualified yet).
 * @param[out] count_out number of records loaded
 * @returns CHARRA_RC_SUCCESS (including when the file doesn't exist yet --
 * treated as zero records, not an error), CHARRA_RC_BAD_ARGUMENT on NULL
 * arguments. Individual unparseable lines are logged and skipped, not a
 * hard failure.
 */
CHARRA_RC charra_qualification_state_load(const char* path,
        charra_qualification_state_record** records_out,
        uint32_t* count_out);

/**
 * @brief Write every record to path, overwriting it.
 *
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_ERROR if the file can't be written,
 * CHARRA_RC_BAD_ARGUMENT on bad arguments.
 */
CHARRA_RC charra_qualification_state_save(const char* path,
        const charra_qualification_state_record* records, uint32_t count);

/**
 * @brief Find the most recently qualified record matching fingerprint.
 * After N qualifications for the same EK, up to N-1 now-superseded records
 * can exist for it (oldest first, since charra_qualification_state_renew()
 * only ever appends); this always returns the last one appended, the only
 * one worth checking charra_qualification_state_is_valid() against.
 *
 * @param[out] index_out set on a match; untouched otherwise
 * @returns true iff found
 */
bool charra_qualification_state_find_by_ek_fingerprint(
        const charra_qualification_state_record* records, uint32_t count,
        const uint8_t fingerprint[32], uint32_t* index_out);

/**
 * @brief Renew: atomically (via an advisory file lock, safe across the
 * multiple `bin/verifier` processes start_verifiers.sh spawns) append
 * new_record as this EK's new qualification record.
 *
 * The only writer coap_qualify_submit_handler() is expected to call -- it
 * should not call charra_qualification_state_load()/_save() directly,
 * since that would not be safe against a concurrent renewal from a sibling
 * verifier process.
 *
 * @param[in] ek_fingerprint identity being (re-)qualified -- must equal
 * new_record->ek_fingerprint
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_ERROR on file/lock failure,
 * CHARRA_RC_BAD_ARGUMENT on bad arguments
 */
CHARRA_RC charra_qualification_state_renew(const char* path,
        const uint8_t ek_fingerprint[32],
        const charra_qualification_state_record* new_record);

/**
 * @brief Is this record still within its qualification window?
 */
bool charra_qualification_state_is_valid(
        const charra_qualification_state_record* record, time_t now);

#endif /* CHARRA_QUALIFICATION_STATE_H */
