/**
 * @file charra_ak_state.h
 * @brief Persisted record of AK certificates issued via /certify_ak.
 *
 * coap_certify_ak_handler() (verifier.c) is otherwise stateless -- every
 * call signs a fresh certificate with no memory of what it issued before.
 * This module gives it that memory, on disk, so it survives both across
 * separate /certify_ak calls and across a server restart, and so multiple
 * `bin/verifier` instances sharing one CA (see start_verifiers.sh) share one
 * view of what has been issued and what has been superseded.
 *
 * Renewal policy: requesting a new AK certificate for an EK that already has
 * one on file always issues a fresh certificate and marks the previous
 * record for that EK revoked -- see charra_ak_state_renew(). Nothing else in
 * this module ever sets a record's `revoked` flag; there is deliberately no
 * separate manual-revocation trigger yet (see CHARRA_V2_NOTES.md).
 *
 * File format: one line per record, whitespace-separated hex/decimal
 * fields, `#`-comments and blank lines skipped -- same convention this
 * project already uses for reference-pcrs.txt/whitelist-hashes.txt. Not
 * meant to be hand-edited in normal operation; charra_ak_state_renew() is
 * the only writer.
 */

#ifndef CHARRA_AK_STATE_H
#define CHARRA_AK_STATE_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/** Width of an issued certificate's serial number, in bytes -- fixed by
 * charra_crypto_sign_ak_certificate(). A certificate whose serial is any
 * other width was not issued here. */
#define CHARRA_AK_STATE_SERIAL_LEN 16

/** One issued-AK-certificate record. */
typedef struct {
    /** SHA-256 of the requester's EK certificate (DER) -- the stable
     * identity a renewal is matched against. */
    uint8_t ek_fingerprint[32];
    /** The certified AK's TPM2B_NAME, as presented in the request. */
    uint8_t ak_name[sizeof(TPM2B_NAME)];
    uint32_t ak_name_len;
    /** The issued certificate's serial number, see
     * charra_crypto_sign_ak_certificate()'s serial_out. */
    uint8_t serial[CHARRA_AK_STATE_SERIAL_LEN];
    time_t issued_at;
    time_t expires_at;
    bool revoked;
} charra_ak_state_record;

/**
 * @brief Load every record from path into a freshly malloc'd array.
 *
 * @param[out] records_out malloc'd, *count_out entries; caller frees. NULL
 * if the file has no valid records (not an error -- an empty/missing state
 * file just means nothing has been issued yet).
 * @param[out] count_out number of records loaded
 * @returns CHARRA_RC_SUCCESS (including when the file doesn't exist yet --
 * treated as zero records, not an error, since a fresh Verifier deployment
 * hasn't issued anything), CHARRA_RC_BAD_ARGUMENT on NULL arguments.
 * Individual unparseable lines are logged and skipped, not a hard failure.
 */
CHARRA_RC charra_ak_state_load(const char* path,
        charra_ak_state_record** records_out, uint32_t* count_out);

/**
 * @brief Write every record to path, overwriting it.
 *
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_ERROR if the file can't be written,
 * CHARRA_RC_BAD_ARGUMENT on bad arguments.
 */
CHARRA_RC charra_ak_state_save(const char* path,
        const charra_ak_state_record* records, uint32_t count);

/**
 * @brief Find the most recently issued record matching fingerprint --
 * revoked or not. After N renewals for the same EK, up to N-1 revoked
 * records can exist for it; this always returns the last one appended
 * (charra_ak_state_renew() only ever appends, never reorders), which is
 * the one still worth checking charra_ak_state_is_valid() against.
 *
 * @param[out] index_out set on a match; untouched otherwise
 * @returns true iff found
 */
bool charra_ak_state_find_by_ek_fingerprint(
        const charra_ak_state_record* records, uint32_t count,
        const uint8_t fingerprint[32], uint32_t* index_out);

/**
 * @brief Find the record for a given certificate serial number -- what the
 * (not yet built) Step 3a/3b EK/AK check would call to reject a revoked
 * certificate regardless of it still being within its validity window.
 *
 * @param[out] index_out set on a match; untouched otherwise
 * @returns true iff found
 */
bool charra_ak_state_find_by_serial(const charra_ak_state_record* records,
        uint32_t count, const uint8_t serial[CHARRA_AK_STATE_SERIAL_LEN], uint32_t* index_out);

/**
 * @brief Renew: atomically (via an advisory file lock, safe across the
 * multiple `bin/verifier` processes start_verifiers.sh spawns, all sharing
 * one CA) revoke any existing record for ek_fingerprint and append
 * new_record as the new active one.
 *
 * This is the only function that ever sets `revoked = true`, and the only
 * writer coap_certify_ak_handler() is expected to call -- it should not call
 * charra_ak_state_load()/_save() directly, since that would not be safe
 * against a concurrent renewal from a sibling verifier process.
 *
 * @param[in] ek_fingerprint identity to revoke the previous record for, if
 * any -- must equal new_record->ek_fingerprint
 * @param[in] new_record the freshly issued record; its own `revoked` field
 * is ignored and written as false
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_ERROR on file/lock failure,
 * CHARRA_RC_BAD_ARGUMENT on bad arguments
 */
CHARRA_RC charra_ak_state_renew(const char* path,
        const uint8_t ek_fingerprint[32],
        const charra_ak_state_record* new_record);

/**
 * @brief Is this record still trustworthy: not revoked, and expires_at is
 * still in the future?
 */
bool charra_ak_state_is_valid(const charra_ak_state_record* record, time_t now);

/**
 * @brief Look up serial in the state file at ak_state_file_path and check
 * it's still valid (see charra_ak_state_is_valid()) -- the revocation half
 * of an AK certificate check, since chain validity alone doesn't know about
 * a since-renewed-away serial.
 *
 * @param[out] ek_fingerprint_out set to the matching record's
 * ek_fingerprint iff this returns true; untouched otherwise. May be NULL if
 * the caller only cares about validity, not identity.
 * @param[out] expires_at_out set to the matching record's expires_at iff
 * this returns true; untouched otherwise. May be NULL if the caller
 * doesn't need it for logging. Lets callers log a certificate's actual
 * remaining validity on success rather than just "valid!".
 * @returns true iff serial names a currently-valid (unrevoked, unexpired)
 * record. False on any lookup/load failure as well as a genuine miss.
 */
bool charra_ak_state_check_serial_valid(const char* ak_state_file_path,
        const uint8_t serial[CHARRA_AK_STATE_SERIAL_LEN], uint8_t ek_fingerprint_out[32],
        time_t* expires_at_out);

#endif /* CHARRA_AK_STATE_H */
