/**
 * @file verifier_qualified_rps.h
 * @brief Which RPs have passed /qualify + /qualify_submit -- shared by
 * every Verifier.
 *
 * The RP qualifies ONCE, with whichever Verifier it reaches first, and
 * every other Verifier has to honour that. So this cannot live in one
 * process's memory: it is a flat file all of them read, written by the one
 * that ran the handshake.
 *
 * Same shape, and same reasoning, as the AK trust anchor next door
 * (charra_trusted_keys.h): the file IS the fact. Unlike the trust anchor,
 * though, a record here EXPIRES -- each line carries the deadline the
 * issuing Verifier granted, and a lapsed record counts as not qualified.
 *
 * Identity does not go stale; behaviour does. A signing key is the same
 * key forever, but an RP can swap its redaction pipeline the moment after
 * it passes, so qualification is deliberately the one thing here with a
 * lifetime (--qualification-validity).
 *
 * The deadline is STORED, not recomputed per Verifier. Only one Verifier
 * ever runs the handshake, so it stamps the window and every other
 * Verifier honours that same number. Recomputing it from each reader's own
 * flag would let a Verifier configured more strictly expire an RP earlier
 * than the RP believes -- and since /appraise never reports WHY it voted
 * no, the RP would have no way to learn it should re-qualify, and would be
 * rejected on every cycle until its own longer deadline lapsed.
 *
 * An RP is identified by the SHA-256 of AK_r's public key, hashed over
 * exactly the bytes that arrive in msg_qualify_submit_request_dto and
 * msg_rp_evidence_dto, so /qualify_submit and /appraise derive the same
 * identity from the same wire field. The fingerprint is a handle, not a
 * credential: what binds an RP to it is the Quote_r signature verifying
 * under that same key, checked separately at Step 3a item 2.
 *
 * One line per RP: re-qualifying REPLACES that RP's record rather than
 * adding a second one, so the file stays as long as there are RPs and can
 * be read at a glance.
 *
 * Concurrency: siblings read this file constantly; only the Verifier that
 * ran the handshake writes it. Because a write REPLACES a record rather
 * than appending, it is published by temp-file + rename() -- atomic within
 * a filesystem, so a reader sees the whole old file or the whole new one.
 * Truncating in place would leave a window where every reader sees an
 * empty file and votes NO inexplicably.
 *
 * Not covered: two Verifiers rewriting at the same instant, the later
 * rename winning. That needs two RPs qualifying simultaneously, which this
 * single-RP PoC cannot produce; it is where a real lock would go.
 */

#ifndef CHARRA_VERIFIER_QUALIFIED_RPS_H
#define CHARRA_VERIFIER_QUALIFIED_RPS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "../common/charra_error.h"

/** SHA-256, so 32 bytes. */
#define VERIFIER_RP_FINGERPRINT_LEN 32

/** Shared by every Verifier instance, relative to the working directory
 * they are all started from. */
#define VERIFIER_QUALIFIED_RPS_DEFAULT_PATH "qualified_rps.txt"

/**
 * @brief Derive an RP's identity from AK_r's public key, as it arrives on
 * the wire (a TPM2B_PUBLIC, not DER).
 *
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT on NULL/empty input,
 * or whatever the hash failed with.
 */
CHARRA_RC verifier_qualified_rps_fingerprint(const uint8_t* ak_public_key,
        size_t ak_public_key_len,
        uint8_t fingerprint_out[VERIFIER_RP_FINGERPRINT_LEN]);

/**
 * @brief Record that this RP qualified, until expires_at.
 *
 * Replaces any record this RP already had, leaving exactly one line for
 * it. Other RPs' records are carried over untouched.
 *
 * @param[in] path the shared file, or NULL for
 * VERIFIER_QUALIFIED_RPS_DEFAULT_PATH.
 * @param[in] expires_at absolute epoch seconds this grant is valid until,
 * as granted by THIS Verifier's --qualification-validity. Every other
 * Verifier reads this number rather than deriving its own.
 * @returns CHARRA_RC_SUCCESS, or CHARRA_RC_ERROR if the file could not be
 * written -- which the caller should treat as "this RP will have to
 * qualify again", not as a failed handshake.
 */
CHARRA_RC verifier_qualified_rps_add(const char* path,
        const uint8_t fingerprint[VERIFIER_RP_FINGERPRINT_LEN],
        time_t expires_at);

/**
 * @brief Is this RP qualified right now, according to any Verifier's
 * still-valid grant?
 *
 * Takes the latest deadline on file for this RP. The writer keeps only one
 * record per RP, so that is normally the only one -- scanning for the
 * latest rather than the first is what keeps a hand-edited or
 * older-format file from resolving to a stale grant.
 *
 * A missing file means nobody has qualified yet -- false, not an error.
 * So does a record whose deadline has passed, and so does a malformed line
 * with no deadline at all: this fails closed in every case, because a
 * qualification that cannot be read is not a qualification.
 */
bool verifier_qualified_rps_is_qualified(const char* path,
        const uint8_t fingerprint[VERIFIER_RP_FINGERPRINT_LEN], time_t now);

#endif /* CHARRA_VERIFIER_QUALIFIED_RPS_H */
