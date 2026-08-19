/**
 * @file charra_sdk.h
 * @brief The Verifier's "desensitization and cleaning module (SDK)", per the
 * privacy-preserving redaction design (see CHARRA_V2_NOTES.md).
 *
 * The Verifier authors this logic and sends it to the RP -- the RP runs it
 * unmodified rather than writing its own redaction routine.
 *
 * ## What is redacted
 *
 * An ima-ng entry's template_data is two length-prefixed fields:
 *
 *     u32 d_len | "<alg>" NUL <file-content-digest>      (the d-ng field)
 *     u32 n_len | "<path>" NUL                           (the n-ng field)
 *
 * Only the **path** is sensitive: it reveals what software and configuration
 * exist on the Attester. The file-content digest is not -- on its own it says
 * only that some file hashed to some value, not where that file lives -- and
 * preserving it is what makes appraisal by content hash (the blacklist pass)
 * possible at all.
 *
 * So the d-ng field is copied through **byte for byte**, and only the n-ng
 * field's contents are replaced:
 *
 *     redacted_path = SHA256(original_path || salt)
 *
 * with a fresh 32-byte random salt per entry that is never transmitted. That
 * has two consequences, both deliberate:
 *
 *  - the mapping is irreversible even against a dictionary of guessed paths,
 *    which an unsalted SHA256(path) would not be; and
 *  - two entries with the same path redact to *different* values, so the
 *    Verifier cannot count or correlate repeated paths.
 *
 * The redacted n-ng field is a fixed 32 bytes with no NUL terminator --
 * nothing variable-length follows it, so there is nothing to terminate.
 *
 * Everything else in the entry -- pcr_index, template_name and its length --
 * is unchanged. template_digest is necessarily recomputed, since it must
 * equal SHA256 of the new template_data for the log to pass its own
 * self-consistency check.
 *
 * ## Consequence
 *
 * Because template_digest is recomputed, a replay of the redacted log can no
 * longer reproduce the Attester's TPM-sealed PCR 10 -- not by policy but
 * mathematically, since the digests differ by construction. The Attester's
 * TPM is therefore not in the Verifier's chain of trust for the PCR 10
 * property; the guarantee becomes "the RP vouches for this", anchored by
 * Quote_r. This is the intended design, not a defect.
 */

#ifndef CHARRA_SDK_H
#define CHARRA_SDK_H

#include <inttypes.h>

#include "../common/charra_error.h"

/** Size of the redacted path: one SHA-256 digest. */
#define CHARRA_SDK_REDACTED_PATH_LEN 32

/** Bytes of salt mixed into each path hash. Never transmitted. */
#define CHARRA_SDK_PATH_SALT_LEN 32

/**
 * @brief Redact an IMA event log: replace each entry's file path with a
 * salted hash of it, leaving every other field intact, and recompute
 * template_digest to match.
 *
 * @param[in] raw_log log bytes to redact; may be NULL only if raw_log_len is
 * 0
 * @param[in] raw_log_len length of raw_log; 0 is valid and produces an empty
 * redacted log
 * @param[out] redacted_log_out receives a malloc'd buffer; caller must
 * free() it. Set to NULL if raw_log_len is 0.
 * @param[out] redacted_log_len_out receives the length of *redacted_log_out
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_BAD_ARGUMENT on bad
 * arguments, CHARRA_RC_MARSHALING_ERROR if raw_log is malformed or an entry's
 * template_data is not a well-formed ima-ng pair of fields,
 * CHARRA_RC_ERROR on allocation failure, CHARRA_RC_CRYPTO_ERROR if hashing or
 * random generation fails.
 */
CHARRA_RC charra_sdk_redact_ima_log(const uint8_t* raw_log,
        uint32_t raw_log_len, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out);

#endif /* CHARRA_SDK_H */
