/**
 * @file charra_sdk.h
 * @brief The Verifier's "desensitization and cleaning module (SDK)", per the
 * privacy-preserving redaction design (see CHARRA_V2_NOTES.md, "RP
 * access/qualification check").
 *
 * The Verifier authors this logic and sends it to the RP -- the RP runs it
 * unmodified rather than writing its own redaction routine. Applied both to
 * real Attester evidence (RP's normal job) and to Verifier-fabricated
 * synthetic data (the qualification check, using
 * charra_synth_generate_ima_log()), so the Verifier can precompute the
 * expected ("golden") result and confirm the RP's real output matches it.
 *
 * Current rule (deliberately simple, a first version): for each entry,
 * locate the path inside template_data (the "sha256:" / "sha1:" + file
 * digest + NUL + path layout charra_synth_generate_ima_log() produces, and
 * the layout a real ima-ng template also uses), hash the path itself with
 * SHA-256, and replace template_data with just that hash -- 32 raw bytes,
 * no prefix, no separator, nothing else. template_digest is then recomputed
 * as SHA256 of that new template_data, exactly as the wider redaction design
 * requires (see "Consequences of recomputing template_digest" in the notes).
 *
 * This does not attempt to preserve the file-content digest the way an
 * earlier, unbuilt design considered (keeping the hash portion for future
 * per-file appraisal) -- it discards it. Simpler, and appraisal is not
 * currently in scope. Revisit if that changes.
 */

#ifndef CHARRA_SDK_H
#define CHARRA_SDK_H

#include <inttypes.h>

#include "../common/charra_error.h"

/**
 * @brief Redact an IMA event log: replace each entry's template_data with a
 * SHA-256 hash of its path, and recompute template_digest to match.
 *
 * Every field except template_data and template_digest is copied through
 * unchanged -- pcr_index, template_name (and its length) are identical to
 * the input entry. The output log always uses 32-byte (SHA-256) digests,
 * regardless of what digest size the input log used, since both the path
 * hash and the recomputed template_digest are produced by SHA-256.
 *
 * @param[in] raw_log log bytes to redact; may be NULL only if raw_log_len is
 * 0
 * @param[in] raw_log_len length of raw_log; 0 is valid and produces an empty
 * redacted log
 * @param[out] redacted_log_out receives a malloc'd buffer; caller must
 * free() it. Set to NULL if raw_log_len is 0.
 * @param[out] redacted_log_len_out receives the length of *redacted_log_out
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_BAD_ARGUMENT on bad
 * arguments, CHARRA_RC_MARSHALING_ERROR if raw_log is malformed,
 * CHARRA_RC_ERROR on allocation failure, CHARRA_RC_CRYPTO_ERROR if hashing
 * fails.
 */
CHARRA_RC charra_sdk_redact_ima_log(const uint8_t* raw_log,
        uint32_t raw_log_len, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out);

#endif /* CHARRA_SDK_H */
