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
 * Current rule: for each entry, locate the file-content digest and the path
 * inside template_data (the "sha256:" / "sha1:" + file digest + NUL + path
 * layout charra_synth_generate_ima_log() produces, and the layout a real
 * ima-ng template also uses). The file-content digest is preserved
 * UNCHANGED -- it isn't sensitive on its own (it doesn't reveal where a
 * file lives, only that some file's content hashed to it) and keeping it is
 * what makes future per-file policy appraisal (whitelist/blacklist by
 * content hash) possible at all. The path IS sensitive (reveals what
 * software/config exists on the system), so it never survives in
 * recoverable form -- only SHA-256(path) does. The redacted template_data
 * becomes:
 *
 *     "sha256:" (7 bytes) + file_content_digest (32 bytes, unchanged)
 *         + SHA256(path) (32 bytes)
 *
 * 71 bytes, always -- no NUL separator (nothing variable-length follows the
 * fixed-size path hash, so nothing needs terminating). template_digest is
 * then recomputed as SHA256 of that new template_data, exactly as the wider
 * redaction design requires (see "Consequences of recomputing
 * template_digest" in the notes).
 *
 * Known limitation, deliberate for now: the prefix is hardcoded to
 * "sha256:" and the preserved file_content_digest is assumed to already be
 * 32 bytes. A log whose file-content hashing algorithm was SHA-1 (20-byte
 * digest) is rejected rather than mishandled -- RP only ever has the digest
 * Attester already computed, never the original file bytes, so it cannot
 * convert a SHA-1 digest into a SHA-256 one to make it fit. Revisit (carry
 * the real prefix/length through instead of hardcoding) if SHA-1 IMA logs
 * need to be supported.
 */

#ifndef CHARRA_SDK_H
#define CHARRA_SDK_H

#include <inttypes.h>

#include "../common/charra_error.h"

/**
 * @brief Redact an IMA event log: replace each entry's template_data with
 * "sha256:" + the unchanged file-content digest + SHA256(path), and
 * recompute template_digest to match.
 *
 * Every field except template_data and template_digest is copied through
 * unchanged -- pcr_index, template_name (and its length) are identical to
 * the input entry. The output log always uses 32-byte (SHA-256) digests for
 * template_digest, regardless of what digest size the input log used, since
 * the recomputed template_digest is always produced by SHA-256.
 *
 * @param[in] raw_log log bytes to redact; may be NULL only if raw_log_len is
 * 0
 * @param[in] raw_log_len length of raw_log; 0 is valid and produces an empty
 * redacted log
 * @param[out] redacted_log_out receives a malloc'd buffer; caller must
 * free() it. Set to NULL if raw_log_len is 0.
 * @param[out] redacted_log_len_out receives the length of *redacted_log_out
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_BAD_ARGUMENT on bad
 * arguments, CHARRA_RC_MARSHALING_ERROR if raw_log is malformed or its
 * file-content digests are not 32 bytes (SHA-256) -- see the known
 * limitation above, CHARRA_RC_ERROR on allocation failure,
 * CHARRA_RC_CRYPTO_ERROR if hashing fails.
 */
CHARRA_RC charra_sdk_redact_ima_log(const uint8_t* raw_log,
        uint32_t raw_log_len, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out);

#endif /* CHARRA_SDK_H */
