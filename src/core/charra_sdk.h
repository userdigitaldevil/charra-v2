/**
 * @file charra_sdk.h
 * @brief The Verifier's "desensitization and cleaning module (SDK)", per the
 * privacy-preserving redaction design.
 *
 * The Verifier authors this logic and sends it to the RP -- the RP runs it
 * unmodified rather than writing its own redaction routine. Applied both to
 * real Attester evidence (RP's normal job) and to Verifier-fabricated
 * synthetic data (the qualification check, using
 * charra_synth_generate_ima_log()), so the Verifier can precompute the
 * expected ("golden") result and confirm the RP's real output matches it.
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
 * field's contents are replaced by a 32-byte commitment to the path:
 *
 *     redacted_path = SHA256(original_path || salt)      -- qualify, tee
 *     redacted_path = Poseidon(original_path, salt)      -- zk
 *
 * The hash differs by which entry point is called, not by a flag:
 * charra_sdk_redact_ima_log() always uses SHA-256, and
 * charra_sdk_redact_ima_log_with_witness() always uses Poseidon, because a
 * commitment the ZK circuit has to re-check is orders of magnitude cheaper
 * there in Poseidon than in SHA-256. Both are 32 bytes, so log_r's format is
 * identical either way, and the properties below hold for both.
 *
 * Either way, by default a fresh 32-byte random salt per entry that is never
 * transmitted. That has two consequences, both deliberate:
 *
 *  - the mapping is irreversible even against a dictionary of guessed paths,
 *    which an unsalted hash of the path would not be; and
 *  - two entries with the same path redact to *different* values, so the
 *    Verifier cannot count or correlate repeated paths.
 *
 * charra_sdk_redact_ima_log()'s optional salt parameter is the one
 * deliberate exception to "never transmitted": the RP qualification
 * handshake (charra_rp_qualification.h) needs the RP's redaction of a
 * Verifier-fabricated challenge log to come out byte-identical to the
 * Verifier's own "golden" redaction of it, which a fresh random salt per
 * call can never produce. Safe specifically because that log is synthetic
 * (fabricated paths, not a real device's), so sharing its salt gives up
 * nothing real evidence's redaction relies on -- irreversibility and
 * non-correlation both matter only for genuine Attester data, never for a
 * throwaway challenge the Verifier itself generated. Real evidence must
 * always be redacted with salt == NULL.
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

struct charra_zk_witness;

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
 * @param[in] salt NULL for the normal case (a fresh random salt is
 * generated for every entry and discarded -- required for real evidence,
 * see this file's header comment). If non-NULL, must point to exactly
 * CHARRA_SDK_PATH_SALT_LEN bytes, used as every entry's salt instead --
 * two calls with the same raw_log and salt then produce byte-identical
 * output. Only ever pass a real salt here for the RP qualification
 * handshake's synthetic challenge log, never for real Attester evidence.
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
        uint32_t raw_log_len, const uint8_t salt[CHARRA_SDK_PATH_SALT_LEN],
        uint8_t** redacted_log_out, uint32_t* redacted_log_len_out);

/**
 * @brief As charra_sdk_redact_ima_log(), but commits with Poseidon and
 * collects the ZK witness.
 *
 * The two go together: the circuit can only check a Poseidon commitment, and
 * nothing but the prover wants the witness. Calling the plain function above
 * therefore still produces exactly the SHA-256 output it always did, which is
 * what keeps the /qualify handshake and the TEE measurement unchanged.
 *
 * Salts are always freshly drawn per entry here -- the shared-salt variant
 * exists for the qualification handshake, which does not run in ZK mode.
 *
 * @param witness  filled in on success; zeroed on failure. CONTAINS SECRETS:
 *                 the real paths and the salts they were committed under.
 *                 The caller must wipe it and must never marshal it.
 */
CHARRA_RC charra_sdk_redact_ima_log_with_witness(const uint8_t* raw_log,
        uint32_t raw_log_len, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out, struct charra_zk_witness* witness);

#endif /* CHARRA_SDK_H */
