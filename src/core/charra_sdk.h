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
 *     u32 d_len | "<alg>:" NUL <file-content-digest>     (the d-ng field)
 *     u32 n_len | "<path>" NUL                           (the n-ng field)
 *
 * Only the **directory** is sensitive. A path splits at its last '/' into a
 * directory and a filename, and the two leak very different things. On a
 * real device the directories carry deployment detail -- mount points, job
 * instance identifiers, version-stamped image names such as
 * /var/secbox/job/lte/secbox_lte_ai_3_24_0/... -- while the filename is a
 * generic library or binary name that the vendor's own published baseline
 * already lists.
 *
 * So the filename stays in the clear and only the directory is committed:
 *
 *     n-ng contents = hex(SHA256(dir || salt)) | label | filename | NUL
 *     n-ng contents = hex(Poseidon(dir, salt)) | label | filename | NUL
 *
 * `label` is the caller's separator between the two -- '/' gives
 * "<64 hex>/libxt_tcp.so", '*' gives "<64 hex>*libxt_tcp.so". It is inside
 * template_data and therefore inside template_digest, so the RP and the
 * Verifier must agree on it or the /qualify comparison fails.
 *
 * The commitment is rendered as 64 lowercase hex characters rather than 32
 * raw bytes, which keeps log_r a printable IMA log: it can be written out in
 * the same ASCII format log_a arrived in (charra_ima_ascii.h) and diffed
 * against it column for column.
 *
 * The hash differs by which entry point is called, not by a flag:
 * charra_sdk_redact_ima_log() always uses SHA-256, and
 * charra_sdk_redact_ima_log_with_witness() always uses Poseidon, because a
 * commitment the ZK circuit has to re-check is orders of magnitude cheaper
 * there in Poseidon than in SHA-256. Both are 32 bytes before hex, so log_r's
 * format is identical either way, and the properties below hold for both.
 *
 * ## What this costs, stated plainly
 *
 * Publishing filenames is a real weakening against committing the whole
 * path. Filenames are strongly correlated with their directories -- on the
 * reference log 167 entries span only 53 distinct directories, and names
 * like GRAT_service.so or URAT_ocl_bs.so announce which radio technology
 * they belong to. The honest claim is that redaction hides the **filesystem
 * layout**, not the software inventory. It was never meant to hide the
 * latter: the inventory is exactly what the Verifier's whitelist has to
 * check.
 *
 * An entry whose path contains no '/' at all is passed through unredacted
 * and logged. Rejoining a directory and a filename that were never separated
 * would invent a leading '/' that was not in the original, and silently
 * changing a measured path is worse than declining to hide it.
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
 * The redacted n-ng field keeps the path's trailing NUL, because it is a
 * well-formed n-ng field like any other: variable-length, NUL-terminated,
 * and counted by its u32 prefix. That is what lets log_r be re-emitted as a
 * genuine ASCII IMA log rather than something merely shaped like one.
 *
 * Everything else in the entry -- pcr_index, template_name and its length --
 * is unchanged. template_digest is necessarily recomputed, since it must
 * hash the new template_data for the log to pass its own self-consistency
 * check, and it is recomputed with **the same algorithm the input log
 * used**: a SHA-1 log stays 20 bytes wide, a SHA-256 log stays 32. Widening
 * it would leave log_r a different shape from log_a for no gain.
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

/** Size of the raw directory commitment: one SHA-256 or Poseidon digest. */
#define CHARRA_SDK_REDACTED_PATH_LEN 32

/** Its rendered width in log_r: hex, so twice the raw digest. */
#define CHARRA_SDK_REDACTED_DIR_HEX_LEN (2 * CHARRA_SDK_REDACTED_PATH_LEN)

/**
 * Default separator between the committed directory and the filename.
 *
 * '/' keeps the redacted value looking like a path, so log_r reads as an
 * ordinary IMA log whose directories happen to be opaque -- the commitment
 * sits exactly where the directory it replaced used to be.
 *
 * The split point stays unambiguous either way: the commitment is always
 * CHARRA_SDK_REDACTED_DIR_HEX_LEN characters, so a reader takes the label at
 * a fixed offset rather than by searching. Hex cannot contain '/' (or '*'),
 * so the first occurrence is the separator in both cases; nothing downstream
 * depends on the choice beyond both sides using the same one.
 */
#define CHARRA_SDK_DEFAULT_LABEL '/'

/** Bytes of salt mixed into each directory hash. Never transmitted. */
#define CHARRA_SDK_PATH_SALT_LEN 32

/**
 * @brief Redact an IMA event log: replace each entry's directory with a
 * salted hash of it, keep the filename, leave every other field intact, and
 * recompute template_digest to match.
 *
 * @param[in] raw_log log bytes to redact, in the binary form
 * charra_ima_ascii_parse() produces; may be NULL only if raw_log_len is 0
 * @param[in] raw_log_len length of raw_log; 0 is valid and produces an empty
 * redacted log
 * @param[in] salt NULL for the normal case (a fresh random salt is
 * generated for every entry and discarded -- required for real evidence,
 * see this file's header comment). If non-NULL, must point to exactly
 * CHARRA_SDK_PATH_SALT_LEN bytes, used as every entry's salt instead --
 * two calls with the same raw_log and salt then produce byte-identical
 * output. Only ever pass a real salt here for the RP qualification
 * handshake's synthetic challenge log, never for real Attester evidence.
 * @param[in] label separator written between the committed directory and the
 * filename; CHARRA_SDK_DEFAULT_LABEL unless there is a reason to differ.
 * Must match on both sides of the /qualify comparison.
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
        char label, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out);

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
        uint32_t raw_log_len, char label, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out, struct charra_zk_witness* witness);

#endif /* CHARRA_SDK_H */
