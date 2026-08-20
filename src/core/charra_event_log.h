
/**
 * @file charra_event_log.h
 * @brief IMA event log replay.
 *
 * A TPM Quote commits to a PCR composite digest, not to individual PCR values.
 * To check that digest, a Verifier needs a value for every selected PCR. Boot
 * PCRs (0-7) are static and can be looked up in a reference file, but the IMA
 * PCR grows every time a new file is measured, so no static reference value
 * can exist for it. It has to be *derived*, by replaying the measurement log:
 * starting from an all-zero PCR and re-applying every extend the TPM did.
 *
 * charra_replay_ima_log() is deliberately usable unchanged by both the Relying
 * Party (replaying the raw log received from the Attester) and the Verifier
 * (replaying the log it received in turn). The extend semantics implemented
 * here -- ordering, PCR filtering, and zero-padding of short digests -- must
 * never diverge between the two, which is why they live in one function.
 */

#ifndef CHARRA_EVENT_LOG_H
#define CHARRA_EVENT_LOG_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/** PCR index Linux IMA extends into by default (CONFIG_IMA_MEASURE_PCR_IDX). */
#define CHARRA_IMA_PCR_INDEX 10

/** Upper bound on an IMA template name, e.g. "ima-ng". Generous on purpose. */
#define CHARRA_IMA_TEMPLATE_NAME_MAX 64

/* --- log entries -------------------------------------------------------- */

/**
 * @brief A single parsed measurement log entry.
 *
 * All pointers borrow into the caller's log buffer. Nothing is copied and
 * nothing must be freed; they stay valid as long as the log buffer does.
 */
typedef struct {
    /** PCR this entry was extended into. */
    uint32_t pcr_index;
    /** The digest that was extended. The only field replay consumes. */
    const uint8_t* template_digest;
    /** Length of template_digest: TPM2_SHA1_DIGEST_SIZE or SHA256. */
    uint16_t template_digest_len;
    /** Template name, e.g. "ima-ng". Not NUL-terminated. */
    const char* template_name;
    uint32_t template_name_len;
    /**
     * Measured data (file digest + path for ima-ng). Privacy sensitive, and
     * never consumed by replay -- IMA hashed it into template_digest once, at
     * measurement time. May be empty or redacted without affecting replay.
     */
    const uint8_t* template_data;
    uint32_t template_data_len;
} charra_event_log_entry;

/**
 * @brief Parse the entry starting at *offset and advance *offset past it.
 *
 * Public deliberately: the RP-side redaction logic needs a second, genuine
 * consumer of this exact bounds-checked TLV parser, and reusing it here
 * beats writing a second one that could silently diverge from the one
 * charra_replay_ima_log() depends on.
 *
 * The log is untrusted input: every field read is bounds-checked, and a
 * malformed entry fails rather than reading past the buffer. Bounds checks
 * are written as 'need > log_len - offset', not 'offset + need > log_len',
 * so a hostile length field cannot overflow the check.
 *
 * @param[in] log log bytes
 * @param[in] log_len length of log
 * @param[in,out] offset position to start parsing at; advanced past the
 * parsed entry on success, left unspecified on failure
 * @param[in] digest_len expected size of template_digest (see
 * charra_event_log_ima_detect_digest_len())
 * @param[out] out the parsed entry; all pointers inside it borrow into log
 * @returns CHARRA_RC_SUCCESS, or CHARRA_RC_MARSHALING_ERROR if the entry is
 * truncated or structurally implausible.
 */
CHARRA_RC charra_event_log_parse_entry(const uint8_t* log, uint32_t log_len,
        uint32_t* offset, uint16_t digest_len, charra_event_log_entry* out);

/**
 * @brief Write a uint32 at buf[*offset] in the same byte order
 * charra_event_log_parse_entry() reads, and advance *offset past it.
 *
 * Public for the same reason charra_event_log_parse_entry() is: more than
 * one module builds log entries in this exact TLV shape (synthetic log
 * generation, redaction), and keeping one writer here -- next to the reader
 * it must stay in sync with -- beats each one reimplementing it.
 */
void charra_event_log_append_u32(
        uint8_t* buf, uint32_t* offset, uint32_t value);

/**
 * @brief Copy len bytes to buf[*offset] and advance *offset past them.
 * A no-op copy (but still advances *offset) when len is 0.
 */
void charra_event_log_append_bytes(
        uint8_t* buf, uint32_t* offset, const void* data, uint32_t len);

/* --- PCR accumulator ---------------------------------------------------- */

/**
 * @brief A software PCR mirroring what the TPM did at measurement time.
 */
typedef struct {
    uint8_t value[TPM2_SHA256_DIGEST_SIZE];
} charra_pcr_accumulator;

/**
 * @brief Reset an accumulator to a PCR's power-on state (all zero).
 */
void charra_pcr_reset(charra_pcr_accumulator* acc);

/**
 * @brief One PCR extend: acc := SHA256(acc || digest).
 *
 * A digest shorter than TPM2_SHA256_DIGEST_SIZE is zero-padded on the right
 * before extending, which is what the kernel does when it has to extend a
 * SHA-256 PCR bank with a SHA-1 template digest.
 *
 * @param[in,out] acc accumulator to extend
 * @param[in] digest digest to extend in
 * @param[in] digest_len length of digest; must be > 0 and must not exceed
 * TPM2_SHA256_DIGEST_SIZE
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT on bad arguments,
 * CHARRA_RC_CRYPTO_ERROR if hashing fails.
 */
CHARRA_RC charra_pcr_extend(charra_pcr_accumulator* acc, const uint8_t* digest,
        uint16_t digest_len);

/* --- IMA binary log ----------------------------------------------------- */

/**
 * @brief Recover the template digest size used by an IMA binary log.
 *
 * The format does not record which hash algorithm produced the template
 * digests -- it is a boot-time kernel choice (ima_hash=). This trial-parses
 * the log at each candidate size and keeps the one that consumes the buffer
 * exactly. Entry structure plus printable template names make a false positive
 * very unlikely; if more than one candidate parses cleanly a warning is logged
 * and the smaller (SHA-1) is chosen, matching the classic format of
 * /sys/kernel/security/ima/binary_runtime_measurements.
 *
 * @param[in] log log bytes
 * @param[in] log_len length of log; must be > 0
 * @param[out] digest_len_out TPM2_SHA1_DIGEST_SIZE or TPM2_SHA256_DIGEST_SIZE
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT on NULL/empty input,
 * CHARRA_RC_MARSHALING_ERROR if no candidate yields a well-formed parse.
 */
CHARRA_RC charra_event_log_ima_detect_digest_len(
        const uint8_t* log, uint32_t log_len, uint16_t* digest_len_out);

/**
 * @brief Replay an IMA binary event log into a PCR value.
 *
 * Starts from an all-zero PCR and extends every entry whose pcr_index matches
 * target_pcr_index, in log order. Entries for other PCRs are parsed (their
 * lengths are needed to find the next entry) but skipped.
 *
 * The log is untrusted input: every field read is bounds-checked, and a
 * malformed log fails rather than reading past the buffer.
 *
 * Expected per-entry layout, integers in the kernel's native byte order:
 *
 *   pcr_index        uint32
 *   template_digest  digest_len bytes   (NOT length-prefixed)
 *   name_len         uint32
 *   template_name    name_len bytes
 *   data_len         uint32
 *   template_data    data_len bytes
 *
 * The legacy "ima" template omits data_len and uses a fixed-size filename
 * field. It is rejected with CHARRA_RC_MARSHALING_ERROR rather than guessed
 * at, since misparsing it would silently corrupt every following entry.
 *
 * The template digest size (SHA-1's 20 bytes or SHA-256's 32) is not
 * recorded in the log, so it is discovered by attempting the parse: the
 * first entry is peeked at to guess which size to try first, then the whole
 * log is parsed and replayed in one pass at that size. If that fails, the
 * other size is tried the same way. A wrong guess costs a second pass, never
 * a false rejection of a well-formed log, since both sizes are always tried
 * before giving up.
 *
 * @param[in] log log bytes; may be NULL only if log_len is 0
 * @param[in] log_len length of log; 0 is a valid empty log and replays to the
 * all-zero PCR
 * @param[in] target_pcr_index PCR to reconstruct (CHARRA_IMA_PCR_INDEX)
 * @param[out] pcr_out the replayed PCR value
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_BAD_ARGUMENT on bad
 * arguments, CHARRA_RC_MARSHALING_ERROR on a malformed log,
 * CHARRA_RC_CRYPTO_ERROR if hashing fails.
 */
CHARRA_RC charra_replay_ima_log(const uint8_t* log, uint32_t log_len,
        uint32_t target_pcr_index, uint8_t pcr_out[TPM2_SHA256_DIGEST_SIZE]);

/* --- log content verification -------------------------------------------
 *
 * Per the RP-mediated attestation architecture, this content verification
 * (self-consistency, PCR replay, file-hash policy) is the RP App's local
 * verification gate, run against the log it received from the Attester --
 * not the Verifier's job, which only checks quote signatures and nonces.
 * Lives here since it is built directly on charra_event_log_parse_entry()
 * and charra_replay_ima_log() above.
 */

/**
 * @brief Per-entry self-consistency check: does every entry's
 * template_digest equal SHA256(template_data), both fields as they
 * currently appear in the log?
 *
 * This is NOT a check that redaction was done faithfully -- that question
 * needs the separate qualification handshake (charra_rp_qualification.h).
 * This only catches a log that is internally malformed: corruption in
 * transit, a redaction bug, or a tampered field that no longer matches its
 * neighbor within the same entry.
 */
bool charra_verify_log_entries_self_consistent(
        const uint8_t* log, uint32_t log_len);

/**
 * @brief Replay a log into one accumulator per selected PCR.
 *
 * Unlike charra_replay_ima_log(), which reconstructs a single PCR, this
 * tracks every PCR in the selection at once: each entry extends whichever
 * PCR it names, and a selected PCR that no entry names stays at its
 * all-zero power-on value. Entries naming a PCR outside the selection are
 * parsed (their lengths are needed to find the next entry) but skipped,
 * since they cannot affect the composite digest.
 *
 * @param[in] pcr_selection the PCR indices to track
 * @param[out] pcrs_out at least pcr_selection_len accumulators, filled in
 * the same order as pcr_selection
 */
CHARRA_RC charra_replay_ima_log_pcrs(const uint8_t* log, uint32_t log_len,
        const uint8_t* pcr_selection, uint32_t pcr_selection_len,
        charra_pcr_accumulator* pcrs_out);

/**
 * @brief Replay a log into the selected PCRs and check that the composite
 * digest built from them matches the one the quote committed to.
 *
 * A quote commits to a composite digest over *every* selected PCR, never to
 * one PCR alone, so all of them are replayed and hashed together in
 * selection order -- the composite digest is order-sensitive.
 *
 * No reference PCR file is consulted: the replayed values *are* the expected
 * values. That holds only because the Attester's PCRs start from power-on
 * zero and are extended solely from this log. On a platform whose firmware
 * extends PCRs 0-7 at boot, those would need reference values instead.
 *
 * @param[in] pcr_selection the PCR indices the quote covers
 * @param[in] attest_struct the unmarshaled quote holding the pcrDigest
 */
bool charra_verify_log_matches_quote_pcr_digest(const uint8_t* log,
        uint32_t log_len, const uint8_t* pcr_selection,
        uint32_t pcr_selection_len, const TPMS_ATTEST* attest_struct);

/**
 * @brief Locate the file-content digest inside an ima-ng entry's
 * template_data.
 *
 * @param[out] digest_out borrows into the entry; not freed by the caller
 * @return false if template_data is not a well-formed ima-ng d-ng field
 */
bool charra_event_log_entry_file_digest(const charra_event_log_entry* entry,
        const uint8_t** digest_out, uint32_t* digest_len_out);

/**
 * @brief Checks every log entry's file-content digest against the
 * whitelist/blacklist policy (DRA-TLS Step 2a item 6).
 *
 * The blacklist is an explicit deny and is always enforced. The whitelist
 * is enforced as default-deny, but only once it has at least one entry --
 * an empty whitelist falls back to allow-by-default rather than rejecting
 * every attestation on a fresh checkout. The chosen mode is logged.
 *
 * @returns true iff every entry is permitted under the policy in force.
 */
bool charra_verify_log_file_hashes_against_policy(const uint8_t* log,
        uint32_t log_len, const char* whitelist_path,
        const char* blacklist_path);

#endif /* CHARRA_EVENT_LOG_H */
