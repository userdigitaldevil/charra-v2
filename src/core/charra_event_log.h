
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

#endif /* CHARRA_EVENT_LOG_H */
