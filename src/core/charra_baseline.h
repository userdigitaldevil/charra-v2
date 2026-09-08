/**
 * @file charra_baseline.h
 * @brief The file-policy list both the RP and the Verifier appraise against:
 * a vendor baseline of approved (or forbidden) files.
 *
 * Two formats are accepted, told apart by looking at the file rather than at
 * its name:
 *
 *  - **Vendor baseline JSON** -- the format a device vendor publishes, e.g.
 *    NODE_evidence_baseline.json:
 *
 *        { "products": [ { "ccFiles": [
 *            { "fileName": "libxt_tcp.so",
 *              "fileType": "IMA",
 *              "sha256":   "9c89d11f..." }, ... ] } ] }
 *
 *    Entries carry a NAME as well as a hash, so policy is checked on the
 *    **pair**. Only "IMA" entries are taken; a baseline that grows other
 *    fileTypes must not have them silently approve IMA measurements.
 *
 *  - **Flat hash list** -- one hex SHA-256 per line, '#' comments. Carries no
 *    names, so policy falls back to matching the hash alone.
 *
 * ## Why the pair, and not the hash alone
 *
 * Redaction keeps the filename in the clear (charra_sdk.h), so by the time
 * log_r reaches the Verifier every entry still says *what* it is as well as
 * what it hashed to. Checking both closes a gap the hash alone leaves open:
 * a genuinely approved binary, planted at a filename it has no business
 * being, passes a hash-only whitelist and fails a pair whitelist.
 *
 * It also matches how the vendor actually publishes the data. The baseline
 * is keyed by fileName with no directory anywhere in it -- which is the same
 * reason redaction commits the directory and keeps the name.
 *
 * ## The name a log entry is checked under
 *
 * Always the last component, so one rule covers both sides of the protocol:
 *
 *     log_a (RP)        /usr/lib64/xtables/libxt_tcp.so  ->  libxt_tcp.so
 *     log_r (Verifier)  <64 hex>/libxt_tcp.so            ->  libxt_tcp.so
 *
 * See charra_event_log_entry_file_name().
 */

#ifndef CHARRA_BASELINE_H
#define CHARRA_BASELINE_H

#include <stdbool.h>
#include <stdint.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/** Longest filename kept from a baseline. The reference baseline's longest
 * is 44 characters; anything past this is a malformed entry, not a file. */
#define CHARRA_BASELINE_NAME_MAX 256

typedef struct {
    char name[CHARRA_BASELINE_NAME_MAX];
    uint8_t hash[TPM2_SHA256_DIGEST_SIZE];
} charra_baseline_entry;

typedef struct {
    charra_baseline_entry* entries;
    uint32_t count;
    /** True if the source carried filenames, and therefore whether lookups
     * match on the pair or on the hash alone. */
    bool has_names;
} charra_baseline;

/**
 * @brief Load a policy list, detecting the format from its contents.
 *
 * A missing file is not an error: it yields an empty list, which the callers
 * treat as "nothing configured". That keeps a fresh checkout from rejecting
 * every attestation, which is the failure mode that gets a check disabled
 * permanently rather than fixed.
 */
CHARRA_RC charra_baseline_load(const char* path, charra_baseline* out);

void charra_baseline_free(charra_baseline* baseline);

/**
 * @brief Is this file permitted/denied by the list?
 *
 * When the baseline has names, `name` must match too; when it does not, the
 * hash decides alone. Passing a NULL name against a named baseline matches
 * on the hash alone and is reported by the caller, since "I could not read
 * the name" must not silently become "the name matched".
 */
bool charra_baseline_contains(
        const charra_baseline* baseline, const char* name, const uint8_t* hash);

/** @returns true if the hash appears under ANY name. Used to tell "wrong
 * file" apart from "right file, wrong name" when reporting a rejection. */
bool charra_baseline_contains_hash_only(
        const charra_baseline* baseline, const uint8_t* hash);

#endif /* CHARRA_BASELINE_H */
