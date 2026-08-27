/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file charra_zk_job.c
 * @brief Client for the proof watcher -- see charra_zk_job.h.
 */

#include "charra_zk_job.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../common/charra_log.h"

#define LOG_NAME "zk-job"

#define POLL_INTERVAL_MS 100

/* Public-input layout, confirmed against a real bb run: one field element
 * per BYTE of each byte-array input, 32 bytes each, big-endian, in the order
 * main() declares them.
 *
 *   fields    0..1055  file_hashes  (33 x 32)
 *   fields 1056..1311  other_pcrs   (8 x 32, all zero)
 *   fields 1312..1344  commitments  (33)
 *   fields 1345..1376  pcrdigest_a  (32)
 *
 * Note the commitments sit BEFORE pcrdigest_a. They were last while the
 * circuit returned them; making them a parameter moved them. Nothing warns
 * about getting this wrong -- verification simply fails. */
#define PI_FIELDS 1377
#define PI_FIELD_BYTES 32
#define PI_TOTAL (PI_FIELDS * PI_FIELD_BYTES)
#define PI_OFF_FILE_HASHES 0
#define PI_OFF_OTHER_PCRS 1056
#define PI_OFF_COMMITMENTS 1312
#define PI_OFF_PCRDIGEST 1345

static const char* jobs_root(void) {
    const char* r = getenv("CHARRA_ZK_JOBS");
    return (r != NULL && r[0] != '\0') ? r : CHARRA_ZK_JOBS_DEFAULT;
}

static unsigned timeout_seconds(void) {
    const char* t = getenv("CHARRA_ZK_TIMEOUT");
    if (t != NULL && t[0] != '\0') {
        long v = strtol(t, NULL, 10);
        if (v > 0) {
            return (unsigned)v;
        }
    }
    return CHARRA_ZK_TIMEOUT_DEFAULT;
}

static CHARRA_RC write_file(
        const char* path, const void* data, size_t len) {
    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        charra_log_error("[" LOG_NAME "] Could not write %s: %s", path,
                strerror(errno));
        return CHARRA_RC_ERROR;
    }
    bool ok = (len == 0) || (fwrite(data, 1, len, f) == len);
    if (fclose(f) != 0 || !ok) {
        charra_log_error("[" LOG_NAME "] Could not finish writing %s.", path);
        return CHARRA_RC_ERROR;
    }
    return CHARRA_RC_SUCCESS;
}

static CHARRA_RC read_file(
        const char* path, uint8_t** out, uint32_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        return CHARRA_RC_ERROR;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    long n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    uint8_t* buf = malloc((size_t)n ? (size_t)n : 1);
    if (buf == NULL) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    fclose(f);
    *out = buf;
    *out_len = (uint32_t)n;
    return CHARRA_RC_SUCCESS;
}

/* Build the job in .staging and rename it into place: rename is atomic, so
 * the watcher never sees a half-written job and no locking is required. */
static CHARRA_RC stage_and_submit(const char* kind, char* job_out,
        size_t job_out_len, CHARRA_RC (*populate)(const char*, const void*),
        const void* ctx) {
    char staging[512];
    char final[512];
    static unsigned counter = 0;

    snprintf(staging, sizeof(staging), "%s/.staging", jobs_root());
    mkdir(jobs_root(), 0700);
    mkdir(staging, 0700);

    char id[128];
    snprintf(id, sizeof(id), "%s-%ld-%d-%u", kind, (long)time(NULL), (int)getpid(),
            counter++);
    snprintf(staging, sizeof(staging), "%s/.staging/%s", jobs_root(), id);
    snprintf(final, sizeof(final), "%s/%s", jobs_root(), id);

    if (mkdir(staging, 0700) != 0) {
        charra_log_error("[" LOG_NAME "] Could not create %s: %s", staging,
                strerror(errno));
        return CHARRA_RC_ERROR;
    }

    char kindfile[600];
    snprintf(kindfile, sizeof(kindfile), "%s/kind", staging);
    CHARRA_RC charra_r = write_file(kindfile, kind, strlen(kind));
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    charra_r = populate(staging, ctx);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    if (rename(staging, final) != 0) {
        charra_log_error("[" LOG_NAME "] Could not submit job: %s",
                strerror(errno));
        return CHARRA_RC_ERROR;
    }
    snprintf(job_out, job_out_len, "%s", final);
    return CHARRA_RC_SUCCESS;
}

/* Wait for the watcher's `done` marker, which it writes last. */
static CHARRA_RC await_job(const char* job, char* status, size_t status_len) {
    char donefile[600];
    snprintf(donefile, sizeof(donefile), "%s/done", job);

    const unsigned timeout = timeout_seconds();
    const unsigned max_polls = timeout * (1000 / POLL_INTERVAL_MS);
    struct timespec ts = {
            .tv_sec = 0, .tv_nsec = POLL_INTERVAL_MS * 1000L * 1000L};

    for (unsigned i = 0; i < max_polls; i++) {
        if (access(donefile, F_OK) == 0) {
            char statusfile[600];
            snprintf(statusfile, sizeof(statusfile), "%s/status", job);
            uint8_t* buf = NULL;
            uint32_t len = 0;
            if (read_file(statusfile, &buf, &len) == CHARRA_RC_SUCCESS) {
                size_t n = (len < status_len - 1) ? len : status_len - 1;
                memcpy(status, buf, n);
                status[n] = '\0';
                while (n > 0 && (status[n - 1] == '\n' || status[n - 1] == ' ')) {
                    status[--n] = '\0';
                }
                free(buf);
            } else {
                snprintf(status, status_len, "no status file");
            }
            return CHARRA_RC_SUCCESS;
        }
        nanosleep(&ts, NULL);
    }

    charra_log_error("[" LOG_NAME "] No answer from the proof watcher after "
                     "%u s. Is zk/proof_watcher.sh running on the host?",
            timeout);
    return CHARRA_RC_TIMEOUT;
}

/* --- prove ------------------------------------------------------------- */

static CHARRA_RC populate_prove(const char* dir, const void* ctx) {
    char p[600];
    snprintf(p, sizeof(p), "%s/witness.json", dir);
    return charra_zk_write_witness_json((const charra_zk_witness*)ctx, p);
}

CHARRA_RC charra_zk_prove(const charra_zk_witness* witness, uint8_t** proof,
        uint32_t* proof_len) {
    if (witness == NULL || proof == NULL || proof_len == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    char job[512];
    CHARRA_RC charra_r = stage_and_submit(
            "prove", job, sizeof(job), populate_prove, witness);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }
    charra_log_info("[" LOG_NAME "] Submitted proof job, waiting ...");

    char status[256] = {0};
    charra_r = await_job(job, status, sizeof(status));
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }
    if (strcmp(status, "ok") != 0) {
        /* "does not replay" means the log handed in is not the log the
         * Attester's TPM attested to -- an attestation failure, not a
         * broken toolchain. */
        charra_log_error("[" LOG_NAME "] Proving failed: %s", status);
        return CHARRA_RC_ERROR;
    }

    char proofpath[600];
    snprintf(proofpath, sizeof(proofpath), "%s/proof", job);
    charra_r = read_file(proofpath, proof, proof_len);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Watcher reported ok but no proof.");
        return charra_r;
    }
    charra_log_info("[" LOG_NAME "] Got a %u-byte proof.", *proof_len);
    return CHARRA_RC_SUCCESS;
}

/* --- verify ------------------------------------------------------------ */

/* One byte -> one 32-byte big-endian field element. */
static void put_bytes_as_fields(
        uint8_t* pi, size_t field_index, const uint8_t* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        pi[(field_index + i) * PI_FIELD_BYTES + PI_FIELD_BYTES - 1] = src[i];
    }
}

/* A commitment is already a field element: 32 bytes big-endian, verbatim. */
static void put_field(uint8_t* pi, size_t field_index, const uint8_t* src) {
    memcpy(pi + field_index * PI_FIELD_BYTES, src, PI_FIELD_BYTES);
}

struct verify_ctx {
    const uint8_t* proof;
    uint32_t proof_len;
    const charra_zk_public_inputs* inputs;
};

static CHARRA_RC populate_verify(const char* dir, const void* vctx) {
    const struct verify_ctx* c = (const struct verify_ctx*)vctx;
    char p[600];

    snprintf(p, sizeof(p), "%s/proof", dir);
    CHARRA_RC charra_r = write_file(p, c->proof, c->proof_len);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    uint8_t* pi = calloc(1, PI_TOTAL);
    if (pi == NULL) {
        return CHARRA_RC_ERROR;
    }
    for (uint32_t i = 0; i < CHARRA_ZK_NUM_ENTRIES; i++) {
        put_bytes_as_fields(pi, PI_OFF_FILE_HASHES + i * 32,
                c->inputs->file_hashes[i], 32);
        put_field(pi, PI_OFF_COMMITMENTS + i, c->inputs->commitments[i]);
    }
    /* other_pcrs stay zero -- calloc already did that. */
    (void)PI_OFF_OTHER_PCRS;
    put_bytes_as_fields(pi, PI_OFF_PCRDIGEST, c->inputs->pcrdigest_a, 32);

    snprintf(p, sizeof(p), "%s/public_inputs", dir);
    charra_r = write_file(p, pi, PI_TOTAL);
    free(pi);
    return charra_r;
}

CHARRA_RC charra_zk_verify(const uint8_t* proof, uint32_t proof_len,
        const charra_zk_public_inputs* inputs, bool* verified) {
    if (proof == NULL || inputs == NULL || verified == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *verified = false;

    if (proof_len == 0) {
        charra_log_error("[" LOG_NAME "] No proof was supplied.");
        return CHARRA_RC_SUCCESS; /* a missing proof is a rejection */
    }

    struct verify_ctx ctx = {
            .proof = proof, .proof_len = proof_len, .inputs = inputs};
    char job[512];
    CHARRA_RC charra_r = stage_and_submit(
            "verify", job, sizeof(job), populate_verify, &ctx);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    char status[256] = {0};
    charra_r = await_job(job, status, sizeof(status));
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }
    if (strcmp(status, "ok") != 0) {
        charra_log_error("[" LOG_NAME "] Verification could not be run: %s",
                status);
        return CHARRA_RC_ERROR;
    }

    char resultpath[600];
    snprintf(resultpath, sizeof(resultpath), "%s/result", job);
    uint8_t* buf = NULL;
    uint32_t len = 0;
    if (read_file(resultpath, &buf, &len) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Watcher reported ok but no verdict.");
        return CHARRA_RC_ERROR;
    }
    *verified = (len >= 8) && (memcmp(buf, "verified", 8) == 0);
    free(buf);

    charra_log_info("[" LOG_NAME "] Proof %s.",
            *verified ? "VERIFIED" : "REJECTED");
    return CHARRA_RC_SUCCESS;
}
