/**
 * @file charra_ima_ascii.c
 * @brief ASCII <-> binary IMA measurement log. See charra_ima_ascii.h.
 */

#include "charra_ima_ascii.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "charra_event_log.h"

#define LOG_NAME "ima-ascii"

/* --- small helpers ------------------------------------------------------ */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/** @returns bytes written, or 0 if any character was not hex. */
static uint32_t hex_decode(
        const char* hex, size_t hex_len, uint8_t* out, size_t out_cap) {
    if ((hex_len % 2) != 0 || hex_len / 2 > out_cap) {
        return 0;
    }
    for (size_t i = 0; i < hex_len; i += 2) {
        const int hi = hex_nibble(hex[i]);
        const int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (uint32_t)(hex_len / 2);
}

static void hex_encode(const uint8_t* in, uint32_t in_len, char* out) {
    static const char D[] = "0123456789abcdef";
    for (uint32_t i = 0; i < in_len; i++) {
        out[2 * i] = D[in[i] >> 4];
        out[2 * i + 1] = D[in[i] & 0x0f];
    }
}

/**
 * @brief Does this physical line begin a new record?
 *
 * This is the whole of the line-unwrapping strategy: a record header is
 * "<digits> <even-length hex> <token> ", and a continuation line -- which
 * starts mid-hash or mid-path -- cannot look like that. Padding, wrapping
 * and unpadded kernel output all fall out of the same test, so neither the
 * 80-column artefact nor a live log needs its own code path.
 */
static bool is_record_start(const char* s, size_t len) {
    size_t i = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9') {
        i++;
    }
    if (i == 0 || i >= len || s[i] != ' ') {
        return false;
    }
    i++;

    const size_t hex_start = i;
    while (i < len && hex_nibble(s[i]) >= 0) {
        i++;
    }
    const size_t hex_len = i - hex_start;
    /* Only the two widths a TPM PCR bank actually uses. Being strict here is
     * what keeps a continuation line that happens to start with hex digits
     * from being mistaken for a header. */
    if (hex_len != 2 * TPM2_SHA1_DIGEST_SIZE &&
            hex_len != 2 * TPM2_SHA256_DIGEST_SIZE) {
        return false;
    }
    if (i >= len || s[i] != ' ') {
        return false;
    }
    i++;

    const size_t name_start = i;
    while (i < len && s[i] != ' ') {
        i++;
    }
    return i > name_start && i < len;
}

/* --- parse -------------------------------------------------------------- */

/**
 * @brief Append one joined record to the binary log at *offset.
 *
 * digest_len is in/out: zero on the first record, which adopts whatever the
 * record carries, and thereafter the width every later record must match.
 */
static CHARRA_RC append_record(const char* rec, size_t rec_len, uint8_t* out,
        uint32_t* offset, uint16_t* digest_len, uint32_t record_num) {
    size_t i = 0;

    /* --- column 1: PCR index --- */
    uint32_t pcr = 0;
    const size_t pcr_start = i;
    while (i < rec_len && rec[i] >= '0' && rec[i] <= '9') {
        pcr = pcr * 10 + (uint32_t)(rec[i] - '0');
        i++;
    }
    if (i == pcr_start || i >= rec_len || rec[i] != ' ') {
        charra_log_error("[" LOG_NAME "] Record %u: bad PCR index.", record_num);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    i++;

    /* --- column 2: template digest --- */
    const size_t td_start = i;
    while (i < rec_len && rec[i] != ' ') {
        i++;
    }
    uint8_t td[TPM2_SHA256_DIGEST_SIZE] = {0};
    const uint32_t td_len =
            hex_decode(rec + td_start, i - td_start, td, sizeof(td));
    if (td_len != TPM2_SHA1_DIGEST_SIZE && td_len != TPM2_SHA256_DIGEST_SIZE) {
        charra_log_error("[" LOG_NAME "] Record %u: template digest is not a "
                         "20- or 32-byte hex value.",
                record_num);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    if (*digest_len == 0) {
        *digest_len = (uint16_t)td_len;
    } else if (*digest_len != td_len) {
        charra_log_error("[" LOG_NAME "] Record %u: template digest is %u "
                         "bytes but the log started at %u. A log with mixed "
                         "digest widths cannot be replayed.",
                record_num, td_len, *digest_len);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    if (i >= rec_len) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    i++;

    /* --- column 3: template name --- */
    const size_t name_start = i;
    while (i < rec_len && rec[i] != ' ') {
        i++;
    }
    const size_t name_len = i - name_start;
    if (name_len != 6 || memcmp(rec + name_start, "ima-ng", 6) != 0) {
        /* The legacy "ima" template packs the filename in a fixed-size field
         * with no length prefix. Misparsing it would not fail here -- it
         * would shift every following entry, so refuse rather than guess. */
        charra_log_error("[" LOG_NAME "] Record %u: template is not 'ima-ng'. "
                         "Only ima-ng is supported.",
                record_num);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    if (i >= rec_len) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    i++;

    /* --- column 4: "<alg>:<file digest hex>" --- */
    const size_t alg_start = i;
    while (i < rec_len && rec[i] != ':' && rec[i] != ' ') {
        i++;
    }
    if (i >= rec_len || rec[i] != ':') {
        charra_log_error("[" LOG_NAME "] Record %u: file digest field has no "
                         "'<alg>:' prefix.",
                record_num);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    const size_t alg_len = i - alg_start; /* excludes the colon */
    i++;                                  /* step past ':' */

    const size_t fd_start = i;
    while (i < rec_len && rec[i] != ' ') {
        i++;
    }
    uint8_t fd[TPM2_SHA256_DIGEST_SIZE] = {0};
    const uint32_t fd_len =
            hex_decode(rec + fd_start, i - fd_start, fd, sizeof(fd));
    if (fd_len == 0) {
        charra_log_error(
                "[" LOG_NAME "] Record %u: file digest is not hex.", record_num);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    if (i >= rec_len) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    i++;

    /* --- column 5: the path, everything left. Taken verbatim, spaces and
     * all: it is the last column, so there is nothing it could run into. */
    const char* path = rec + i;
    const size_t path_len = rec_len - i;
    if (path_len == 0) {
        charra_log_error(
                "[" LOG_NAME "] Record %u: empty path.", record_num);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    /* --- rebuild the binary record ---
     * d-ng content is "<alg>:" + NUL + digest; the NUL is inside the field
     * and counted by its length. n-ng content is the path plus its NUL. */
    const uint32_t d_content_len = (uint32_t)alg_len + 2 + fd_len;
    const uint32_t n_content_len = (uint32_t)path_len + 1;
    const uint32_t td_data_len = (uint32_t)sizeof(uint32_t) + d_content_len +
                                 (uint32_t)sizeof(uint32_t) + n_content_len;

    charra_event_log_append_u32(out, offset, pcr);
    charra_event_log_append_bytes(out, offset, td, td_len);
    charra_event_log_append_u32(out, offset, (uint32_t)name_len);
    charra_event_log_append_bytes(
            out, offset, (const uint8_t*)rec + name_start, (uint32_t)name_len);
    charra_event_log_append_u32(out, offset, td_data_len);

    charra_event_log_append_u32(out, offset, d_content_len);
    charra_event_log_append_bytes(
            out, offset, (const uint8_t*)rec + alg_start, (uint32_t)alg_len);
    const uint8_t colon_nul[2] = {(uint8_t)':', 0};
    charra_event_log_append_bytes(out, offset, colon_nul, 2);
    charra_event_log_append_bytes(out, offset, fd, fd_len);

    charra_event_log_append_u32(out, offset, n_content_len);
    charra_event_log_append_bytes(
            out, offset, (const uint8_t*)path, (uint32_t)path_len);
    const uint8_t nul = 0;
    charra_event_log_append_bytes(out, offset, &nul, 1);

    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_ima_ascii_parse(const char* text, size_t text_len,
        uint8_t** log_out, uint32_t* log_len_out) {
    if (log_out == NULL || log_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (text == NULL && text_len != 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *log_out = NULL;
    *log_len_out = 0;
    if (text_len == 0) {
        return CHARRA_RC_SUCCESS;
    }

    /* The binary form of a record is always shorter than its ASCII form --
     * both digests halve, and only the u32 length prefixes are added back --
     * so the input length is a safe bound for the output. */
    uint8_t* out = malloc(text_len);
    char* rec = malloc(text_len + 1);
    if (out == NULL || rec == NULL) {
        free(out);
        free(rec);
        return CHARRA_RC_ERROR;
    }

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    uint32_t offset = 0;
    uint16_t digest_len = 0;
    uint32_t records = 0;
    size_t rec_len = 0;
    bool have_rec = false;

    size_t pos = 0;
    while (pos <= text_len) {
        /* One physical line, minus its terminator and any trailing padding.
         * The 80-column export pads with spaces; a live log does not. */
        size_t end = pos;
        while (end < text_len && text[end] != '\n') {
            end++;
        }
        size_t line_end = end;
        while (line_end > pos &&
                (text[line_end - 1] == ' ' || text[line_end - 1] == '\r' ||
                        text[line_end - 1] == '\t')) {
            line_end--;
        }
        const char* line = text + pos;
        const size_t line_len = line_end - pos;

        if (line_len > 0) {
            if (is_record_start(line, line_len)) {
                if (have_rec) {
                    charra_r = append_record(
                            rec, rec_len, out, &offset, &digest_len, records);
                    if (charra_r != CHARRA_RC_SUCCESS) {
                        goto done;
                    }
                    records++;
                }
                memcpy(rec, line, line_len);
                rec_len = line_len;
                have_rec = true;
            } else if (have_rec) {
                /* A continuation: the export wrapped mid-token, so the pieces
                 * join with nothing between them. */
                memcpy(rec + rec_len, line, line_len);
                rec_len += line_len;
            } else {
                charra_log_error("[" LOG_NAME "] Line before the first record "
                                 "header is not a record; log is malformed.");
                charra_r = CHARRA_RC_MARSHALING_ERROR;
                goto done;
            }
        }

        if (end >= text_len) {
            break;
        }
        pos = end + 1;
    }
    if (have_rec) {
        charra_r =
                append_record(rec, rec_len, out, &offset, &digest_len, records);
        if (charra_r != CHARRA_RC_SUCCESS) {
            goto done;
        }
        records++;
    }

    if (records == 0) {
        free(out);
        out = NULL;
    }
    *log_out = out;
    *log_len_out = offset;
    charra_log_info("[" LOG_NAME "] Parsed %u ASCII records (%zu bytes) into "
                    "%u bytes binary, %u-byte template digests.",
            records, text_len, offset, digest_len);
    free(rec);
    return CHARRA_RC_SUCCESS;

done:
    free(out);
    free(rec);
    return charra_r;
}

/* --- emit --------------------------------------------------------------- */

CHARRA_RC charra_ima_ascii_emit(const uint8_t* log, uint32_t log_len,
        char** text_out, size_t* text_len_out) {
    if (text_out == NULL || text_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (log == NULL && log_len != 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *text_out = NULL;
    *text_len_out = 0;

    uint16_t digest_len = 0;
    if (log_len == 0) {
        char* empty = malloc(1);
        if (empty == NULL) {
            return CHARRA_RC_ERROR;
        }
        empty[0] = '\0';
        *text_out = empty;
        return CHARRA_RC_SUCCESS;
    }
    CHARRA_RC charra_r =
            charra_event_log_ima_detect_digest_len(log, log_len, &digest_len);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    /* Hex doubles the two digests and the u32 prefixes disappear; twice the
     * binary length plus a fixed slab per entry covers both comfortably. */
    uint32_t entries = 0;
    {
        uint32_t off = 0;
        while (off < log_len) {
            charra_event_log_entry e = {0};
            charra_r = charra_event_log_parse_entry(
                    log, log_len, &off, digest_len, &e);
            if (charra_r != CHARRA_RC_SUCCESS) {
                return charra_r;
            }
            entries++;
        }
    }
    const size_t cap = (size_t)2 * log_len + (size_t)32 * entries + 1;
    char* buf = malloc(cap);
    if (buf == NULL) {
        return CHARRA_RC_ERROR;
    }

    size_t w = 0;
    uint32_t off = 0;
    uint32_t n = 0;
    while (off < log_len) {
        charra_event_log_entry e = {0};
        charra_r =
                charra_event_log_parse_entry(log, log_len, &off, digest_len, &e);
        if (charra_r != CHARRA_RC_SUCCESS) {
            goto fail;
        }

        /* Split template_data back into its two length-prefixed fields. The
         * d-ng field is rendered as "<alg>:<hex>", which means finding the
         * NUL that ends the algorithm name rather than assuming its width --
         * the assumption is what got this wrong before. */
        if (e.template_data_len < sizeof(uint32_t)) {
            charra_r = CHARRA_RC_MARSHALING_ERROR;
            goto fail;
        }
        const uint8_t* d = e.template_data;
        const uint32_t d_len = (uint32_t)d[0] | ((uint32_t)d[1] << 8) |
                               ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
        if (d_len > e.template_data_len - sizeof(uint32_t)) {
            charra_r = CHARRA_RC_MARSHALING_ERROR;
            goto fail;
        }
        const uint8_t* dc = d + sizeof(uint32_t);
        uint32_t alg_len = 0;
        while (alg_len < d_len && dc[alg_len] != '\0') {
            alg_len++;
        }
        if (alg_len == d_len) {
            charra_log_error("[" LOG_NAME "] Entry %u: d-ng field has no NUL "
                             "after the algorithm name.",
                    n);
            charra_r = CHARRA_RC_MARSHALING_ERROR;
            goto fail;
        }
        const uint8_t* fdig = dc + alg_len + 1;
        const uint32_t fdig_len = d_len - alg_len - 1;

        const uint8_t* nfield = d + sizeof(uint32_t) + d_len;
        if ((size_t)(nfield - e.template_data) + sizeof(uint32_t) >
                e.template_data_len) {
            charra_r = CHARRA_RC_MARSHALING_ERROR;
            goto fail;
        }
        const uint32_t n_len = (uint32_t)nfield[0] |
                               ((uint32_t)nfield[1] << 8) |
                               ((uint32_t)nfield[2] << 16) |
                               ((uint32_t)nfield[3] << 24);
        const uint8_t* path = nfield + sizeof(uint32_t);
        uint32_t path_len = n_len;
        /* The stored field carries the path's NUL; the rendered column does
         * not. */
        while (path_len > 0 && path[path_len - 1] == '\0') {
            path_len--;
        }

        const size_t need = 12 + 1 + (size_t)2 * e.template_digest_len + 1 +
                            e.template_name_len + 1 + alg_len + 1 +
                            (size_t)2 * fdig_len + 1 + path_len + 2;
        if (w + need > cap) {
            charra_r = CHARRA_RC_ERROR;
            goto fail;
        }

        w += (size_t)snprintf(buf + w, cap - w, "%" PRIu32 " ", e.pcr_index);
        hex_encode(e.template_digest, e.template_digest_len, buf + w);
        w += (size_t)2 * e.template_digest_len;
        buf[w++] = ' ';
        memcpy(buf + w, e.template_name, e.template_name_len);
        w += e.template_name_len;
        buf[w++] = ' ';
        /* Emit exactly one colon, whichever convention produced the entry.
         * Two do, and they disagree: charra_ima_ascii_parse() keeps the
         * colon in the stored prefix ("sha256:" NUL), while the Attester's
         * build_ima_ng_template_data() strips it ("sha256" NUL) -- and a
         * redacted log_r descends from the latter. Assuming either one
         * unconditionally gets the other wrong, as "sha256::" once and
         * "sha2569c89..." since. Neither re-parses. */
        memcpy(buf + w, dc, alg_len);
        w += alg_len;
        if (alg_len == 0 || dc[alg_len - 1] != ':') {
            buf[w++] = ':';
        }
        hex_encode(fdig, fdig_len, buf + w);
        w += (size_t)2 * fdig_len;
        buf[w++] = ' ';
        memcpy(buf + w, path, path_len);
        w += path_len;
        buf[w++] = '\n';
        n++;
    }
    buf[w] = '\0';
    *text_out = buf;
    *text_len_out = w;
    return CHARRA_RC_SUCCESS;

fail:
    free(buf);
    return charra_r;
}

/* --- file convenience --------------------------------------------------- */

CHARRA_RC charra_ima_ascii_read_file(
        const char* path, uint8_t** log_out, uint32_t* log_len_out) {
    if (path == NULL || log_out == NULL || log_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Could not open IMA log '%s'.", path);
        return CHARRA_RC_ERROR;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    const long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    char* text = malloc((size_t)size + 1);
    if (text == NULL) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    const size_t read = fread(text, 1, (size_t)size, f);
    fclose(f);
    text[read] = '\0';

    const CHARRA_RC charra_r =
            charra_ima_ascii_parse(text, read, log_out, log_len_out);
    free(text);
    return charra_r;
}
