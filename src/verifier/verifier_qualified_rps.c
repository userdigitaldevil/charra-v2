/**
 * @file verifier_qualified_rps.c
 * @brief See verifier_qualified_rps.h.
 */

#include "verifier_qualified_rps.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../common/charra_log.h"
#include "../util/crypto_util.h"
#include "../util/hex_util.h"

#define LOG_NAME "verifier"

/** Two hex characters per byte, plus the terminator. */
#define FINGERPRINT_HEX_LEN (VERIFIER_RP_FINGERPRINT_LEN * 2)

static const char* resolve_path(const char* path) {
    return (path != NULL) ? path : VERIFIER_QUALIFIED_RPS_DEFAULT_PATH;
}

/** @brief Render a fingerprint as the lowercase hex one line holds. */
static void fingerprint_to_hex(
        const uint8_t fingerprint[VERIFIER_RP_FINGERPRINT_LEN],
        char out[FINGERPRINT_HEX_LEN + 1]) {
    for (size_t i = 0; i < VERIFIER_RP_FINGERPRINT_LEN; i++) {
        snprintf(out + (i * 2), 3, "%02x", fingerprint[i]);
    }
    out[FINGERPRINT_HEX_LEN] = '\0';
}

CHARRA_RC verifier_qualified_rps_fingerprint(const uint8_t* ak_public_key,
        size_t ak_public_key_len,
        uint8_t fingerprint_out[VERIFIER_RP_FINGERPRINT_LEN]) {
    if (ak_public_key == NULL || ak_public_key_len == 0 ||
            fingerprint_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    return hash_sha256(ak_public_key_len, ak_public_key, fingerprint_out);
}

/**
 * @brief Latest deadline on file for this RP, or 0 if it has none.
 *
 * "Latest", not "first". The writer keeps one record per RP, so there is
 * normally only one -- but taking the latest means a hand-edited file, or
 * one left by an older build, still resolves to the freshest grant rather
 * than a stale one. A line whose deadline will not parse is skipped rather
 * than treated as unlimited: an unreadable grant is not a grant.
 */
static time_t latest_expiry(
        const char* path, const uint8_t fingerprint[VERIFIER_RP_FINGERPRINT_LEN]) {
    FILE* f = fopen(path, "r");
    if (f == NULL) {
        /* Nobody has qualified yet. Not an error: the file is created by
         * the first successful /qualify_submit, not at startup. */
        return 0;
    }

    char wanted[FINGERPRINT_HEX_LEN + 1] = {0};
    fingerprint_to_hex(fingerprint, wanted);

    char line[256] = {0};
    time_t newest = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        if (strncmp(line, wanted, FINGERPRINT_HEX_LEN) != 0) {
            continue;
        }
        /* <fingerprint-hex> <expires-at>; anything else is malformed and
         * deliberately yields no grant at all. */
        long long expires_at = 0;
        if (sscanf(line + FINGERPRINT_HEX_LEN, " %lld", &expires_at) != 1 ||
                expires_at <= 0) {
            charra_log_warn("[" LOG_NAME "] Qualified-RP file ('%s') has a "
                            "record for %.16s... with no readable deadline; "
                            "ignoring it.",
                    path, wanted);
            continue;
        }
        if ((time_t)expires_at > newest) {
            newest = (time_t)expires_at;
        }
    }
    fclose(f);
    return newest;
}

bool verifier_qualified_rps_is_qualified(const char* path,
        const uint8_t fingerprint[VERIFIER_RP_FINGERPRINT_LEN], time_t now) {
    if (fingerprint == NULL) {
        return false;
    }
    return now < latest_expiry(resolve_path(path), fingerprint);
}

/** The header written at the top of a freshly-rewritten file. */
static void write_header(FILE* f) {
    fprintf(f,
            "# RPs that have passed /qualify + /qualify_submit, shared by "
            "every Verifier.\n"
            "#\n"
            "#   <SHA-256 of the RP's AK public key>  <expires-at, epoch "
            "seconds>\n"
            "#\n"
            "# One line per RP: re-qualifying REPLACES that RP's record "
            "rather than adding\n"
            "# a second one. The deadline is the one the issuing Verifier "
            "granted\n"
            "# (--qualification-validity); every other Verifier honours that "
            "same number\n"
            "# rather than deriving its own.\n"
            "# See src/verifier/verifier_qualified_rps.h.\n");
}

CHARRA_RC verifier_qualified_rps_add(const char* path,
        const uint8_t fingerprint[VERIFIER_RP_FINGERPRINT_LEN],
        time_t expires_at) {
    if (fingerprint == NULL || expires_at <= 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    path = resolve_path(path);

    char hex[FINGERPRINT_HEX_LEN + 1] = {0};
    fingerprint_to_hex(fingerprint, hex);

    /* Rewrite rather than append, so an RP has exactly one record and a
     * renewal leaves no stale line behind. Done as write-to-temp then
     * rename(): rename is atomic within a filesystem, so a sibling
     * Verifier reading concurrently sees either the whole old file or the
     * whole new one, never a half-written one. Truncating the live file in
     * place would give readers a window in which the RP looks unqualified
     * -- and a Verifier that read during that window would vote NO for no
     * reason anyone could later reconstruct. */
    char tmp_path[512] = {0};
    if ((size_t)snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path) >=
            sizeof(tmp_path)) {
        charra_log_error("[" LOG_NAME "] Qualified-RP file path is too long "
                         "to build a temporary name from ('%s').",
                path);
        return CHARRA_RC_ERROR;
    }

    FILE* out = fopen(tmp_path, "w");
    if (out == NULL) {
        charra_log_error("[" LOG_NAME "] Could not open '%s' to rewrite the "
                         "qualified-RP file.",
                tmp_path);
        return CHARRA_RC_ERROR;
    }
    write_header(out);

    /* Carry over every OTHER RP's record verbatim; this RP's own is
     * dropped, since the new one below replaces it. */
    FILE* in = fopen(path, "r");
    if (in != NULL) {
        char line[256] = {0};
        while (fgets(line, sizeof(line), in) != NULL) {
            if (line[0] == '#' || line[0] == '\n') {
                continue; /* the header is regenerated above */
            }
            if (strncmp(line, hex, FINGERPRINT_HEX_LEN) == 0) {
                continue; /* superseded */
            }
            fputs(line, out);
        }
        fclose(in);
    }

    fprintf(out, "%s %lld\n", hex, (long long)expires_at);

    /* Flush before the rename, or the rename can publish a file whose
     * contents are still sitting in this process's stdio buffer. */
    if (fflush(out) != 0 || fclose(out) != 0) {
        charra_log_error("[" LOG_NAME "] Could not write the qualified-RP "
                         "file ('%s').",
                tmp_path);
        remove(tmp_path);
        return CHARRA_RC_ERROR;
    }

    if (rename(tmp_path, path) != 0) {
        charra_log_error("[" LOG_NAME "] Could not move '%s' into place as "
                         "'%s'.",
                tmp_path, path);
        remove(tmp_path);
        return CHARRA_RC_ERROR;
    }

    charra_log_info("[" LOG_NAME "] Recorded RP %.16s... as qualified until "
                    "%lld (%lld second(s) from now) in the shared file "
                    "('%s'); every Verifier honours it.",
            hex, (long long)expires_at,
            (long long)(expires_at - time(NULL)), path);
    return CHARRA_RC_SUCCESS;
}
