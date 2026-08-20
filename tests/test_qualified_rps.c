/**
 * @file test_qualified_rps.c
 * @brief Standalone tests for the shared qualified-RP file.
 *
 * This is the gate that decides whether an RP's evidence is looked at, and
 * it is the only thing in the system with a lifetime, so the interesting
 * cases are all about time: a grant that has run out must stop counting,
 * and a record that cannot be read must not count as an unlimited one.
 *
 * Build and run:  make test_qualified_rps && ./bin/test_qualified_rps
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/verifier/verifier_qualified_rps.h"

static unsigned int tests_run = 0;
static unsigned int tests_failed = 0;

static void check(const char* name, bool condition) {
    tests_run++;
    if (condition) {
        printf("  PASS  %s\n", name);
    } else {
        tests_failed++;
        printf("  FAIL  %s\n", name);
    }
}

#define TMP_FILE "/tmp/charra_test_qualified_rps.txt"

/** A fingerprint that is not derived from any real key -- the lookup only
 * ever compares bytes, so any distinct pattern will do. */
static void make_fingerprint(uint8_t seed, uint8_t out[VERIFIER_RP_FINGERPRINT_LEN]) {
    for (size_t i = 0; i < VERIFIER_RP_FINGERPRINT_LEN; i++) {
        out[i] = (uint8_t)(seed + i);
    }
}

/** How many non-comment records the file holds. */
static int record_count(void) {
    FILE* f = fopen(TMP_FILE, "r");
    if (f == NULL) {
        return -1;
    }
    char line[256] = {0};
    int n = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] != '#' && line[0] != '\n') {
            n++;
        }
    }
    fclose(f);
    return n;
}

int main(void) {
    printf("Running qualified-RP file tests ...\n");

    const time_t now = 1700000000;
    uint8_t rp_a[VERIFIER_RP_FINGERPRINT_LEN];
    uint8_t rp_b[VERIFIER_RP_FINGERPRINT_LEN];
    make_fingerprint(0x10, rp_a);
    make_fingerprint(0x90, rp_b);

    printf("\na grant that has not run out counts\n");
    {
        remove(TMP_FILE);
        check("recording succeeds",
                verifier_qualified_rps_add(TMP_FILE, rp_a, now + 300) ==
                        CHARRA_RC_SUCCESS);
        check("qualified now",
                verifier_qualified_rps_is_qualified(TMP_FILE, rp_a, now));
        check("still qualified one second before it lapses",
                verifier_qualified_rps_is_qualified(
                        TMP_FILE, rp_a, now + 299));
    }

    /* The whole point of the change: an expired grant must stop counting
     * without anyone rewriting the file. */
    printf("\na grant that HAS run out stops counting\n");
    {
        check("not qualified at the deadline itself",
                !verifier_qualified_rps_is_qualified(
                        TMP_FILE, rp_a, now + 300));
        check("not qualified after it",
                !verifier_qualified_rps_is_qualified(
                        TMP_FILE, rp_a, now + 301));
    }

    printf("\nan RP with no record at all is not qualified\n");
    {
        uint8_t stranger[VERIFIER_RP_FINGERPRINT_LEN];
        make_fingerprint(0xC0, stranger);
        check("unknown RP rejected", !verifier_qualified_rps_is_qualified(
                                             TMP_FILE, stranger, now));
    }

    /* Renewal REPLACES the record rather than adding a second one, so the
     * file stays one line per RP however long a daemon runs. */
    printf("\nre-qualifying replaces the record, leaving exactly one\n");
    {
        check("one record before renewal", record_count() == 1);
        check("renewal recorded",
                verifier_qualified_rps_add(TMP_FILE, rp_a, now + 900) ==
                        CHARRA_RC_SUCCESS);
        check("STILL one record after renewal", record_count() == 1);
        check("qualified again past the OLD deadline",
                verifier_qualified_rps_is_qualified(
                        TMP_FILE, rp_a, now + 400));
        check("bounded by the NEW deadline",
                !verifier_qualified_rps_is_qualified(
                        TMP_FILE, rp_a, now + 900));
    }

    /* Replacing one RP must not disturb another's grant. */
    printf("\nreplacing one RP's record leaves other RPs untouched\n");
    {
        check("second RP recorded",
                verifier_qualified_rps_add(TMP_FILE, rp_b, now + 600) ==
                        CHARRA_RC_SUCCESS);
        check("two records now", record_count() == 2);
        check("renewing RP A again succeeds",
                verifier_qualified_rps_add(TMP_FILE, rp_a, now + 1200) ==
                        CHARRA_RC_SUCCESS);
        check("still two records", record_count() == 2);
        check("RP B's grant survived", verifier_qualified_rps_is_qualified(
                                               TMP_FILE, rp_b, now + 500));
        check("RP A got the new deadline",
                verifier_qualified_rps_is_qualified(
                        TMP_FILE, rp_a, now + 1000));
    }

    /* Defensive: a file left by an older build, or hand-edited, can hold
     * two records for one RP. The freshest must win -- resolving to the
     * stale one would expire a perfectly good grant. */
    printf("\na file with duplicate records resolves to the freshest\n");
    {
        remove(TMP_FILE);
        FILE* f = fopen(TMP_FILE, "w");
        for (size_t i = 0; i < VERIFIER_RP_FINGERPRINT_LEN; i++) {
            fprintf(f, "%02x", rp_a[i]);
        }
        fprintf(f, " %lld\n", (long long)(now + 100));
        for (size_t i = 0; i < VERIFIER_RP_FINGERPRINT_LEN; i++) {
            fprintf(f, "%02x", rp_a[i]);
        }
        fprintf(f, " %lld\n", (long long)(now + 900));
        fclose(f);
        check("latest deadline wins regardless of line order",
                verifier_qualified_rps_is_qualified(
                        TMP_FILE, rp_a, now + 400));
    }

    /* Fail closed. A line we cannot read is not a licence to trust the RP
     * forever -- which is exactly what treating a missing deadline as
     * "unlimited" would mean. */
    printf("\na record with no deadline fails closed\n");
    {
        remove(TMP_FILE);
        FILE* f = fopen(TMP_FILE, "w");
        for (size_t i = 0; i < VERIFIER_RP_FINGERPRINT_LEN; i++) {
            fprintf(f, "%02x", rp_a[i]);
        }
        fprintf(f, "\n"); /* fingerprint only, no deadline */
        fclose(f);
        check("not qualified", !verifier_qualified_rps_is_qualified(
                                       TMP_FILE, rp_a, now));
    }

    printf("\na missing file is not an error, just nobody qualified\n");
    {
        remove(TMP_FILE);
        check("not qualified", !verifier_qualified_rps_is_qualified(
                                       TMP_FILE, rp_a, now));
    }

    printf("\na nonsensical deadline is refused at write time\n");
    {
        check("zero rejected",
                verifier_qualified_rps_add(TMP_FILE, rp_a, 0) !=
                        CHARRA_RC_SUCCESS);
    }

    remove(TMP_FILE);
    printf("\n%u tests, %u failed\n", tests_run, tests_failed);
    return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
