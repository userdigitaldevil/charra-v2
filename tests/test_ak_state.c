/**
 * @file test_ak_state.c
 * @brief Standalone tests for the AK-provisioning state module
 * (charra_ak_state.h) -- persisted record of AK certificates issued via
 * /certify_ak, used to implement rolling renewal (a fresh request always
 * revokes the requester's previous record) and to give a future revocation
 * check (Step 3a/3b item 1) somewhere to look up a presented certificate's
 * serial number.
 *
 * Build and run: make test_ak_state && ./bin/test_ak_state
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/charra_ak_state.h"

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

/** A path under the repo root, same convention as other config files this
 * project reads/writes (verifiers_config.txt, reference-pcrs.txt, ...).
 * Removed (along with its .lock companion) at the start and end of the
 * suite so re-runs start clean. */
static const char* STATE_PATH = "test_ak_state_tmp.txt";

static void remove_state_file(void) {
    char lock_path[256];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", STATE_PATH);
    remove(STATE_PATH);
    remove(lock_path);
}

static void fill_fingerprint(uint8_t out[32], uint8_t seed) {
    for (int i = 0; i < 32; i++) {
        out[i] = (uint8_t)(seed + i);
    }
}

static void fill_serial(uint8_t out[16], uint8_t seed) {
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(seed + i);
    }
}

static charra_ak_state_record make_record(
        uint8_t fingerprint_seed, uint8_t serial_seed, time_t expires_at) {
    charra_ak_state_record rec = {0};
    fill_fingerprint(rec.ek_fingerprint, fingerprint_seed);
    fill_serial(rec.serial, serial_seed);
    rec.ak_name_len = 4;
    rec.ak_name[0] = 0xAA;
    rec.ak_name[1] = 0xBB;
    rec.ak_name[2] = 0xCC;
    rec.ak_name[3] = 0xDD;
    rec.issued_at = 1000;
    rec.expires_at = expires_at;
    rec.revoked = false;
    return rec;
}

static void test_load_missing_file_is_empty_not_error(void) {
    printf("\nloading a state file that doesn't exist yet returns zero "
           "records, not an error\n");

    remove_state_file();

    charra_ak_state_record* records = NULL;
    uint32_t count = 0;
    CHARRA_RC rc = charra_ak_state_load(STATE_PATH, &records, &count);
    check("load succeeds", rc == CHARRA_RC_SUCCESS);
    check("zero records", count == 0);
    check("records left NULL", records == NULL);

    free(records);
}

static void test_save_load_round_trip(void) {
    printf("\nsaved records survive a load byte for byte\n");

    charra_ak_state_record in[2];
    in[0] = make_record(0x10, 0x20, 5000);
    in[1] = make_record(0x30, 0x40, 6000);
    in[1].revoked = true;

    CHARRA_RC rc = charra_ak_state_save(STATE_PATH, in, 2);
    check("save succeeds", rc == CHARRA_RC_SUCCESS);

    charra_ak_state_record* out = NULL;
    uint32_t out_count = 0;
    rc = charra_ak_state_load(STATE_PATH, &out, &out_count);
    check("load succeeds", rc == CHARRA_RC_SUCCESS);
    check("record count round-trips", out_count == 2);
    if (out_count == 2) {
        check("record[0] ek_fingerprint round-trips",
                memcmp(in[0].ek_fingerprint, out[0].ek_fingerprint, 32) == 0);
        check("record[0] ak_name round-trips",
                in[0].ak_name_len == out[0].ak_name_len &&
                        memcmp(in[0].ak_name, out[0].ak_name,
                                in[0].ak_name_len) == 0);
        check("record[0] serial round-trips",
                memcmp(in[0].serial, out[0].serial, 16) == 0);
        check("record[0] issued_at round-trips",
                in[0].issued_at == out[0].issued_at);
        check("record[0] expires_at round-trips",
                in[0].expires_at == out[0].expires_at);
        check("record[0] revoked=false round-trips", out[0].revoked == false);
        check("record[1] revoked=true round-trips", out[1].revoked == true);
    }

    free(out);
}

static void test_find_by_ek_fingerprint(void) {
    printf("\nfind_by_ek_fingerprint locates the right record, and reports "
           "no match honestly\n");

    charra_ak_state_record records[2];
    records[0] = make_record(0x01, 0x01, 5000);
    records[1] = make_record(0x02, 0x02, 5000);

    uint32_t index = 999;
    check("finds record[1]",
            charra_ak_state_find_by_ek_fingerprint(
                    records, 2, records[1].ek_fingerprint, &index) &&
                    index == 1);

    uint8_t unknown_fingerprint[32] = {0};
    memset(unknown_fingerprint, 0xFF, sizeof(unknown_fingerprint));
    check("unknown fingerprint not found",
            !charra_ak_state_find_by_ek_fingerprint(
                    records, 2, unknown_fingerprint, &index));
}

static void test_find_by_ek_fingerprint_prefers_most_recent(void) {
    printf("\nfind_by_ek_fingerprint returns the MOST RECENT record for a "
           "fingerprint, not the oldest -- otherwise repeated renewals "
           "would keep finding an already-revoked record\n");

    charra_ak_state_record records[3];
    records[0] = make_record(0x01, 0x01, 5000); /* oldest, revoked */
    records[0].revoked = true;
    records[1] = make_record(0x02, 0x02, 5000); /* unrelated fingerprint */
    records[2] = make_record(0x01, 0x03, 6000); /* newest, same fingerprint
                                                    as records[0], active */

    uint32_t index = 999;
    bool found = charra_ak_state_find_by_ek_fingerprint(
            records, 3, records[0].ek_fingerprint, &index);
    check("finds a match", found);
    check("finds the newest record (index 2), not the oldest (index 0)",
            found && index == 2);
}

static void test_find_by_serial(void) {
    printf("\nfind_by_serial locates the right record\n");

    charra_ak_state_record records[2];
    records[0] = make_record(0x01, 0x11, 5000);
    records[1] = make_record(0x02, 0x22, 5000);

    uint32_t index = 999;
    check("finds record[0] by its serial",
            charra_ak_state_find_by_serial(
                    records, 2, records[0].serial, &index) &&
                    index == 0);

    uint8_t unknown_serial[16] = {0};
    memset(unknown_serial, 0xEE, sizeof(unknown_serial));
    check("unknown serial not found",
            !charra_ak_state_find_by_serial(
                    records, 2, unknown_serial, &index));
}

static void test_is_valid(void) {
    printf("\nis_valid: not revoked and not expired\n");

    charra_ak_state_record active = make_record(0x01, 0x01, 5000);
    check("active record is valid at t=4000",
            charra_ak_state_is_valid(&active, 4000));
    check("active record is invalid once past expiry (t=5001)",
            !charra_ak_state_is_valid(&active, 5001));

    charra_ak_state_record revoked = make_record(0x01, 0x01, 5000);
    revoked.revoked = true;
    check("revoked record is invalid even before expiry (t=4000)",
            !charra_ak_state_is_valid(&revoked, 4000));

    check("NULL record is invalid", !charra_ak_state_is_valid(NULL, 4000));
}

static void test_renew_first_issuance(void) {
    printf("\nrenew: first issuance for an EK creates exactly one active "
           "record\n");

    remove_state_file();

    uint8_t fingerprint[32];
    fill_fingerprint(fingerprint, 0x50);
    charra_ak_state_record rec = make_record(0x50, 0x60, 9999999999);

    CHARRA_RC rc = charra_ak_state_renew(STATE_PATH, fingerprint, &rec);
    check("renew succeeds", rc == CHARRA_RC_SUCCESS);

    charra_ak_state_record* records = NULL;
    uint32_t count = 0;
    charra_ak_state_load(STATE_PATH, &records, &count);
    check("exactly one record on disk", count == 1);
    if (count == 1) {
        check("it is not revoked", records[0].revoked == false);
        check("its serial matches what was issued",
                memcmp(records[0].serial, rec.serial, 16) == 0);
    }
    free(records);
}

static void test_renew_revokes_previous_and_survives_multiple_cycles(void) {
    printf("\nrenew: each subsequent renewal for the same EK revokes "
           "exactly the previous active record, across several cycles -- "
           "this is what the find_by_ek_fingerprint backward-scan fix "
           "above is for\n");

    remove_state_file();

    uint8_t fingerprint[32];
    fill_fingerprint(fingerprint, 0x70);

    const int num_renewals = 4;
    for (int i = 0; i < num_renewals; i++) {
        charra_ak_state_record rec =
                make_record(0x70, (uint8_t)(0x80 + i), 9999999999);
        CHARRA_RC rc = charra_ak_state_renew(STATE_PATH, fingerprint, &rec);
        check("renewal succeeds", rc == CHARRA_RC_SUCCESS);
    }

    charra_ak_state_record* records = NULL;
    uint32_t count = 0;
    charra_ak_state_load(STATE_PATH, &records, &count);
    check("one record per renewal on disk",
            count == (uint32_t)num_renewals);

    uint32_t active_count = 0;
    uint32_t revoked_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (records[i].revoked) {
            revoked_count++;
        } else {
            active_count++;
        }
    }
    check("exactly one active (unrevoked) record survives",
            active_count == 1);
    check("all the others ended up revoked",
            revoked_count == (uint32_t)num_renewals - 1);

    /* the one still-active record must be the LAST one issued */
    if (count > 0) {
        charra_ak_state_record expected_active =
                make_record(0x70, (uint8_t)(0x80 + num_renewals - 1), 0);
        check("the active record is the most recently issued one",
                !records[count - 1].revoked &&
                        memcmp(records[count - 1].serial,
                                expected_active.serial, 16) == 0);
    }

    free(records);
}

static void test_renew_bad_arguments_rejected(void) {
    printf("\nrenew: bad arguments\n");

    uint8_t fingerprint[32] = {0};
    charra_ak_state_record rec = make_record(0x01, 0x01, 5000);

    check("NULL path rejected",
            charra_ak_state_renew(NULL, fingerprint, &rec) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL fingerprint rejected",
            charra_ak_state_renew(STATE_PATH, NULL, &rec) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL record rejected",
            charra_ak_state_renew(STATE_PATH, fingerprint, NULL) ==
                    CHARRA_RC_BAD_ARGUMENT);

    uint8_t mismatched_fingerprint[32];
    fill_fingerprint(mismatched_fingerprint, 0x99);
    check("mismatched fingerprint/record rejected",
            charra_ak_state_renew(
                    STATE_PATH, mismatched_fingerprint, &rec) ==
                    CHARRA_RC_BAD_ARGUMENT);
}

int main(void) {
    printf("AK-provisioning state tests\n");
    printf("============================\n");

    test_load_missing_file_is_empty_not_error();
    test_save_load_round_trip();
    test_find_by_ek_fingerprint();
    test_find_by_ek_fingerprint_prefers_most_recent();
    test_find_by_serial();
    test_is_valid();
    test_renew_first_issuance();
    test_renew_revokes_previous_and_survives_multiple_cycles();
    test_renew_bad_arguments_rejected();

    remove_state_file();

    printf("\n============================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
