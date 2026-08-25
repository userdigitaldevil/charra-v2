/**
 * @file test_pcr_selection.c
 * @brief Tests for charra_helper.h's PCR selection conversion.
 *
 * charra_tpm2_pcr_selection_to_bitmap() turns the array of PCR indices an
 * /attest request carries into the TPMS_PCR_SELECTION bitmap TPM2_Quote
 * wants. Two things make it worth its own suite:
 *
 *   - sizeofSelect is fixed at 3 bytes, covering PCRs 0..23, because a PC
 *     Client TPM has 24 PCRs while TPM2_MAX_PCRS is the spec ceiling of
 *     32. A selection describing PCRs the device lacks is refused by the
 *     TPM, so this bound is load-bearing rather than cosmetic.
 *   - an index it cannot encode must be REJECTED. It used to log and
 *     continue, returning SUCCESS on a selection silently missing the PCR
 *     the caller asked for.
 *
 * Pure function: no TPM, no network.
 *
 * Build and run:  make test_pcr_selection && ./bin/test_pcr_selection
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "../src/core/charra_helper.h"

/** Highest PCR this build can encode; see the header note above. */
#define ENCODABLE_PCRS (TPM2_MAX_PCRS - 8)

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

/** @brief Is exactly this bit, and no other, set in the bitmap? */
static bool only_bit_set(const TPMS_PCR_SELECTION* b, uint32_t pcr) {
    for (uint32_t i = 0; i < b->sizeofSelect; ++i) {
        uint8_t want = (i == pcr / 8) ? (uint8_t)(1u << (pcr % 8)) : 0u;
        if (b->pcrSelect[i] != want) {
            return false;
        }
    }
    return true;
}

static void test_single_pcr(void) {
    printf("\none PCR sets exactly one bit\n");

    /* Every encodable index, not a sample: the byte/bit arithmetic is the
     * whole function, and an off-by-one at a byte boundary (7->8, 15->16)
     * is exactly what a spot check would miss. */
    bool all_ok = true;
    for (uint32_t pcr = 0; pcr < ENCODABLE_PCRS; ++pcr) {
        TPMS_PCR_SELECTION bitmap = {0};
        uint8_t sel[1] = {(uint8_t)pcr};
        if (charra_tpm2_pcr_selection_to_bitmap(1, sel, &bitmap) !=
                        CHARRA_RC_SUCCESS ||
                !only_bit_set(&bitmap, pcr)) {
            printf("        (first failure at PCR %u)\n", pcr);
            all_ok = false;
            break;
        }
    }
    check("PCRs 0..23 each map to their own bit", all_ok);
}

static void test_multiple_pcrs(void) {
    printf("\nthe live selection {0..7, 10} converts as expected\n");

    TPMS_PCR_SELECTION bitmap = {0};
    uint8_t sel[] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
    check("conversion succeeds",
            charra_tpm2_pcr_selection_to_bitmap(
                    sizeof(sel), sel, &bitmap) == CHARRA_RC_SUCCESS);

    /* PCRs 0-7 fill byte 0; PCR 10 is bit 2 of byte 1. */
    check("byte 0 holds PCRs 0-7", bitmap.pcrSelect[0] == 0xff);
    check("byte 1 holds only PCR 10", bitmap.pcrSelect[1] == 0x04);
    check("byte 2 is empty", bitmap.pcrSelect[2] == 0x00);

    /* Order must not matter, and a repeat must not toggle a bit off. */
    TPMS_PCR_SELECTION shuffled = {0};
    uint8_t sel2[] = {10, 7, 0, 3, 1, 6, 2, 5, 4};
    charra_tpm2_pcr_selection_to_bitmap(sizeof(sel2), sel2, &shuffled);
    check("selection order does not change the bitmap",
            memcmp(bitmap.pcrSelect, shuffled.pcrSelect,
                    bitmap.sizeofSelect) == 0);

    TPMS_PCR_SELECTION repeated = {0};
    uint8_t sel3[] = {10, 10, 10};
    charra_tpm2_pcr_selection_to_bitmap(sizeof(sel3), sel3, &repeated);
    check("a repeated index sets the bit once, not zero times",
            repeated.pcrSelect[1] == 0x04);
}

static void test_sizeof_select(void) {
    printf("\nsizeofSelect is 3 -- PCRs 0..23, a PC Client TPM\n");

    TPMS_PCR_SELECTION bitmap = {0};
    uint8_t sel[] = {0};
    charra_tpm2_pcr_selection_to_bitmap(sizeof(sel), sel, &bitmap);

    check("three bytes of selection", bitmap.sizeofSelect == 3);
    /* Restating the constant the code derives it from, so that changing
     * TPM2_MAX_PCRS in a header upgrade fails here rather than silently
     * producing a selection the TPM refuses. */
    check("which is TPM2_PCR_SELECT_MAX - 1",
            bitmap.sizeofSelect == TPM2_PCR_SELECT_MAX - 1);
    check("covering exactly the encodable range",
            (uint32_t)bitmap.sizeofSelect * 8 == ENCODABLE_PCRS);
}

/* Regression: this used to log an error and fall through, returning
 * SUCCESS with the offending PCR silently absent from the wire. */
static void test_unencodable_pcr_rejected(void) {
    printf("\na PCR index that cannot be encoded is REJECTED\n");

    for (uint32_t pcr = ENCODABLE_PCRS; pcr < TPM2_MAX_PCRS; ++pcr) {
        TPMS_PCR_SELECTION bitmap = {0};
        uint8_t sel[1] = {(uint8_t)pcr};
        if (charra_tpm2_pcr_selection_to_bitmap(1, sel, &bitmap) !=
                CHARRA_RC_BAD_ARGUMENT) {
            printf("        (PCR %u was not rejected)\n", pcr);
            check("PCRs 24..31 are rejected", false);
            return;
        }
    }
    check("PCRs 24..31 are rejected", true);

    /* And one bad index poisons the whole selection -- a caller asking for
     * {10, 25} must not receive a bitmap holding only PCR 10. */
    TPMS_PCR_SELECTION mixed = {0};
    uint8_t sel[] = {10, 25};
    check("one bad index rejects the whole selection",
            charra_tpm2_pcr_selection_to_bitmap(sizeof(sel), sel, &mixed) ==
                    CHARRA_RC_BAD_ARGUMENT);
}

static void test_bad_arguments(void) {
    printf("\nbad arguments\n");

    TPMS_PCR_SELECTION bitmap = {0};
    uint8_t sel[] = {0, 1};

    check("NULL selection rejected",
            charra_tpm2_pcr_selection_to_bitmap(1, NULL, &bitmap) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("an over-long selection is rejected",
            charra_tpm2_pcr_selection_to_bitmap(
                    ENCODABLE_PCRS + 1, sel, &bitmap) ==
                    CHARRA_RC_BAD_ARGUMENT);

    /* Zero-length is legitimate: a quote over no PCRs. It must produce an
     * empty bitmap rather than an error or stale bits. */
    TPMS_PCR_SELECTION empty = {0};
    memset(empty.pcrSelect, 0xff, sizeof(empty.pcrSelect));
    check("an empty selection succeeds",
            charra_tpm2_pcr_selection_to_bitmap(0, sel, &empty) ==
                    CHARRA_RC_SUCCESS);
    bool cleared = true;
    for (uint32_t i = 0; i < empty.sizeofSelect; ++i) {
        cleared = cleared && empty.pcrSelect[i] == 0;
    }
    check("and clears every selection byte it owns", cleared);
}

int main(void) {
    printf("PCR selection tests\n");
    printf("===================\n");

    test_single_pcr();
    test_multiple_pcrs();
    test_sizeof_select();
    test_unencodable_pcr_rejected();
    test_bad_arguments();

    printf("\n===================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
