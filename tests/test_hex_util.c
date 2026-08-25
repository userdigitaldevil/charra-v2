/**
 * @file test_hex_util.c
 * @brief Tests for hex_util.h -- encoding, truncating encoding, decoding.
 *
 * Small module, but it formats every key fingerprint and nonce that
 * appears in a log, and charra_hex_encode_prefix() is the one that writes
 * into fixed-size stack buffers. Truncation behaviour is therefore the
 * part worth pinning: an off-by-one here is a stack overwrite, not a
 * cosmetic bug.
 *
 * Build and run:  make test_hex_util && ./bin/test_hex_util
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../src/util/hex_util.h"

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

static void test_encode(void) {
    printf("\ncharra_hex_encode: lowercase, NUL-terminated, full width\n");

    const uint8_t data[] = {0x00, 0x0f, 0xa5, 0xff};
    char out[sizeof(data) * 2 + 1];
    memset(out, 'X', sizeof(out));
    charra_hex_encode(data, sizeof(data), out);

    check("encodes every byte as two chars", strcmp(out, "000fa5ff") == 0);
    check("NUL-terminates", out[sizeof(data) * 2] == '\0');

    /* Lowercase specifically: log lines are grepped, and mixing cases
     * across call sites would break a naive search. */
    const uint8_t high[] = {0xab, 0xcd, 0xef};
    char hout[7] = {0};
    charra_hex_encode(high, sizeof(high), hout);
    check("uses lowercase a-f", strcmp(hout, "abcdef") == 0);

    /* Zero length is a legitimate input -- an absent nonce logs as "". */
    char empty[1] = {'X'};
    charra_hex_encode(data, 0, empty);
    check("zero length yields the empty string", empty[0] == '\0');
}

static void test_encode_prefix_truncates(void) {
    printf("\ncharra_hex_encode_prefix: truncates, never overflows\n");

    const uint8_t data[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

    /* The live call sites use char[17] for a 32-byte field, so the
     * overwhelmingly common case is "far too small". */
    char small[5] = {0};
    charra_hex_encode_prefix(data, sizeof(data), small, sizeof(small));
    check("fills the buffer to capacity minus the NUL",
            strlen(small) == sizeof(small) - 1);
    check("emits the leading bytes in order", strcmp(small, "1122") == 0);
    check("still NUL-terminates", small[sizeof(small) - 1] == '\0');

    /* Guard bytes on both sides: a one-past-the-end write is the failure
     * this function exists to avoid. */
    struct {
        char guard_before[4];
        char buf[5];
        char guard_after[4];
    } framed;
    memset(&framed, '#', sizeof(framed));
    charra_hex_encode_prefix(
            data, sizeof(data), framed.buf, sizeof(framed.buf));
    check("writes nothing before the buffer",
            memcmp(framed.guard_before, "####", 4) == 0);
    check("writes nothing past the buffer",
            memcmp(framed.guard_after, "####", 4) == 0);

    /* An odd capacity cannot hold a whole byte pair; it must not emit half
     * a byte and it must not run over. */
    char odd[4] = {0};
    charra_hex_encode_prefix(data, sizeof(data), odd, sizeof(odd));
    check("an odd capacity stays in bounds", strlen(odd) <= sizeof(odd) - 1);

    /* Exactly-fits and larger-than-needed both produce the full string. */
    char exact[sizeof(data) * 2 + 1] = {0};
    charra_hex_encode_prefix(data, sizeof(data), exact, sizeof(exact));
    check("an exactly-sized buffer holds the whole encoding",
            strcmp(exact, "1122334455667788") == 0);

    char roomy[64] = {0};
    charra_hex_encode_prefix(data, sizeof(data), roomy, sizeof(roomy));
    check("an oversized buffer does not pad",
            strcmp(roomy, "1122334455667788") == 0);

    /* Degenerate capacities: 1 leaves room for the NUL only, 0 for
     * nothing at all. Neither may write out of bounds. */
    char one[2] = {'X', 'Y'};
    charra_hex_encode_prefix(data, sizeof(data), one, 1);
    check("capacity 1 yields the empty string", one[0] == '\0');
    check("capacity 1 touches nothing else", one[1] == 'Y');

    char none[2] = {'X', 'Y'};
    charra_hex_encode_prefix(data, sizeof(data), none, 0);
    check("capacity 0 writes nothing at all",
            none[0] == 'X' && none[1] == 'Y');
}

static void test_decode(void) {
    printf("\ncharra_hex_decode: exact length, hex only\n");

    uint8_t out[4] = {0};
    check("decodes a well-formed string",
            charra_hex_decode("000fa5ff", sizeof(out), out));
    const uint8_t expected[] = {0x00, 0x0f, 0xa5, 0xff};
    check("produces the right bytes",
            memcmp(out, expected, sizeof(out)) == 0);

    /* Round-trip, which is the property the two functions owe each
     * other. */
    const uint8_t original[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f};
    char encoded[sizeof(original) * 2 + 1] = {0};
    uint8_t decoded[sizeof(original)] = {0};
    charra_hex_encode(original, sizeof(original), encoded);
    check("encode then decode is the identity",
            charra_hex_decode(encoded, sizeof(original), decoded) &&
                    memcmp(original, decoded, sizeof(original)) == 0);

    /* Uppercase is not what we emit, but rejecting it would surprise
     * anyone hand-editing a hash file. Pin whichever way it behaves so a
     * change is deliberate. */
    uint8_t upper[2] = {0};
    bool upper_ok = charra_hex_decode("ABcd", sizeof(upper), upper);
    check("uppercase input is accepted",
            upper_ok && upper[0] == 0xab && upper[1] == 0xcd);
}

static void test_decode_rejects_bad_input(void) {
    printf("\ncharra_hex_decode: rejects what is not exactly hex\n");

    uint8_t out[4] = {0};
    check("a short string is rejected",
            !charra_hex_decode("00ff", sizeof(out), out));
    check("an empty string is rejected for a non-zero length",
            !charra_hex_decode("", sizeof(out), out));
    check("a non-hex character is rejected",
            !charra_hex_decode("00ffzz11", sizeof(out), out));
    check("whitespace is rejected",
            !charra_hex_decode("00ff 011", sizeof(out), out));
    check("a lone odd character is rejected",
            !charra_hex_decode("0", 1, out));

    /* A trailing byte beyond byte_len*2 is simply not read -- decoding is
     * defined by the requested length, not by the string's end. */
    uint8_t two[2] = {0};
    check("trailing characters past byte_len are ignored",
            charra_hex_decode("aabbccdd", sizeof(two), two) &&
                    two[0] == 0xaa && two[1] == 0xbb);
}

int main(void) {
    printf("hex_util tests\n");
    printf("==============\n");

    test_encode();
    test_encode_prefix_truncates();
    test_decode();
    test_decode_rejects_bad_input();

    printf("\n==============\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
