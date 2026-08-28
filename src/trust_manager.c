#include <arpa/inet.h>
#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tinydtls/session.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_tcti_mssim.h>
#include <time.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "core/charra_helper.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "util/cbor_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"



#define LOG_NAME "trust manager"

/* Monotonic seconds since an arbitrary epoch. Lets /get_verifiers report its
 * own server-side cost, which the RP's round-trip figure cannot separate from
 * the network. */
static double charra_now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
static volatile sig_atomic_t quit = 0;
static const char LISTEN_ADDRESS[] = "0.0.0.0";
int port = 6000;

/* DTLS. Off unless a flag turns it on, matching the other three roles.
 * Only the RPK peer path differs in kind: the Trust Manager faces exactly
 * one client -- the RP -- so the single rpk_peer_public_key_path fits,
 * unlike the RP which needs one path per peer kind. */
static charra_dtls_config dtls_config = {
        .psk_key = "Charra DTLS Key",
        .psk_hint = "Charra Trust Manager",
        .rpk_private_key_path = "keys/trust_manager.der",
        .rpk_public_key_path = "keys/trust_manager.pub.der",
        .rpk_peer_public_key_path = "keys/relying_party.pub.der",
        .rpk_verify_peer_public_key = true,
};

/* Counts /get_verifiers calls this process has served, purely for the log
 * delimiter coap_handler() prints -- one call happens per RP benchmark
 * cycle (relying_party.c's get_verifiers(), called once per num_verifiers
 * value in its 1..N sweep), same cadence as attester.c's /attest, so this
 * gives the same kind of easy-to-scan boundary in a multi-cycle log. */
static unsigned int get_verifiers_request_counter = 0;

/* Seeded from LOG_LEVEL_CHARRA before parsing, so the environment works the
 * same way here as for every other role, and --log-level still wins. */
charra_log_t charra_log_level = CHARRA_LOG_INFO;

static void coap_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

int main(int argc, char** argv) {
    int result = EXIT_SUCCESS;

    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);

    /* Hand-rolled rather than routed through cli_util.c, for the same
     * reason rp_config.c is: that parser is built around a binary
     * verifier-or-attester split and this role shares almost none of its
     * options. Any unrecognised argument is rejected rather than ignored,
     * so a typo is not silently swallowed by a daemon that runs anyway. */
    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];
        const char* eq = strchr(arg, '=');
        const char* val = eq ? eq + 1 : NULL;
        size_t name_len = eq ? (size_t)(eq - arg) : strlen(arg);
#define TM_OPT(name) (strncmp(arg, (name), name_len) == 0 &&                   \
                      strlen(name) == name_len)

        if (TM_OPT("--help") || TM_OPT("-h")) {
            printf("\nUsage: trust_manager [OPTIONS]\n"
                   "\n"
                   "Resolves Verifier IDs to host:port from "
                   "./verifiers_config.txt\n"
                   "and serves them on /get_verifiers. Opens no TPM.\n"
                   "\n"
                   "     --log-level=LEVEL         TRACE DEBUG INFO WARN "
                   "ERROR FATAL. Default INFO.\n"
                   "     --port=PORT               Listen on PORT instead of "
                   "%d.\n"
                   "\n"
                   "DTLS Options (PSK and RPK are mutually exclusive; every "
                   "role must use the SAME mode):\n"
                   "     --psk                     Enable DTLS-PSK.\n"
                   "     --key=KEY                 Pre-shared key. Implies "
                   "--psk.\n"
                   "     --hint=HINT               PSK hint. Implies --psk.\n"
                   "     --rpk                     Enable DTLS-RPK.\n"
                   "     --private-key=PATH        Default '%s'.\n"
                   "     --public-key=PATH         Default '%s'.\n"
                   "     --peer-public-key=PATH    The RP's key. Default "
                   "'%s'.\n"
                   "     --verify-peer=[0,1]       Default %d.\n"
                   "\n"
                   "     --help, -h                Print this message.\n",
                    port, dtls_config.rpk_private_key_path,
                    dtls_config.rpk_public_key_path,
                    dtls_config.rpk_peer_public_key_path,
                    dtls_config.rpk_verify_peer_public_key ? 1 : 0);
            return EXIT_SUCCESS;
        }
        if (TM_OPT("--psk")) {
            dtls_config.use_psk = true;
        } else if (TM_OPT("--rpk")) {
            dtls_config.use_rpk = true;
        } else if (val == NULL) {
            fprintf(stderr, "\ntrust_manager: '%s' needs a =VALUE, or is "
                            "unrecognised. Try --help.\n",
                    arg);
            return EXIT_FAILURE;
        } else if (TM_OPT("--log-level")) {
            /* Without this the Trust Manager ignored the log level entirely
             * and emitted DEBUG and TRACE while every other role honoured it
             * -- so quietening a run quietened everything except this one. */
            if (charra_log_level_from_str(val, &charra_log_level) != 0) {
                fprintf(stderr,
                        "\ntrust_manager: --log-level must be one of "
                        "TRACE DEBUG INFO WARN ERROR FATAL (got '%s').\n",
                        val);
                return EXIT_FAILURE;
            }
        } else if (TM_OPT("--port")) {
            char* end = NULL;
            long p = strtol(val, &end, 10);
            if (end == val || *end != '\0' || p < 1 || p > 65535) {
                fprintf(stderr, "\ntrust_manager: --port must be 1..65535.\n");
                return EXIT_FAILURE;
            }
            port = (int)p;
        } else if (TM_OPT("--key")) {
            dtls_config.psk_key = (char*)val;
            dtls_config.use_psk = true;
        } else if (TM_OPT("--hint")) {
            dtls_config.psk_hint = (char*)val;
            dtls_config.use_psk = true;
        } else if (TM_OPT("--private-key")) {
            dtls_config.rpk_private_key_path = (char*)val;
            dtls_config.use_rpk = true;
        } else if (TM_OPT("--public-key")) {
            dtls_config.rpk_public_key_path = (char*)val;
            dtls_config.use_rpk = true;
        } else if (TM_OPT("--peer-public-key")) {
            dtls_config.rpk_peer_public_key_path = (char*)val;
            dtls_config.use_rpk = true;
        } else if (TM_OPT("--verify-peer")) {
            if (strcmp(val, "0") != 0 && strcmp(val, "1") != 0) {
                fprintf(stderr,
                        "\ntrust_manager: --verify-peer must be 0 or 1.\n");
                return EXIT_FAILURE;
            }
            dtls_config.rpk_verify_peer_public_key = (strcmp(val, "1") == 0);
        } else {
            fprintf(stderr,
                    "\ntrust_manager: unrecognised option '%s'.\n", arg);
            return EXIT_FAILURE;
        }
#undef TM_OPT
    }

    charra_log_set_level(charra_log_level);

    /* Refused at startup rather than left to charra_coap_server_start(),
     * which would also reject it -- but after the log line below has
     * already claimed a configuration that will not come up. */
    if (dtls_config.use_psk && dtls_config.use_rpk) {
        fprintf(stderr, "\ntrust_manager: --psk and --rpk are mutually "
                        "exclusive; pick one.\n");
        return EXIT_FAILURE;
    }

    coap_context_t* coap_context = NULL;
    coap_endpoint_t* coap_endpoint = NULL;

    charra_log_info("[" LOG_NAME "] Effective configuration: port=%d, "
                    "DTLS=%s",
            port,
            dtls_config.use_psk ? "PSK"
                                : (dtls_config.use_rpk ? "RPK" : "off"));

    charra_coap_server_config server_config = {
        .log_name = LOG_NAME,
        .listen_address = LISTEN_ADDRESS,
        .port = port,
        .use_dtls_psk = dtls_config.use_psk,
        .dtls_psk_key = dtls_config.psk_key,
        .dtls_psk_hint = dtls_config.psk_hint,
        .use_dtls_rpk = dtls_config.use_rpk,
        .dtls_rpk_private_key_path = dtls_config.rpk_private_key_path,
        .dtls_rpk_public_key_path = dtls_config.rpk_public_key_path,
        .dtls_rpk_peer_public_key_path = dtls_config.rpk_peer_public_key_path,
        .dtls_rpk_verify_peer_public_key =
                dtls_config.rpk_verify_peer_public_key,
    };
    if (charra_coap_server_start(&server_config, &coap_context,
                &coap_endpoint) != CHARRA_RC_SUCCESS) {
        goto error;
    }

    /* register CoAP resource and resource handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "get_verifiers", coap_handler);

    if (charra_coap_server_run(coap_context, LOG_NAME, &quit) !=
            CHARRA_RC_SUCCESS) {
        goto error;
    }

    goto finish;

error:
    result = EXIT_FAILURE;

finish:
    charra_coap_server_stop(coap_context, coap_endpoint);

    return result;
}

/**
 * @brief Looks verifier_id up in filename (format: "<id> <ip> <port>" per
 * line), writing straight into a msg_verifier_endpoint_dto slot -- no
 * intermediate heap allocation (strdup) the caller then has to remember to
 * free, unlike the old verifier_info this replaced. "%15s" is sized for
 * CHARRA_VERIFIER_IP_MAXLEN - 1 (room for the NUL fscanf itself adds),
 * matching msg_verifier_endpoint_dto's own ip_address field size.
 *
 * @returns true and fills *out on a match, false if verifier_id is not in
 * the file (or the file can't be opened).
 */
static bool read_verifier_config(
        const char* filename, int verifier_id, msg_verifier_endpoint_dto* out) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot open configuration file.");
        return false;
    }

    int id;
    char ip[CHARRA_VERIFIER_IP_MAXLEN];
    /* Named distinctly from the file-scope "port" (this process's own
     * listen port) -- these are unrelated values (a verifier's config-file
     * port vs. Trust Manager's own) that happened to share a name and
     * shadow each other, which is a readability trap even though it isn't
     * functionally wrong. */
    unsigned int config_port;
    while (fscanf(file, "%d %15s %u", &id, ip, &config_port) != EOF) {
        if (id == verifier_id) {
            snprintf(out->ip_address, sizeof(out->ip_address), "%s", ip);
            out->port_number = config_port;
            fclose(file);
            return true;
        }
    }

    fclose(file);
    return false;
}

static void coap_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {

    int coap_r = 0;
    const double handler_start = charra_now_s();

    /* Clear delimiter between benchmark cycles -- see
     * get_verifiers_request_counter's own comment. */
    get_verifiers_request_counter++;
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME "] Starting /get_verifiers request #%u.",
            get_verifiers_request_counter);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_coap_log_peer_address(LOG_NAME, "/get_verifiers", session);

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_total_len = 0;
    if (!charra_coap_get_payload(request, LOG_NAME, "/get_verifiers", &data,
                &data_len, &data_total_len)) {
        /* Nothing allocated yet at this point (verifier_infos/response_data
         * below don't exist), so a plain return is correct here -- unlike
         * further down, there is nothing for a 'goto cleanup' to free, and
         * jumping over a VLA's own declaration the way the old (dead,
         * commented-out) 'goto cleanup;' here would have done is not
         * actually legal C: a goto may not jump from outside a variably
         * modified identifier's scope to inside it. This used to fall
         * through instead, into memcpy(verifier_list, NULL, 0) below --
         * technically undefined behavior even at a 0 length, and silently
         * masked the original failure. */
        return;
    }
    charra_log_info(
            "[" LOG_NAME "] Received request of %zu byte(s) (%zu byte(s) "
            "total).",
            data_len, data_total_len);

    /* Unmarshal via the same shared, tested CBOR marshal/unmarshal pattern
     * every other endpoint in this codebase uses (charra_marshaling.c) --
     * replaces the hand-packed raw-int-array layout this used to decode
     * manually, with no bounds check tying request length to verifier
     * count, and no shared code with the encoder in relying_party.c that
     * has to agree with it. charra_unmarshal_get_verifiers_request()
     * rejects an oversized/malformed request outright. */
    msg_get_verifiers_request_dto req = {0};
    CHARRA_RC charra_r = charra_unmarshal_get_verifiers_request(
            (uint32_t)data_total_len, data, &req);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not parse CBOR request: CHARRA_RC=%d.",
                charra_r);
        return;
    }

    {
        char id_list[256] = {0};
        size_t pos = 0;
        for (uint32_t i = 0; i < req.verifier_ids_len && pos < sizeof(id_list);
                ++i) {
            int written = snprintf(id_list + pos, sizeof(id_list) - pos,
                    "%s%d", (i == 0) ? "" : ",", req.verifier_ids[i]);
            if (written < 0) {
                break;
            }
            pos += (size_t)written;
        }
        charra_log_info(
                "[" LOG_NAME "] Requested %u Verifier ID(s): [%s].",
                req.verifier_ids_len, id_list);
    }

    /* Read verifier information from the configuration file */
    const char* config_filename = "./verifiers_config.txt";
    charra_log_info(
            "[" LOG_NAME "] Looking up Verifier(s) in '%s'.", config_filename);

    msg_get_verifiers_response_dto resp = {0};
    for (uint32_t i = 0; i < req.verifier_ids_len; i++) {
        msg_verifier_endpoint_dto* slot = &resp.verifiers[resp.verifiers_len];
        if (read_verifier_config(config_filename, req.verifier_ids[i], slot)) {
            charra_log_info("[" LOG_NAME "] Found Verifier ID %d: %s:%u",
                    req.verifier_ids[i], slot->ip_address, slot->port_number);
            resp.verifiers_len++;
        } else {
            charra_log_error(
                    "[" LOG_NAME "] Verifier ID %d not found in "
                    "configuration file.",
                    req.verifier_ids[i]);
        }
    }
    charra_log_info(
            "[" LOG_NAME "] Lookup summary: %u requested, %u found, %u "
            "missing.",
            req.verifier_ids_len, resp.verifiers_len,
            req.verifier_ids_len - resp.verifiers_len);

    /* Marshal the response the same tested way -- the encoder writes
     * exactly what it declares (QCBOREncode_Finish's own length), so the
     * response_len/actual-bytes-written mismatch that used to leak
     * uninitialized heap memory (and make the RP believe more records had
     * arrived than really did) cannot recur here:
     * there is no separate hand-computed size formula to drift out of
     * sync with what the write loop fills. */
    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    charra_r = charra_marshal_get_verifiers_response(
            &resp, &marshaled_len, &marshaled);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal response: CHARRA_RC=%d.",
                charra_r);
        return;
    }
    charra_log_info(
            "[" LOG_NAME "] Response is %u byte(s) for %u Verifier(s).",
            marshaled_len, resp.verifiers_len);

    charra_log_info(
            "[" LOG_NAME
            "] Adding marshaled data to CoAP response PDU and send it.");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    bool send_ok = true;
    if ((coap_r = coap_add_data_large_response(resource, session, request,
                 response, query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                 marshaled_len, marshaled, NULL, NULL)) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
        send_ok = false;
    }
    free(marshaled);

    charra_log_info("[" LOG_NAME "] Timing: /get_verifiers server-side "
                    "handling took %f second(s).",
            charra_now_s() - handler_start);

    charra_log_info("[" LOG_NAME "] +----------------------------+");
    if (send_ok && resp.verifiers_len == req.verifier_ids_len) {
        charra_log_info("[" LOG_NAME "] |   REQUEST SUCCESSFUL       |");
    } else if (send_ok) {
        charra_log_info("[" LOG_NAME "] |  PARTIAL: SOME IDs MISSING |");
    } else {
        charra_log_info("[" LOG_NAME "] |   REQUEST FAILED           |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");
}

