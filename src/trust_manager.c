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

#define CHARRA_UNUSED __attribute__((unused))


#define LOG_NAME "trust manager"
static bool quit = false;
static const char LISTEN_ADDRESS[] = "0.0.0.0";
int port = 6000;
bool processing_response = false;

/* Counts /get_verifiers calls this process has served, purely for the log
 * delimiter coap_handler() prints -- one call happens per RP benchmark
 * cycle (relying_party.c's get_verifiers(), called once per num_verifiers
 * value in its 1..N sweep), same cadence as attester.c's /attest, so this
 * gives the same kind of easy-to-scan boundary in a multi-cycle log. */
static unsigned int get_verifiers_request_counter = 0;

typedef struct verifier_info {
    char* ip_address;
    unsigned int port_number;
} verifier_info;

static void coap_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

/**
 * @brief Logs the requesting peer's address:port for a CoAP handler --
 * same helper attester.c/verifier.c already added for the same reason.
 */
static void log_peer_address(
        const char* endpoint_name, struct coap_session_t* session) {
    const coap_address_t* remote = coap_session_get_addr_remote(session);
    if (remote == NULL) {
        return;
    }
    unsigned char addr_buf[64] = {0};
    size_t addr_len = coap_print_addr(remote, addr_buf, sizeof(addr_buf) - 1);
    addr_buf[addr_len] = '\0';
    charra_log_info("[" LOG_NAME "] %s: request from %s.", endpoint_name,
            (const char*)addr_buf);
}

int main(int argc CHARRA_UNUSED, char** argv CHARRA_UNUSED) {
      
    coap_context_t* coap_context = NULL;
    coap_endpoint_t* coap_endpoint = NULL;

    charra_log_info(
            "[" LOG_NAME "] Effective configuration: port=%d", port);

    charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        goto error;
    }

    charra_log_info("[" LOG_NAME "] Creating CoAP server endpoint using UDP.");
    if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
                    LISTEN_ADDRESS, port, COAP_PROTO_UDP)) == NULL) {
        charra_log_error("[" LOG_NAME"] Cannot create CoAP server endpoint based on UDP.\n");
        goto error;
    }

    /* register CoAP resource and resource handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "get_verifiers", coap_handler);

    /* enter main loop */
    charra_log_info("[" LOG_NAME "] Entering main loop.");
    while (!quit) {
        /* process CoAP I/O */
        if (coap_io_process(coap_context, COAP_IO_WAIT) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            goto error;
        }
    }

    goto finish;

error:

finish:
    /* free CoAP memory */
    charra_free_and_null_ex(coap_endpoint, coap_free_endpoint);
    charra_free_and_null_ex(coap_context, coap_free_context);
    coap_cleanup();

}

static int read_verifier_config(const char* filename, int verifier_id, verifier_info* info) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot open configuration file.");
        return -1;
    }

    int id;
    char ip[16];
    unsigned int port;
    while (fscanf(file, "%d %15s %u", &id, ip, &port) != EOF) {
        if (id == verifier_id) {
            info->ip_address = strdup(ip);
            info->port_number = port;
            fclose(file);
            return 0;
        }
    }

    fclose(file);
    return -1;
}

static void coap_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {

    processing_response = true;
    int coap_r = 0;

    /* Clear delimiter between benchmark cycles -- see
     * get_verifiers_request_counter's own comment. */
    get_verifiers_request_counter++;
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME "] Starting /get_verifiers request #%u.",
            get_verifiers_request_counter);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    log_peer_address("/get_verifiers", session);

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 request, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
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
        processing_response = false;
        return;
    }
    charra_log_info(
            "[" LOG_NAME "] Received request of %zu byte(s) (%zu byte(s) "
            "total).",
            data_len, data_total_len);

    if (data_total_len % sizeof(int) != 0) {
        charra_log_error(
                "[" LOG_NAME "] Request length %zu is not a whole number "
                "of verifier IDs (%zu-byte int) -- rejecting instead of "
                "silently truncating.",
                data_total_len, sizeof(int));
        processing_response = false;
        return;
    }
    const size_t requested_count = data_total_len / sizeof(int);

    /* Save the received verifier list */
    int verifier_list[requested_count];
    memcpy(verifier_list, data, data_total_len);

    {
        char id_list[256] = {0};
        size_t pos = 0;
        for (size_t i = 0; i < requested_count && pos < sizeof(id_list); ++i) {
            int written = snprintf(id_list + pos, sizeof(id_list) - pos,
                    "%s%d", (i == 0) ? "" : ",", verifier_list[i]);
            if (written < 0) {
                break;
            }
            pos += (size_t)written;
        }
        charra_log_info(
                "[" LOG_NAME "] Requested %zu Verifier ID(s): [%s].",
                requested_count, id_list);
    }

    /* Read verifier information from the configuration file */
    const char* config_filename = "./verifiers_config.txt";
    charra_log_info(
            "[" LOG_NAME "] Looking up Verifier(s) in '%s'.", config_filename);
    verifier_info verifier_infos[requested_count];
    size_t verifier_count = 0;

    for (size_t i = 0; i < requested_count; i++) {
        if (read_verifier_config(config_filename, verifier_list[i], &verifier_infos[verifier_count]) == 0) {
            charra_log_info("[" LOG_NAME "] Found Verifier ID %d: %s:%u", verifier_list[i], verifier_infos[verifier_count].ip_address, verifier_infos[verifier_count].port_number);
            verifier_count++;
        } else {
            charra_log_error("[" LOG_NAME "] Verifier ID %d not found in configuration file.", verifier_list[i]);
        }
    }
    charra_log_info(
            "[" LOG_NAME "] Lookup summary: %zu requested, %zu found, %zu "
            "missing.",
            requested_count, verifier_count, requested_count - verifier_count);

    /* Send verifier information as a response */
    size_t response_len = verifier_count * (sizeof(verifier_info) - sizeof(char*) + 16 + sizeof(unsigned int));
    uint8_t* response_data = malloc(response_len);
    if (response_data == NULL) {
        charra_log_error("[" LOG_NAME "] Could not allocate memory for response data.");
        goto cleanup;
    }

    uint8_t* ptr = response_data;
    for (size_t i = 0; i < verifier_count; i++) {
        strcpy((char*)ptr, verifier_infos[i].ip_address);
        ptr += 16;
        memcpy(ptr, &verifier_infos[i].port_number, sizeof(unsigned int));
        ptr += sizeof(unsigned int);
    }
    charra_log_info(
            "[" LOG_NAME "] Response is %zu byte(s) for %zu Verifier(s).",
            response_len, verifier_count);

    charra_log_info(
            "[" LOG_NAME
            "] Adding marshaled data to CoAP response PDU and send it.");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    bool send_ok = true;
    if ((coap_r = coap_add_data_large_response(resource, session, request,
                 response, query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                 response_len, response_data, NULL, NULL)) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
        send_ok = false;
    }

    free(response_data);

    charra_log_info("[" LOG_NAME "] +----------------------------+");
    if (send_ok && verifier_count == requested_count) {
        charra_log_info("[" LOG_NAME "] |   REQUEST SUCCESSFUL       |");
    } else if (send_ok) {
        charra_log_info("[" LOG_NAME "] |  PARTIAL: SOME IDs MISSING |");
    } else {
        charra_log_info("[" LOG_NAME "] |   REQUEST FAILED           |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");

cleanup:
    for (size_t i = 0; i < verifier_count; i++) {
        free(verifier_infos[i].ip_address);
    }
    processing_response = false;
}

