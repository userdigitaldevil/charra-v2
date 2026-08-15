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

typedef struct verifier_info {
    char* ip_address;
    unsigned int port_number;
} verifier_info;

static void coap_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

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

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 request, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        //goto cleanup;
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received data of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received data of total length %zu.",
                data_total_len);
    }

    /* Save the received verifier list */
    int verifier_list[data_total_len / sizeof(int)];
    memcpy(verifier_list, data, data_total_len);

    /* Read verifier information from the configuration file */
    const char* config_filename = "./verifiers_config.txt";
    verifier_info verifier_infos[data_total_len / sizeof(int)];
    size_t verifier_count = 0;

    for (size_t i = 0; i < data_total_len / sizeof(int); i++) {
        if (read_verifier_config(config_filename, verifier_list[i], &verifier_infos[verifier_count]) == 0) {
            charra_log_info("[" LOG_NAME "] Found Verifier ID %d: %s:%u", verifier_list[i], verifier_infos[verifier_count].ip_address, verifier_infos[verifier_count].port_number);
            verifier_count++;
        } else {
            charra_log_error("[" LOG_NAME "] Verifier ID %d not found in configuration file.", verifier_list[i]);
        }
    }

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
            "[" LOG_NAME
            "] Adding marshaled data to CoAP response PDU and send it.");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    if ((coap_r = coap_add_data_large_response(resource, session, request,
                 response, query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                 response_len, response_data, NULL, NULL)) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
    }

    free(response_data);

cleanup:
    for (size_t i = 0; i < verifier_count; i++) {
        free(verifier_infos[i].ip_address);
    }
    processing_response = false;
}

