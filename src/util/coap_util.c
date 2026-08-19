/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file coap_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "coap_util.h"

#include <arpa/inet.h>
#include <coap3/coap.h>
#include <stdbool.h>
#include <string.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../util/io_util.h"

#define LOG_NAME "coap-util"

static const char* const coap_level_names[10] = {
        [LOG_EMERG] = "EMERG",
        [LOG_ALERT] = "ALERT",
        [LOG_CRIT] = "CRIT",
        [LOG_ERR] = "ERR",
        [LOG_WARNING] = "WARNING",
        [LOG_NOTICE] = "NOTICE",
        [LOG_INFO] = "INFO",
        [LOG_DEBUG] = "DEBUG",
        [COAP_LOG_CIPHERS] = "CIPHERS",
};

/* --- function forward declarations -------------------------------------- */

static int verify_rpk_peer_callback(const char* cn,
        const uint8_t* asn1_public_cert, size_t asn1_length,
        coap_session_t* session, unsigned depth, int validated, void* arg);

/* --- function definitions ----------------------------------------------- */

coap_context_t* charra_coap_new_context(const bool enable_coap_block_mode) {
    /* startup */
    coap_startup();

    /* create new context */
    coap_context_t* coap_context = NULL;
    if ((coap_context = coap_new_context(NULL)) != NULL) {
        if (enable_coap_block_mode) {
            /* enable block handling by libcoap */
            coap_context_set_block_mode(coap_context,
                    COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
        }
    }

    return coap_context;
}

coap_endpoint_t* charra_coap_new_endpoint(coap_context_t* coap_context,
        const char* listen_address, const uint16_t port,
        const coap_proto_t coap_protocol) {
    /* prepare address */
    coap_address_t addr = {0};
    coap_address_init(&addr);
    addr.addr.sin.sin_family = AF_INET;
    inet_pton(AF_INET, listen_address, &addr.addr.sin.sin_addr);
    addr.addr.sin.sin_port = htons(port);

    /* create endpoint */
    return coap_new_endpoint(coap_context, &addr, coap_protocol);
}

coap_session_t* charra_coap_new_client_session(coap_context_t* coap_context,
        const char* dest_address, const uint16_t port,
        const coap_proto_t coap_protocol) {
    /* prepare address */
    coap_address_t addr = {0};
    coap_address_init(&addr);
    addr.addr.sin.sin_family = AF_INET;
    inet_pton(AF_INET, dest_address, &addr.addr.sin.sin_addr);
    addr.addr.sin.sin_port = htons(port);

    /* create session */
    return coap_new_client_session(coap_context, NULL, &addr, coap_protocol);
}

coap_session_t* charra_coap_new_client_session_psk(coap_context_t* coap_context,
        const char* dest_address, const uint16_t port,
        const coap_proto_t coap_protocol, const char* identity,
        const uint8_t* key, unsigned key_length) {
    /* prepare address */
    coap_address_t addr = {0};
    coap_address_init(&addr);
    addr.addr.sin.sin_family = AF_INET;
    inet_pton(AF_INET, dest_address, &addr.addr.sin.sin_addr);
    addr.addr.sin.sin_port = htons(port);

    /* create session */
    return coap_new_client_session_psk(coap_context, NULL, &addr, coap_protocol,
            identity, key, key_length);
}

coap_session_t* charra_coap_new_client_session_pki(coap_context_t* coap_context,
        const char* dest_address, const uint16_t port,
        const coap_proto_t coap_protocol, coap_dtls_pki_t* dtls_pki) {
    /* prepare address */
    coap_address_t addr = {0};
    coap_address_init(&addr);
    addr.addr.sin.sin_family = AF_INET;
    inet_pton(AF_INET, dest_address, &addr.addr.sin.sin_addr);
    addr.addr.sin.sin_port = htons(port);

    /* create session */
    return coap_new_client_session_pki(
            coap_context, NULL, &addr, coap_protocol, dtls_pki);
}

coap_pdu_t* charra_coap_new_request(coap_session_t* session,
        coap_message_t msg_type, coap_request_t method,
        coap_optlist_t** options, const uint8_t* data, const size_t data_len) {
    coap_pdu_t* pdu = NULL;

    /* create new PDU */
    if ((pdu = coap_new_pdu(msg_type, method, session)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create PDU");
        goto error;
    }

    /* generate new message ID */
    coap_message_id_t msg_id = coap_new_message_id(session);

    /* set up PDU */
    coap_pdu_set_mid(pdu, msg_id);

    /* generate new token */
    static unsigned char _token_data[24]; /* With support for RFC8974 */
    coap_binary_t the_token = { 0, _token_data };

    uint8_t token[8];
    size_t tokenlen;

    /* add token to PDU */
    if (the_token.length > COAP_TOKEN_DEFAULT_MAX) {
        coap_session_new_token(session, &tokenlen, token);
        /* Update the last part 8 bytes of the large token */
        memcpy(&the_token.s[the_token.length - tokenlen], token, tokenlen);
    } else {
        coap_session_new_token(session, &the_token.length, the_token.s);
    }
    if (!coap_add_token(pdu, the_token.length, the_token.s)) {
        charra_log_error("[" LOG_NAME "] cannot add token to request");
        goto error;
    }

    /* add options to PDU */
    if (options != NULL) {
        if (coap_add_optlist_pdu(pdu, options) == 0) {
            charra_log_error("[" LOG_NAME "] Cannot add options to request");
            goto error;
        }
    }

    /* add (large) data to PDU */
    if (data_len > 0) {
        /* let the underlying libcoap decide how this data should be sent */
        if (coap_add_data_large_request(
                    session, pdu, data_len, data, NULL, NULL) == 0) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot add (large) data option list to request");
            goto error;
        }
    }

    return pdu;

error:
    /* cleanup */
    if (pdu != NULL) {
        coap_delete_pdu(pdu);
        // coap_free_type(COAP_PDU, pdu);
    }

    return NULL;
}

void charra_coap_add_resource(struct coap_context_t* coap_context,
        const coap_request_t method, const char* resource_name,
        const coap_method_handler_t handler) {
    // charra_log_info("[" LOG_NAME "] Adding CoAP %s resource '%s'.",
    //         charra_coap_method_to_str(method), resource_name);

    coap_str_const_t* resource_uri = coap_new_str_const(
            (uint8_t const*)resource_name, strlen(resource_name));
    coap_resource_t* resource =
            coap_resource_init(resource_uri, COAP_RESOURCE_FLAGS_RELEASE_URI);
    coap_register_handler(resource, method, handler);
    coap_add_resource(coap_context, resource);
}

CHARRA_RC charra_coap_setup_dtls_pki_for_rpk(coap_dtls_pki_t* dtls_pki,
        char* private_key_path, char* public_key_path,
        char* peer_public_key_path, bool verify_peer_public_key) {
    // read public key file
    char* public_key_file = NULL;
    size_t public_key_file_length = 0;
    CHARRA_RC rc = charra_io_read_file(
            public_key_path, &public_key_file, &public_key_file_length);
    if (rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Cannot read file at path '%s'",
                public_key_path);
        return rc;
    }

    // read private key file
    char* private_key_file = NULL;
    size_t private_key_file_length = 0;
    rc = charra_io_read_file(
            private_key_path, &private_key_file, &private_key_file_length);
    if (rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Cannot read file at path '%s'",
                private_key_path);
        return rc;
    }

    // DTLS setup for PKI / RPK (raw public keys)
    dtls_pki->version = COAP_DTLS_PKI_SETUP_VERSION;
    dtls_pki->verify_peer_cert = 1;  // not documented to be ignored when RPK is
                                     // used, but seems like it is?
    dtls_pki->check_common_ca = 0;   // ignored when RPK is used
    dtls_pki->allow_self_signed = 0;        // ignored when RPK is used
    dtls_pki->allow_expired_certs = 0;      // ignored when RPK is used
    dtls_pki->cert_chain_validation = 0;    // ignored when RPK is used
    dtls_pki->cert_chain_verify_depth = 0;  // ignored when RPK is used
    dtls_pki->check_cert_revocation = 0;    // ignored when RPK is used
    dtls_pki->allow_no_crl = 0;             // ignored when RPK is used
    dtls_pki->allow_expired_crl = 0;        // ignored when RPK is used
    dtls_pki->allow_bad_md_hash = 0;        // ignored when RPK is used
    dtls_pki->allow_short_rsa_length = 0;   // ignored when RPK is used
    dtls_pki->is_rpk_not_cert = 1;          // use RPK instead of PKI
    dtls_pki->validate_cn_call_back =
            verify_peer_public_key ? verify_rpk_peer_callback : NULL;
    dtls_pki->cn_call_back_arg = (void*)peer_public_key_path;
    dtls_pki->validate_sni_call_back = NULL;
    dtls_pki->sni_call_back_arg = NULL;
    dtls_pki->additional_tls_setup_call_back = NULL;
    dtls_pki->client_sni = NULL;
    dtls_pki->pki_key.key_type = COAP_PKI_KEY_ASN1;
    dtls_pki->pki_key.key.asn1.ca_cert = NULL;
    dtls_pki->pki_key.key.asn1.ca_cert_len = 0;
    dtls_pki->pki_key.key.asn1.public_cert = (uint8_t*)public_key_file;
    dtls_pki->pki_key.key.asn1.public_cert_len = public_key_file_length;
    dtls_pki->pki_key.key.asn1.private_key = (uint8_t*)private_key_file;
    dtls_pki->pki_key.key.asn1.private_key_len = private_key_file_length;
    dtls_pki->pki_key.key.asn1.private_key_type = COAP_ASN1_PKEY_EC;

    return CHARRA_RC_SUCCESS;
}

int charra_coap_log_level_from_str(
        const char* log_level_str, coap_log_t* log_level) {
    if (log_level_str != NULL) {
        int array_size = sizeof(coap_level_names) / sizeof(coap_level_names[0]);
        for (int i = 0; i < array_size; i++) {
            const char* name = coap_level_names[i];
            if (name == NULL) {
                continue;
            }
            if (strcmp(name, log_level_str) == 0) {
                *log_level = i;
                return 0;
            }
        }
        return -1;
    }

    return -1;
}

const char* charra_coap_method_to_str(const coap_request_t method) {
    switch (method) {
    case COAP_REQUEST_GET:
        return "GET";
    case COAP_REQUEST_POST:
        return "POST";
    case COAP_REQUEST_PUT:
        return "PUT";
    case COAP_REQUEST_DELETE:
        return "DELETE";
    case COAP_REQUEST_FETCH:
        return "FETCH";
    case COAP_REQUEST_PATCH:
        return "PATCH";
    case COAP_REQUEST_IPATCH:
        return "IPATCH";
    default:
        return "UNKNOWN";
    }
}

/**
 * Peer Validation callback that can be set up by coap_context_set_pki().
 * Invoked when libcoap has done the validation checks at the TLS level,
 * but the application needs to check that the CN (for PKI) or public key
 * (for RPK) is allowed. Currently in out case only RPK is used.
 *
 * @param cn  A string containing "RPK", for PKI the common name
 * @param asn1_public_cert  ASN.1 encoded (DER) public key, for PKI the X.509
 * certificate
 * @param asn1_length  The ASN.1 length
 * @param session  The coap session associated with the certificate update
 * @param depth  for PKI: Depth in cert chain.  If 0, then client cert, else a
 * CA
 * @param validated  TLS can find no issues if 1
 * @param arg  The same as was passed into coap_context_set_pki()
 *             in setup_data->cn_call_back_arg, in this case the path of the
 *             peers' public key
 *
 * @return 1 if accepted, else 0 if to be rejected
 */
static int verify_rpk_peer_callback(const char* cn,
        const uint8_t* asn1_public_cert, size_t asn1_length,
        coap_session_t* session CHARRA_UNUSED, unsigned depth CHARRA_UNUSED,
        int validated, void* arg) {
    charra_log_info("[" LOG_NAME "] Checking peers public key for equivalence "
                    "against peers' known public key.");
    if (strcmp("RPK", cn) == 0 && validated == 1) {
        char* reference = NULL;
        size_t reference_length = 0;
        CHARRA_RC rc =
                charra_io_read_file((char*)arg, &reference, &reference_length);
        if (rc == CHARRA_RC_SUCCESS) {
            if (reference_length == asn1_length) {
                if (memcmp(reference, asn1_public_cert, reference_length) ==
                        0) {
                    return 1;
                }
            }
            charra_log_error("[" LOG_NAME
                             "] DTLS-RPK: The public key of the peer could not "
                             "be verified with the reference key at path '%s'.",
                    (char*)arg);
            charra_print_hex(CHARRA_LOG_DEBUG, reference_length,
                    (uint8_t*)reference, "Reference public key of peer: ", "\n",
                    false);
            charra_print_hex(CHARRA_LOG_DEBUG, asn1_length, asn1_public_cert,
                    "Actual public key of peer: ", "\n", false);
            return 0;
        }
        charra_log_error("[" LOG_NAME "] DTLS-RPK: The reference key of the "
                         "peer at path '%s' could not be opened.",
                (char*)arg);
        return 0;
    }
    charra_log_error(
            "[" LOG_NAME
            "] DTLS-RPK: Unexpected error while verifying peers' public key");
    return 0;
}

void charra_coap_log_peer_address(const char* log_name,
        const char* endpoint_name, struct coap_session_t* session) {
    const coap_address_t* remote = coap_session_get_addr_remote(session);
    if (remote == NULL) {
        return;
    }
    unsigned char addr_buf[64] = {0};
    size_t addr_len = coap_print_addr(remote, addr_buf, sizeof(addr_buf) - 1);
    addr_buf[addr_len] = '\0';
    charra_log_info(
            "[%s] %s: request from %s.", log_name, endpoint_name, addr_buf);
}

/* --- server lifecycle ---------------------------------------------------- */

void charra_coap_server_log_config(const charra_coap_server_config* config) {
    charra_log_debug("[%s]     Used local port: %d", config->log_name,
            config->port);
    charra_log_debug("[%s]     DTLS-PSK enabled: %s", config->log_name,
            config->use_dtls_psk ? "true" : "false");
    if (config->use_dtls_psk) {
        charra_log_debug("[%s]         Pre-shared key: '%s'",
                config->log_name, config->dtls_psk_key);
        charra_log_debug(
                "[%s]         Hint: '%s'", config->log_name,
                config->dtls_psk_hint);
    }
    charra_log_debug("[%s]     DTLS-RPK enabled: %s", config->log_name,
            config->use_dtls_rpk ? "true" : "false");
    if (config->use_dtls_rpk) {
        charra_log_debug("[%s]         Private key path: '%s'",
                config->log_name, config->dtls_rpk_private_key_path);
        charra_log_debug("[%s]         Public key path: '%s'",
                config->log_name, config->dtls_rpk_public_key_path);
        charra_log_debug("[%s]         Peers' public key path: '%s'",
                config->log_name, config->dtls_rpk_peer_public_key_path);
    }
}

CHARRA_RC charra_coap_server_start(const charra_coap_server_config* config,
        coap_context_t** context_out, coap_endpoint_t** endpoint_out) {
    if (config == NULL || context_out == NULL || endpoint_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *context_out = NULL;
    *endpoint_out = NULL;

    if (config->use_dtls_psk && config->use_dtls_rpk) {
        charra_log_error("[%s] Configuration enables both DTSL with PSK and "
                         "DTSL with PKI. Aborting!",
                config->log_name);
        return CHARRA_RC_ERROR;
    }
    if (config->use_dtls_psk || config->use_dtls_rpk) {
        coap_show_tls_version(LOG_DEBUG); /* debug builds only */
        if (!coap_dtls_is_supported()) {
            charra_log_error("[%s] CoAP does not support DTLS but the "
                             "configuration enables DTLS. Aborting!",
                    config->log_name);
            return CHARRA_RC_ERROR;
        }
    }

    charra_log_info(
            "[%s] Initializing CoAP in block-wise mode.", config->log_name);
    coap_context_t* context = charra_coap_new_context(true);
    if (context == NULL) {
        charra_log_error("[%s] Cannot create CoAP context.", config->log_name);
        return CHARRA_RC_ERROR;
    }

    coap_endpoint_t* endpoint = NULL;
    if (config->use_dtls_psk) {
        charra_log_info("[%s] Creating CoAP server endpoint using DTLS-PSK.",
                config->log_name);
        if (!coap_context_set_psk(context, config->dtls_psk_hint,
                    (const uint8_t*)config->dtls_psk_key,
                    strlen(config->dtls_psk_key))) {
            charra_log_error(
                    "[%s] Error while configuring CoAP to use DTLS-PSK.",
                    config->log_name);
            goto error;
        }
        endpoint = charra_coap_new_endpoint(context, config->listen_address,
                config->port, COAP_PROTO_DTLS);
        if (endpoint == NULL) {
            charra_log_error("[%s] Cannot create CoAP server endpoint based "
                             "on DTLS-PSK.",
                    config->log_name);
            goto error;
        }
    } else if (config->use_dtls_rpk) {
        charra_log_info("[%s] Creating CoAP server endpoint using DTLS-RPK.",
                config->log_name);
        coap_dtls_pki_t dtls_pki = {0};
        if (charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                    config->dtls_rpk_private_key_path,
                    config->dtls_rpk_public_key_path,
                    config->dtls_rpk_peer_public_key_path,
                    config->dtls_rpk_verify_peer_public_key) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[%s] Error while setting up DTLS-RPK structure.",
                    config->log_name);
            goto error;
        }
        if (!coap_context_set_pki(context, &dtls_pki)) {
            charra_log_error(
                    "[%s] Error while configuring CoAP to use DTLS-RPK.",
                    config->log_name);
            goto error;
        }
        endpoint = charra_coap_new_endpoint(context, config->listen_address,
                config->port, COAP_PROTO_DTLS);
        if (endpoint == NULL) {
            charra_log_error("[%s] Cannot create CoAP server endpoint based "
                             "on DTLS-RPK.",
                    config->log_name);
            goto error;
        }
    } else {
        charra_log_info("[%s] Creating CoAP server endpoint using UDP.",
                config->log_name);
        endpoint = charra_coap_new_endpoint(context, config->listen_address,
                config->port, COAP_PROTO_UDP);
        if (endpoint == NULL) {
            charra_log_error(
                    "[%s] Cannot create CoAP server endpoint based on UDP.",
                    config->log_name);
            goto error;
        }
    }

    *context_out = context;
    *endpoint_out = endpoint;
    return CHARRA_RC_SUCCESS;

error:
    /* The endpoint is owned by the context once created, so freeing the
     * context is the whole cleanup. */
    coap_free_context(context);
    return CHARRA_RC_ERROR;
}

CHARRA_RC charra_coap_server_run(coap_context_t* context, const char* log_name,
        const volatile bool* quit) {
    if (context == NULL || log_name == NULL || quit == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    charra_log_debug("[%s] Entering main loop.", log_name);
    while (!*quit) {
        if (coap_io_process(context, COAP_IO_WAIT) == -1) {
            charra_log_error(
                    "[%s] Error during CoAP I/O processing.", log_name);
            return CHARRA_RC_ERROR;
        }
    }
    return CHARRA_RC_SUCCESS;
}

void charra_coap_server_stop(
        coap_context_t* context, coap_endpoint_t* endpoint) {
    charra_free_and_null_ex(endpoint, coap_free_endpoint);
    charra_free_and_null_ex(context, coap_free_context);
    coap_cleanup();
}
