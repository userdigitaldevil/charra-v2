/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file coap_util.h
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

#ifndef COAP_UTIL_H
#define COAP_UTIL_H

#include "../common/charra_error.h"
#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>

/* --- type declarations/definitions -------------------------------------- */

/**
 * @brief CoAP token type.
 *
 */
typedef struct coap_token_t {
    /**
     * @brief (Real) length of the token (max. 8).
     *
     */
    size_t length;

    /**
     * @brief The token (max. 8 bytes)
     *
     */
    uint8_t data[8];
} coap_token_t;

/**
 * @brief CoAP message ID type.
 *
 */
typedef uint16_t coap_message_id_t;

/**
 * @brief CoAP message type.
 *
 */
typedef uint8_t coap_message_t;
/* confirmable message (requires ACK/RST) */
#define COAP_MESSAGE_TYPE_CON ((coap_message_t)COAP_MESSAGE_CON)
/* non-confirmable message (one-shot message) */
#define COAP_MESSAGE_TYPE_NON ((coap_message_t)COAP_MESSAGE_NON)
/* used to acknowledge confirmable messages */
#define COAP_MESSAGE_TYPE_ACK ((coap_message_t)COAP_MESSAGE_ACK)
/* indicates error in received messages */
#define COAP_MESSAGE_TYPE_RST ((coap_message_t)COAP_MESSAGE_RST)

/* --- function forward declarations -------------------------------------- */

/**
 * @brief Creates a new CoAP context.
 *
 * @param[in] enable_coap_block_mode whether to enable CoAP block mode.
 * @return coap_context_t* the Coap context.
 * @return NULL if an error occurred.
 */
coap_context_t* charra_coap_new_context(const bool enable_coap_block_mode);

/**
 * @brief Creates a CoAP server endpoint.
 *
 * @param[inout] coap_context the CoAP context.
 * @param[in] listen_address the IP address to listen on (e.g. "0.0.0.0").
 * @param[in] port the port (default CoAP UDP port is 5683).
 * @param[in] coap_protocol the CoAP protocol.
 * @return coap_endpoint_t* the CoAP endpoint.
 * @return NULL if an error occurred.
 */
coap_endpoint_t* charra_coap_new_endpoint(coap_context_t* coap_context,
        const char* listen_address, const uint16_t port,
        const coap_proto_t coap_protocol);

/**
 * @brief Creates a CoAP client session.
 *
 * @param[inout] coap_context the CoAP context.
 * @param[in] dest_address the destination IP address.
 * @param[in] port the port (default CoAP UDP port is 5683).
 * @param[in] coap_protocol the CoAP protocol.
 * @return coap_session_t* the CoAP session.
 * @return NULL if an error occurred.
 */
coap_session_t* charra_coap_new_client_session(coap_context_t* coap_context,
        const char* dest_address, const uint16_t port,
        const coap_proto_t coap_protocol);

/**
 * @brief Creates a CoAP client session with PSK.
 *
 * @param[inout] coap_context the CoAP context.
 * @param[in] dest_address the destination IP address.
 * @param[in] port the port (default CoAP UDP port is 5683).
 * @param[in] coap_protocol the CoAP protocol.
 * @param[in] identity the identity used for PSK.
 * @param[in] key the pre-shared key.
 * @param[in] key_length the length of the pre-shared key.
 * @return coap_session_t* the CoAP session.
 * @return NULL if an error occurred.
 */
coap_session_t* charra_coap_new_client_session_psk(coap_context_t* coap_context,
        const char* dest_address, const uint16_t port,
        const coap_proto_t coap_protocol, const char* identity,
        const uint8_t* key, unsigned key_length);

/**
 * @brief Creates a CoAP client session with PKI.
 *
 * @param[inout] coap_context the CoAP context.
 * @param[in] dest_address the destination IP address.
 * @param[in] port the port (default CoAP UDP port is 5683).
 * @param[in] coap_protocol the CoAP protocol.
 * @param[in] dtls_pki structure holding configuration data for PKI mode of
 * CoAP.
 * @return coap_session_t* the CoAP session.
 * @return NULL if an error occurred.
 */
coap_session_t* charra_coap_new_client_session_pki(coap_context_t* coap_context,
        const char* dest_address, const uint16_t port,
        const coap_proto_t coap_protocol, coap_dtls_pki_t* dtls_pki);

/**
 * @brief Creates a new CoAP request with large data, using CoAP block-wise
 * transfers.
 *
 * @param session the CoAP session.
 * @param msg_type the CoAP message type.
 * @param method the CoAP request method.
 * @param options list of CoAP options.
 * @param data the data to send (this can be larger than the typical size of
 * 1024 bytes for one PDU since internally CoAP block-wise transfers are
 * used).
 * @param data_len the length of the data.
 * @return coap_pdu_t* the created CoAP PDU.
 * @return NULL in case of an error.
 */
coap_pdu_t* charra_coap_new_request(coap_session_t* session,
        coap_message_t msg_type, coap_request_t method,
        coap_optlist_t** options, const uint8_t* data, const size_t data_len);

/**
 * @brief Adds a CoAP resource.
 *
 * @param coap_context the CoAP context.
 * @param method the CoAP request method.
 * @param resource_name the resource name.
 * @param handler the method handler function.
 */
void charra_coap_add_resource(struct coap_context_t* coap_context,
        const coap_request_t method, const char* resource_name,
        const coap_method_handler_t handler);

/**
 * @brief: Setup the dtls_pki structure for DTLS-RPK.
 *
 * @param dtls_pki the strcture to setup
 * @param private_key_path the path of the private key to use
 * @param public_key_path the path of the public key to use
 * @param peer_public_key_path the path of the peers' public key to use
 * @param verify_peer_public_key true if the structure shall be setup to
 * validate the peers' public key, false otherwise
 */
CHARRA_RC charra_coap_setup_dtls_pki_for_rpk(coap_dtls_pki_t* dtls_pki,
        char* private_key_path, char* public_key_path,
        char* peer_public_key_path, bool verify_peer_public_key);

/**
 * @brief Parses the libcoap log level from string and writes the result into
 * variable log_level. In case of an parsing error nothing is written and the
 * function returns -1.
 *
 * @param[in] log_level_str the libcoap log level string.
 * @param[out] log_level the variable into which the log level is written.
 * @return 0 on success, -1 on error.
 */
int charra_coap_log_level_from_str(
        const char* log_level_str, coap_log_t* log_level);

/**
 * @brief Returns the string representation of a CoAP request method.
 *
 * @param method the CoAP request method.
 * @return const char* the string representation of a CoAP request method.
 */
const char* charra_coap_method_to_str(const coap_request_t method);

/**
 * @brief Logs the requesting peer's address:port for a CoAP handler, so a
 * round's log lines can be tied to the physical connection they came from.
 *
 * Silent when the session has no remote address.
 *
 * @param log_name the calling role's log prefix, i.e. its own LOG_NAME.
 * @param endpoint_name the resource being served, e.g. "/appraise".
 * @param session the session the request arrived on.
 */
void charra_coap_log_peer_address(const char* log_name,
        const char* endpoint_name, struct coap_session_t* session);

/**
 * @brief Extracts a CoAP PDU's payload, logging under log_name/context when
 * the PDU carries none.
 *
 * Wraps coap_get_data_large(), whose block-wise offset output is write-only
 * at every call site in this codebase and so is not exposed here.
 *
 * @param context what is being read, for the log line, e.g. "/appraise".
 * @param data_total_len_out the block-wise total; NULL if unwanted.
 * @return false if the PDU carries no payload, with the outputs zeroed.
 */
bool charra_coap_get_payload(const struct coap_pdu_t* pdu,
        const char* log_name, const char* context, const uint8_t** data_out,
        size_t* data_len_out, size_t* data_total_len_out);

/**
 * @brief The DTLS settings a role is configured with, one instance per
 * program.
 *
 * The values differ per role -- key paths, identity, hint -- but the set of
 * settings does not, so it is declared once here rather than as three
 * parallel lists of globals.
 *
 * Not every field applies to every role: psk_identity is client-side and
 * psk_hint server-side, and a client talking to more than one kind of peer
 * (the RP does) keeps its per-peer key paths separately instead of in
 * rpk_peer_public_key_path.
 */
typedef struct {
    bool use_psk;
    char* psk_key;
    char* psk_identity;
    char* psk_hint;

    bool use_rpk;
    char* rpk_private_key_path;
    char* rpk_public_key_path;
    char* rpk_peer_public_key_path;
    bool rpk_verify_peer_public_key;
} charra_dtls_config;

/* --- server lifecycle ---------------------------------------------------- */

/**
 * @brief What the Attester, Verifier and Trust Manager configure identically
 * when they stand up their CoAP server.
 *
 * The three differ only in which resources they register and what state they
 * keep -- the transport bring-up below was 101 contiguous identical lines in
 * two of them.
 */
typedef struct {
    /** Tag for this server's log lines, e.g. "attester". */
    const char* log_name;
    const char* listen_address;
    unsigned int port;

    /** DTLS-PSK. Mutually exclusive with RPK; both set is rejected. */
    bool use_dtls_psk;
    const char* dtls_psk_key;
    const char* dtls_psk_hint;

    /** DTLS-RPK (raw public keys). */
    bool use_dtls_rpk;
    /* Non-const to match charra_coap_setup_dtls_pki_for_rpk()'s signature. */
    char* dtls_rpk_private_key_path;
    char* dtls_rpk_public_key_path;
    char* dtls_rpk_peer_public_key_path;
    bool dtls_rpk_verify_peer_public_key;
} charra_coap_server_config;

/** @brief Logs the effective DTLS settings at DEBUG level. */
void charra_coap_server_log_config(const charra_coap_server_config* config);

/**
 * @brief Create the CoAP context and listening endpoint for one server.
 *
 * Rejects PSK and RPK enabled together, and DTLS requested from a libcoap
 * built without it. On failure both out-params are NULL and there is
 * nothing to free.
 */
CHARRA_RC charra_coap_server_start(const charra_coap_server_config* config,
        coap_context_t** context_out, coap_endpoint_t** endpoint_out);

/**
 * @brief Process CoAP I/O until *quit turns true, or an I/O error occurs.
 *
 * quit is a volatile sig_atomic_t because it is set from a signal
 * handler.
 */
CHARRA_RC charra_coap_server_run(coap_context_t* context, const char* log_name,
        const volatile sig_atomic_t* quit);

/** @brief Frees the endpoint and context, then shuts libcoap down. */
void charra_coap_server_stop(
        coap_context_t* context, coap_endpoint_t* endpoint);

#endif /* COAP_UTIL_H */
