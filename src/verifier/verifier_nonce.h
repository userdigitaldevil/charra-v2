/**
 * @file verifier_nonce.h
 * @brief /nonce -- this Verifier's own freshness challenge for Quote_r.
 */

#ifndef CHARRA_VERIFIER_NONCE_H
#define CHARRA_VERIFIER_NONCE_H

#include <coap3/coap.h>

/**
 * @brief Generates and returns a fresh challenge nonce for Quote_r.
 *
 * The RP must sign THIS value, not one it chose itself, or it could replay
 * an old signature over a nonce it already knew would match. Also marks a
 * new attestation round in this Verifier's log, /nonce being the first
 * request of every round.
 */
void coap_nonce_handler(struct coap_resource_t* resource,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query, struct coap_pdu_t* response);

#endif /* CHARRA_VERIFIER_NONCE_H */
